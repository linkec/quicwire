//! 多条独立 H3 连接、双向复制、滑动窗口去重和健康选路。
use crate::{
    config::{Config, Mode},
    http3::{self, Session},
    identity::{Identity, PublicKey},
    packet::valid_ipv4,
    transport,
};
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use quinn::{Connection, Endpoint};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Notify, Semaphore, mpsc, watch},
    task::JoinSet,
};

pub const PROBE_INTERVAL: Duration = Duration::from_millis(500);
pub const DEAD_AFTER: Duration = Duration::from_millis(1500);
const QUEUE: usize = 128;
const WINDOW: u64 = 65536;
type Epoch = [u8; 16];
fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    SystemRandom::new().fill(&mut b).expect("系统随机源不可用");
    b
}
fn number(b: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

#[derive(Default)]
pub struct Dedup {
    highest: Option<u64>,
    bits: Vec<u64>,
}
#[derive(Debug, PartialEq)]
pub enum Verdict {
    New,
    Duplicate,
    TooOld,
}
impl Dedup {
    pub fn insert(&mut self, sequence: u64) -> Verdict {
        if self.bits.is_empty() {
            self.bits.resize((WINDOW / 64) as usize, 0);
        }
        if let Some(highest) = self.highest {
            if sequence <= highest && highest - sequence >= WINDOW {
                return Verdict::TooOld;
            }
            if sequence > highest {
                if sequence - highest >= WINDOW {
                    self.bits.fill(0);
                } else {
                    for n in highest + 1..=sequence {
                        let bit = n % WINDOW;
                        self.bits[(bit / 64) as usize] &= !(1 << (bit % 64));
                    }
                }
            }
        }
        self.highest = Some(self.highest.unwrap_or(sequence).max(sequence));
        let bit = sequence % WINDOW;
        let word = &mut self.bits[(bit / 64) as usize];
        let mask = 1 << (bit % 64);
        if *word & mask != 0 {
            Verdict::Duplicate
        } else {
            *word |= mask;
            Verdict::New
        }
    }
}

#[derive(Clone)]
pub struct PathSender {
    pub id: u64,
    pub sender: mpsc::Sender<Bytes>,
}
#[derive(Default, Serialize, Clone)]
pub struct Counters {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_copies: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub duplicates: u64,
    pub too_old: u64,
    pub invalid: u64,
    pub disconnected: u64,
    pub queue_drops: u64,
    pub rx_queue_drops: u64,
    pub send_errors: u64,
    pub partial_replication: u64,
}
struct Path {
    id: u64,
    slot: usize,
    local: SocketAddr,
    remote: SocketAddr,
    connection: Connection,
    sender: mpsc::Sender<Bytes>,
    connected: Instant,
    seen: Option<Instant>,
    rtt: f64,
    jitter: f64,
    probes: u64,
    timeouts: u64,
    recent_loss: f64,
    standby_since: Option<Instant>,
    rotating: bool,
    rate_sample: (Instant, u64, u64),
    tx_bps: f64,
    rx_bps: f64,
    acked_generation: u64,
    tx_copies: u64,
    tx_bytes: u64,
    rx_copies: u64,
    rx_bytes: u64,
    queue_drops: u64,
}
impl Path {
    fn healthy(&self, now: Instant) -> bool {
        self.connection.close_reason().is_none()
            && self
                .seen
                .is_some_and(|t| now.duration_since(t) < DEAD_AFTER)
    }
    fn score(&self) -> f64 {
        self.rtt + 4.0 * self.jitter + 100.0 * self.recent_loss
    }
}
struct State {
    client_epoch: Option<Epoch>,
    server_epoch: Option<Epoch>,
    retired: VecDeque<(Epoch, Instant)>,
    paths: BTreeMap<u64, Path>,
    active: Vec<u64>,
    generation: u64,
    configured_max: usize,
    configured_active: usize,
    dedup: Dedup,
    counters: Counters,
    last_switch: Instant,
    challenger: Option<(Vec<u64>, Instant)>,
    rotations: u64,
    last_rotation: Instant,
    switches: u64,
    reason: String,
    started: Instant,
    failures: u64,
    latest_error: Option<String>,
    startup_pending: bool,
    selection_started: Instant,
    reserved: Vec<u64>,
    retiring: Option<u64>,
    ttl_rotations: u64,
    ttl_waiting_reason: Option<String>,
}
pub struct Shared {
    state: Mutex<State>,
    pub available: Notify,
    selected: watch::Sender<Vec<PathSender>>,
    config: Config,
    boot: Epoch,
}
#[derive(Serialize)]
pub struct PathStatus {
    pub id: String,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: &'static str,
    pub tx_bps: f64,
    pub rx_bps: f64,
    pub acked_generation: u64,
    pub connected_seconds: u64,
    pub standby_seconds: u64,
    pub probe_rtt_ms: f64,
    pub jitter_ms: f64,
    pub probes: u64,
    pub probe_timeouts: u64,
    pub recent_probe_loss: f64,
    pub quic_rtt_ms: f64,
    pub quic_sent_packets: u64,
    pub quic_lost_packets: u64,
    pub tx_copies: u64,
    pub tx_bytes: u64,
    pub rx_copies: u64,
    pub rx_bytes: u64,
    pub queue_drops: u64,
    pub score: f64,
    pub slot: Option<usize>,
    pub reserved: bool,
    pub retiring: bool,
    pub ttl_remaining_secs: Option<u64>,
}
#[derive(Serialize)]
pub struct Status {
    pub mode: String,
    pub tun: String,
    pub uptime_seconds: u64,
    pub max_sessions: usize,
    pub active_sessions: usize,
    pub connected: usize,
    pub healthy: usize,
    pub active: usize,
    pub degraded: bool,
    pub reason: String,
    pub selection_generation: u64,
    pub switches: u64,
    pub standby_rotate_secs: Option<u64>,
    pub rotations: u64,
    pub connection_failures: u64,
    pub latest_error: Option<String>,
    pub tun_tx_dropped: Option<u64>,
    pub tun_rx_dropped: Option<u64>,
    pub counters: Counters,
    pub paths: Vec<PathStatus>,
    pub switch_threshold_percent: Option<f64>,
    pub stable_session_ttl_secs: Option<u64>,
    pub reserve_sessions: Option<usize>,
    pub reserved: usize,
    pub startup_pending: bool,
    pub ttl_rotations: u64,
    pub ttl_waiting_reason: Option<String>,
    pub ttl_degradation_percent: Option<f64>,
}

fn tun_stat(name: &str, counter: &str) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/sys/class/net/{name}/statistics/{counter}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, counter);
        None
    }
}

impl Shared {
    pub fn counters(&self, f: impl FnOnce(&mut Counters)) {
        f(&mut self.state.lock().unwrap().counters);
    }
    pub fn snapshot(&self) -> Status {
        let s = self.state.lock().unwrap();
        let now = Instant::now();
        let paths: Vec<_> = s
            .paths
            .values()
            .map(|p| {
                let q = p.connection.stats();
                PathStatus {
                    id: format!("{:016x}", p.id),
                    local: p.local,
                    remote: p.remote,
                    state: if !p.healthy(now) {
                        if p.seen.is_none() {
                            "probing"
                        } else {
                            "unhealthy"
                        }
                    } else if s.active.contains(&p.id) {
                        "active"
                    } else {
                        "standby"
                    },
                    tx_bps: p.tx_bps,
                    rx_bps: p.rx_bps,
                    acked_generation: p.acked_generation,
                    connected_seconds: p.connected.elapsed().as_secs(),
                    standby_seconds: p.standby_since.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                    probe_rtt_ms: p.rtt,
                    jitter_ms: p.jitter,
                    probes: p.probes,
                    probe_timeouts: p.timeouts,
                    recent_probe_loss: p.recent_loss,
                    quic_rtt_ms: q.path.rtt.as_secs_f64() * 1000.0,
                    quic_sent_packets: q.path.sent_packets,
                    quic_lost_packets: q.path.lost_packets,
                    tx_copies: p.tx_copies,
                    tx_bytes: p.tx_bytes,
                    rx_copies: p.rx_copies,
                    rx_bytes: p.rx_bytes,
                    queue_drops: p.queue_drops,
                    score: p.score(),
                    slot: (self.config.mode == Mode::Client).then_some(p.slot),
                    reserved: s.reserved.contains(&p.id),
                    retiring: s.retiring == Some(p.id),
                    ttl_remaining_secs: (self.config.mode == Mode::Client
                        && self.config.stable_session_ttl_secs != 0
                        && (s.active.contains(&p.id) || s.reserved.contains(&p.id)))
                    .then(|| {
                        self.config
                            .stable_session_ttl_secs
                            .saturating_sub(p.connected.elapsed().as_secs())
                    }),
                }
            })
            .collect();
        let healthy = paths
            .iter()
            .filter(|p| p.state == "active" || p.state == "standby")
            .count();
        let active = paths.iter().filter(|p| p.state == "active").count();
        Status {
            mode: format!("{:?}", self.config.mode).to_lowercase(),
            tun: self.config.tun_name.clone(),
            uptime_seconds: s.started.elapsed().as_secs(),
            max_sessions: s.configured_max,
            active_sessions: s.configured_active,
            connected: paths.len(),
            healthy,
            active,
            degraded: active < s.configured_active || paths.len() < s.configured_max,
            reason: if active == 0 {
                "没有可用激活连接".into()
            } else if active < s.configured_active {
                "健康连接不足，实际副本数降低".into()
            } else if paths.len() < s.configured_max {
                "已连接数量未达到 max_sessions（候选数不足或连接失败）".into()
            } else {
                s.reason.clone()
            },
            selection_generation: s.generation,
            switches: s.switches,
            standby_rotate_secs: (self.config.mode == Mode::Client)
                .then_some(self.config.standby_rotate_secs),
            rotations: s.rotations,
            connection_failures: s.failures,
            latest_error: s.latest_error.clone(),
            tun_tx_dropped: tun_stat(&self.config.tun_name, "tx_dropped"),
            tun_rx_dropped: tun_stat(&self.config.tun_name, "rx_dropped"),
            counters: s.counters.clone(),
            paths,
            switch_threshold_percent: (self.config.mode == Mode::Client)
                .then_some(self.config.switch_threshold_percent),
            stable_session_ttl_secs: (self.config.mode == Mode::Client)
                .then_some(self.config.stable_session_ttl_secs),
            reserve_sessions: (self.config.mode == Mode::Client)
                .then_some(self.config.reserve_sessions),
            reserved: s.reserved.len(),
            startup_pending: s.startup_pending,
            ttl_rotations: s.ttl_rotations,
            ttl_waiting_reason: s.ttl_waiting_reason.clone(),
            ttl_degradation_percent: (self.config.mode == Mode::Client)
                .then_some(self.config.ttl_degradation_percent),
        }
    }
    fn publish(&self, s: &State) {
        let now = Instant::now();
        self.selected.send_replace(
            s.active
                .iter()
                .filter_map(|id| s.paths.get(id))
                .filter(|p| p.healthy(now))
                .map(|p| PathSender {
                    id: p.id,
                    sender: p.sender.clone(),
                })
                .collect(),
        );
        self.available.notify_waiters();
    }
    fn failed(&self, error: &anyhow::Error) {
        let mut s = self.state.lock().unwrap();
        s.failures += 1;
        s.latest_error = Some(format!("{error:#}"));
        eprintln!("连接失败：{error:#}");
    }
    pub fn queue_drop(&self, id: u64) {
        let mut s = self.state.lock().unwrap();
        s.counters.queue_drops += 1;
        if let Some(p) = s.paths.get_mut(&id) {
            p.queue_drops += 1;
        }
    }
    fn tick(&self) {
        let now = Instant::now();
        let mut s = self.state.lock().unwrap();
        let ttl = Duration::from_secs(self.config.stable_session_ttl_secs);
        if self.config.mode == Mode::Client {
            let mut candidates: Vec<_> = s
                .paths
                .values()
                .filter(|p| p.healthy(now) && !p.rotating)
                .map(|p| (p.id, p.score()))
                .collect();
            candidates.sort_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)));
            let valid: Vec<_> = s
                .active
                .iter()
                .copied()
                .filter(|id| {
                    s.paths
                        .get(id)
                        .is_some_and(|p| p.healthy(now) && !p.rotating)
                })
                .collect();
            let mut next = valid.clone();
            let mut reason = if valid.len() < s.active.len() {
                "故障路径替换"
            } else {
                "补充健康路径"
            };
            s.ttl_waiting_reason = None;
            if s.startup_pending {
                let mut ordered: Vec<_> = candidates
                    .iter()
                    .map(|(id, _)| (*id, s.paths[id].slot))
                    .collect();
                ordered.sort_by_key(|p| p.1);
                let expected = s
                    .configured_active
                    .min(self.config.remote_addresses().map(|a| a.len()).unwrap_or(0));
                let initial_ready =
                    (0..expected).all(|slot| ordered.iter().any(|(_, i)| *i == slot));
                if initial_ready
                    || now.duration_since(s.selection_started) >= transport::HANDSHAKE_TIMEOUT
                {
                    next = ordered
                        .into_iter()
                        .take(s.configured_active)
                        .map(|p| p.0)
                        .collect();
                    if !next.is_empty() {
                        s.startup_pending = false;
                    }
                    reason = "启动按配置顺序激活";
                }
            } else {
                for (id, _) in &candidates {
                    if next.len() >= s.configured_active {
                        break;
                    }
                    if !next.contains(id) {
                        next.push(*id);
                    }
                }
                let best: Vec<_> = candidates
                    .iter()
                    .take(s.configured_active)
                    .map(|p| p.0)
                    .collect();
                if next == s.active
                    && !best.is_empty()
                    && s.retiring.is_none()
                    && now.duration_since(s.last_switch) >= Duration::from_secs(5)
                {
                    let old_score: f64 = next.iter().map(|id| s.paths[id].score()).sum();
                    let qualifies = |ids: &[u64]| {
                        ids.len() == s.configured_active
                            && ids.iter().all(|id| {
                                s.paths
                                    .get(id)
                                    .is_some_and(|p| p.healthy(now) && !p.rotating)
                            })
                            && score_improves(
                                old_score,
                                ids.iter().map(|id| s.paths[id].score()).sum(),
                                self.config.switch_threshold_percent,
                            )
                    };
                    let pending = s.challenger.clone().filter(|(ids, _)| qualifies(ids));
                    if let Some((ids, since)) = pending {
                        if now.duration_since(since) >= Duration::from_secs(3) {
                            next = ids;
                            reason = "备用路径质量持续改善";
                        }
                    } else if best != next && qualifies(&best) {
                        s.challenger = Some((best, now));
                    } else {
                        s.challenger = None;
                    }
                } else {
                    s.challenger = None;
                }
                // TTL 是软期限：先检查质量，再选备用接替；旧连接保留至对端确认。
                if next == s.active
                    && s.retiring.is_none()
                    && !ttl.is_zero()
                    && now.duration_since(s.last_rotation) >= Duration::from_secs(2)
                {
                    let mut expired: Vec<_> = next
                        .iter()
                        .copied()
                        .filter(|id| now.duration_since(s.paths[id].connected) >= ttl)
                        .collect();
                    expired.sort_by_key(|id| s.paths[id].connected);
                    if !expired.is_empty() {
                        let replacement = candidates.iter().find(|(id, _)| {
                            !next.contains(id)
                                && now.duration_since(s.paths[id].connected)
                                    >= Duration::from_secs(3)
                        });
                        match replacement {
                            Some((new, score)) => {
                                if let Some(old) = expired.into_iter().find(|id| {
                                    ttl_degraded(
                                        s.paths[id].score(),
                                        *score,
                                        self.config.ttl_degradation_percent,
                                    )
                                }) {
                                    let pos = next.iter().position(|id| *id == old).unwrap();
                                    next[pos] = *new;
                                    s.retiring = Some(old);
                                    reason = "TTL 到期且质量劣化，备用接替";
                                } else {
                                    s.ttl_waiting_reason = Some(
                                        "TTL 到期，质量劣化未达门槛，继续使用并定期复查".into(),
                                    );
                                }
                            }
                            None => {
                                s.ttl_waiting_reason = Some(
                                    "TTL 到期，缺少经过至少 3 秒观察的健康备用，延后轮换".into(),
                                )
                            }
                        }
                    }
                }
            }
            if next != s.active {
                s.reason = reason.into();
                s.active = next;
                s.generation = s.generation.checked_add(1).expect("控制版本耗尽");
                s.switches += 1;
                s.last_switch = now;
                s.challenger = None;
                eprintln!(
                    "激活集合变更 generation={} active={:?} reason={}",
                    s.generation, s.active, s.reason
                );
            }
            if let Some(old) = s.retiring {
                if s.active.contains(&old) || !s.paths.contains_key(&old) {
                    // 新路径失效时允许回退至尚未关闭的旧路径。
                    s.retiring = None;
                } else {
                    let all_ready = s.active.len() == s.configured_active
                        && s.active
                            .iter()
                            .all(|id| s.paths.get(id).is_some_and(|p| p.healthy(now)));
                    let confirmed = s.active.iter().any(|id| {
                        s.paths
                            .get(id)
                            .is_some_and(|p| p.acked_generation >= s.generation)
                    });
                    if all_ready && confirmed {
                        let p = s.paths.get_mut(&old).unwrap();
                        p.rotating = true;
                        p.connection.close(0x300u32.into(), b"stable TTL rotation");
                        s.rotations += 1;
                        s.ttl_rotations += 1;
                        s.last_rotation = now;
                        s.retiring = None;
                    } else {
                        s.ttl_waiting_reason = Some("等待服务端确认接替，保留旧连接".into());
                    }
                }
            }
            s.reserved = candidates
                .iter()
                .filter(|(id, _)| {
                    !s.active.contains(id)
                        && s.retiring != Some(*id)
                        && s.paths.get(id).is_some_and(|p| !p.rotating)
                })
                .take(self.config.reserve_sessions)
                .map(|p| p.0)
                .collect();
        }
        let active = s.active.clone();
        for p in s.paths.values_mut() {
            if active.contains(&p.id) {
                p.standby_since = None;
            } else if p.standby_since.is_none() {
                p.standby_since = Some(now);
            }
            let secs = now.duration_since(p.rate_sample.0).as_secs_f64();
            if secs >= 1.0 {
                p.tx_bps = (p.tx_bytes - p.rate_sample.1) as f64 * 8.0 / secs;
                p.rx_bps = (p.rx_bytes - p.rate_sample.2) as f64 * 8.0 / secs;
                p.rate_sample = (now, p.tx_bytes, p.rx_bytes);
            }
        }
        if self.config.mode == Mode::Client
            && s.retiring.is_none()
            && now.duration_since(s.last_rotation) >= Duration::from_secs(2)
        {
            let standby_age = Duration::from_secs(self.config.standby_rotate_secs);
            let rotate = s
                .paths
                .values()
                .filter(|p| !p.rotating && !active.contains(&p.id))
                .filter(|p| {
                    !s.challenger
                        .as_ref()
                        .is_some_and(|(ids, _)| ids.contains(&p.id))
                })
                .filter_map(|p| {
                    if s.reserved.contains(&p.id) {
                        // 最快候选保留跨越普通备用周期；TTL 到期后仅在质量明显落后时重采样。
                        let best_other = s
                            .paths
                            .values()
                            .filter(|other| {
                                other.id != p.id
                                    && !active.contains(&other.id)
                                    && other.healthy(now)
                                    && !other.rotating
                            })
                            .map(Path::score)
                            .min_by(f64::total_cmp);
                        (!ttl.is_zero()
                            && now.duration_since(p.connected) >= ttl
                            && best_other.is_some_and(|score| {
                                ttl_degraded(p.score(), score, self.config.ttl_degradation_percent)
                            }))
                        .then_some((p.id, p.connected, true))
                    } else {
                        p.standby_since
                            .filter(|t| {
                                !standby_age.is_zero() && now.duration_since(*t) >= standby_age
                            })
                            .map(|t| (p.id, t, false))
                    }
                })
                .min_by_key(|p| p.1);
            if let Some((id, _, stable)) = rotate {
                let p = s.paths.get_mut(&id).unwrap();
                p.rotating = true;
                p.connection.close(0x300u32.into(), b"standby rotation");
                s.reserved.retain(|p| *p != id);
                s.rotations += 1;
                if stable {
                    s.ttl_rotations += 1;
                }
                s.last_rotation = now;
                eprintln!("备用路径轮转 id={id:016x} stable={stable}，重新分配 UDP 源端口");
            }
        }
        self.publish(&s);
    }
}

fn score_improves(current: f64, candidate: f64, threshold: f64) -> bool {
    candidate < current * (1.0 - threshold / 100.0)
}
fn ttl_degraded(current: f64, reference: f64, threshold: f64) -> bool {
    threshold == 0.0
        || (current > reference && current - reference >= reference * threshold / 100.0)
}

pub struct Multipath {
    pub shared: Arc<Shared>,
    pub selected: watch::Receiver<Vec<PathSender>>,
    pub received: mpsc::Receiver<Bytes>,
    endpoints: Vec<Endpoint>,
    pub(crate) manager: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Drop for Multipath {
    fn drop(&mut self) {
        if let Some(manager) = &self.manager {
            manager.abort();
        }
        for p in self.shared.state.lock().unwrap().paths.values() {
            p.connection.close(0u32.into(), b"shutdown");
        }
        for e in &self.endpoints {
            e.close(0u32.into(), b"shutdown");
        }
    }
}
impl Multipath {
    pub async fn shutdown(&mut self) {
        if let Some(manager) = self.manager.take() {
            manager.abort();
            let _ = manager.await;
        }
        {
            let mut state = self.shared.state.lock().unwrap();
            for path in state.paths.values() {
                path.connection.close(0u32.into(), b"shutdown");
            }
            state.paths.clear();
            self.shared.selected.send_replace(Vec::new());
        }
        for endpoint in &self.endpoints {
            endpoint.set_server_config(None);
            endpoint.close(0u32.into(), b"shutdown");
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            for endpoint in &self.endpoints {
                endpoint.wait_idle().await;
            }
        })
        .await;
        self.endpoints.clear();
    }
    pub fn start(config: Config, identity: Identity) -> Result<Self> {
        config.validate()?;
        let peer = PublicKey::parse(&config.peer_public_key)?;
        let addresses = if config.mode == Mode::Server {
            config.listen_addresses()?
        } else {
            Vec::new()
        };
        let mut endpoints = Vec::new();
        for address in addresses {
            let socket = std::net::UdpSocket::bind(address)
                .with_context(|| format!("无法监听 {address}"))?;
            #[cfg(target_os = "linux")]
            {
                use nix::sys::socket::{setsockopt, sockopt};
                let bytes = 7 * 1024 * 1024;
                setsockopt(&socket, sockopt::RcvBuf, &bytes)?;
                setsockopt(&socket, sockopt::SndBuf, &bytes)?;
                let _ = setsockopt(&socket, sockopt::RcvBufForce, &bytes);
                let _ = setsockopt(&socket, sockopt::SndBufForce, &bytes);
            }
            let server = if config.mode == Mode::Server {
                Some(transport::server_config(&identity, &peer)?)
            } else {
                None
            };
            let mut endpoint = Endpoint::new(
                quinn::EndpointConfig::default(),
                server,
                socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            if config.mode == Mode::Client {
                endpoint.set_default_client_config(transport::client_config(&identity, &peer)?);
            }
            endpoints.push(endpoint);
        }
        let (selected, receiver) = watch::channel(Vec::new());
        let (incoming, received) = mpsc::channel(4096);
        let now = Instant::now();
        let boot = random();
        let shared = Arc::new(Shared {
            config: config.clone(),
            boot,
            available: Notify::new(),
            selected,
            state: Mutex::new(State {
                client_epoch: (config.mode == Mode::Client).then_some(boot),
                server_epoch: (config.mode == Mode::Server).then_some(boot),
                retired: VecDeque::new(),
                paths: BTreeMap::new(),
                active: Vec::new(),
                generation: 0,
                configured_max: config.max_sessions,
                configured_active: config.active_sessions,
                dedup: Dedup::default(),
                counters: Counters::default(),
                last_switch: now,
                challenger: None,
                rotations: 0,
                last_rotation: now,
                switches: 0,
                reason: "等待路径探测".into(),
                started: now,
                failures: 0,
                latest_error: None,
                startup_pending: config.mode == Mode::Client,
                selection_started: now,
                reserved: Vec::new(),
                retiring: None,
                ttl_rotations: 0,
                ttl_waiting_reason: None,
            }),
        });
        let task_shared = shared.clone();
        let task_endpoints = endpoints.clone();
        let manager = tokio::spawn(async move {
            manage(
                task_endpoints,
                config,
                task_shared,
                incoming,
                transport::client_config(&identity, &peer)?,
            )
            .await
        });
        Ok(Self {
            shared,
            selected: receiver,
            received,
            endpoints,
            manager: Some(manager),
        })
    }
}
async fn manage(
    endpoints: Vec<Endpoint>,
    config: Config,
    shared: Arc<Shared>,
    incoming: mpsc::Sender<Bytes>,
    client_config: quinn::ClientConfig,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    match config.mode {
        Mode::Client => {
            let addresses = config.remote_addresses()?;
            let slots = config.max_sessions.min(addresses.len());
            for slot in 0..slots {
                let candidates: Vec<_> = addresses
                    .iter()
                    .skip(slot)
                    .step_by(slots)
                    .copied()
                    .collect();
                let client_config = client_config.clone();
                let shared = shared.clone();
                let config = config.clone();
                let incoming = incoming.clone();
                tasks.spawn(async move {
                    let mut attempt = 0usize;
                    let mut backoff = 1u64;
                    let mut last_port = None;
                    loop {
                        let address = candidates[attempt % candidates.len()];
                        attempt = attempt.wrapping_add(1);
                        let mut cfg = config.clone();
                        cfg.endpoint = Some(address);
                        cfg.endpoints.clear();
                        let started = Instant::now();
                        let result = async {
                            let endpoint =
                                fresh_client_endpoint(config.bind, &client_config, last_port)?;
                            last_port = Some(endpoint.local_addr()?.port());
                            let conn = tokio::time::timeout(
                                transport::HANDSHAKE_TIMEOUT,
                                endpoint.connect(address, &cfg.tls_server_name()?)?,
                            )
                            .await
                            .context("QUIC 握手超时")??;
                            connected(
                                conn,
                                endpoint.local_addr()?,
                                cfg,
                                shared.clone(),
                                incoming.clone(),
                                slot,
                            )
                            .await
                        }
                        .await;
                        if result.is_ok() {
                            backoff = 1;
                            continue;
                        }
                        if let Err(e) = result {
                            shared.failed(&e);
                        }
                        if started.elapsed() > Duration::from_secs(5) {
                            backoff = 1;
                        }
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(8);
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), anyhow::Error>(())
                });
            }
        }
        Mode::Server => {
            let limit = Arc::new(Semaphore::new(64));
            for endpoint in &endpoints {
                let endpoint = endpoint.clone();
                let config = config.clone();
                let shared = shared.clone();
                let incoming = incoming.clone();
                let limit = limit.clone();
                tasks.spawn(async move {
                    let mut peers=JoinSet::new();
                    loop {tokio::select! {
                        next=endpoint.accept() => {
                            let next=next.context("监听端已关闭")?;
                            let Ok(permit)=limit.clone().try_acquire_owned() else {next.refuse();continue;};
                            let config=config.clone();let shared=shared.clone();let incoming=incoming.clone();let local=endpoint.local_addr()?;
                            peers.spawn(async move {
                                let _permit=permit;
                                let result=async {let conn=tokio::time::timeout(transport::HANDSHAKE_TIMEOUT,next).await.context("QUIC 握手超时")??;connected(conn,local,config,shared.clone(),incoming,0).await}.await;
                                if let Err(e)=result {shared.failed(&e);}
                            });
                        },
                        Some(result)=peers.join_next(),if !peers.is_empty()=>{result.context("连接任务异常")?;},
                    }}
                });
            }
        }
    }
    let mut timer = tokio::time::interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=timer.tick()=>shared.tick(),
            result=tasks.join_next()=>{result.context("连接任务全部退出")???;bail!("连接管理任务意外退出");},
        }
    }
}

// 注册守卫保证连接任务取消、握手失败和正常退出均释放发送队列。
struct Registered {
    shared: Arc<Shared>,
    id: u64,
    connection: Connection,
}
impl Drop for Registered {
    fn drop(&mut self) {
        let mut s = self.shared.state.lock().unwrap();
        s.paths.remove(&self.id);
        self.connection.close(0u32.into(), b"path ended");
        self.shared.publish(&s);
    }
}
fn bind_group(shared: &Shared, peer: Epoch, max: usize, active: usize) -> Result<()> {
    let now = Instant::now();
    let mut s = shared.state.lock().unwrap();
    while s
        .retired
        .front()
        .is_some_and(|(_, t)| now.duration_since(*t) > Duration::from_secs(30))
    {
        s.retired.pop_front();
    }
    let old = if shared.config.mode == Mode::Server {
        s.client_epoch
    } else {
        s.server_epoch
    };
    if old != Some(peer) {
        ensure!(
            !s.retired.iter().any(|(e, _)| e == &peer),
            "拒绝已退役运行代际"
        );
        if let Some(old) = old {
            s.retired.push_back((old, now));
            if s.retired.len() > 64 {
                s.retired.pop_front();
            }
        }
        for p in s.paths.values() {
            p.connection.close(0u32.into(), b"new epoch");
        }
        s.paths.clear();
        s.active.clear();
        s.generation = 0;
        s.dedup = Dedup::default();
        s.challenger = None;
        s.startup_pending = shared.config.mode == Mode::Client;
        s.selection_started = now;
        s.reserved.clear();
        s.retiring = None;
        s.ttl_waiting_reason = None;
        if shared.config.mode == Mode::Server {
            s.client_epoch = Some(peer);
        } else {
            s.server_epoch = Some(peer);
        }
    }
    if shared.config.mode == Mode::Server {
        ensure!(
            s.paths.is_empty() || (s.configured_max == max && s.configured_active == active),
            "同一隧道的 N/K 不一致"
        );
        s.configured_max = max;
        s.configured_active = active;
    }
    Ok(())
}
async fn connected(
    conn: Connection,
    local: SocketAddr,
    config: Config,
    shared: Arc<Shared>,
    incoming: mpsc::Sender<Bytes>,
    slot: usize,
) -> Result<()> {
    let mut session = http3::negotiate_multipath(&conn, &config).await?;
    let client = config.mode == Mode::Client;
    let proposed = u64::from_be_bytes(random());
    let mut hello = vec![1];
    hello.extend_from_slice(&shared.boot);
    hello.extend_from_slice(&proposed.to_be_bytes());
    hello.push(config.max_sessions as u8);
    hello.push(config.active_sessions as u8);
    let (id,peer)=tokio::time::timeout(transport::HANDSHAKE_TIMEOUT,async {
        let mut timer=tokio::time::interval(PROBE_INTERVAL);timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {tokio::select! {
            _=timer.tick(),if client=>{conn.send_datagram(session.active.encode(&hello))?;},
            bytes=session.read_datagram()=>{
                let bytes=bytes?;let Some(data)=session.active.decode(&bytes) else {continue;};
                if client && data.len()==41 && data[0]==2 && data[1..17]==shared.boot && number(&data[33..41])==Some(proposed) {
                    let peer:Epoch=data[17..33].try_into().unwrap();bind_group(&shared,peer,config.max_sessions,config.active_sessions)?;return Ok::<_,anyhow::Error>((proposed,peer));
                }
                if !client && data.len()==27 && data[0]==1 {
                    let peer:Epoch=data[1..17].try_into().unwrap();let id=number(&data[17..25]).unwrap();let max=data[25] as usize;let active=data[26] as usize;
                    ensure!((1..=32).contains(&max) && (1..=max).contains(&active),"对端 N/K 无效");
                    bind_group(&shared,peer,max,active)?;
                    return Ok((id,peer));
                }
            },
        }}
    }).await.context("多路径绑定超时")??;
    let (tx, rx) = mpsc::channel(QUEUE);
    {
        let mut s = shared.state.lock().unwrap();
        ensure!(
            s.paths.len() < s.configured_max && !s.paths.contains_key(&id),
            "超过会话上限或重复路径标识"
        );
        s.paths.insert(
            id,
            Path {
                id,
                slot,
                local,
                remote: conn.remote_address(),
                connection: conn.clone(),
                sender: tx,
                connected: Instant::now(),
                seen: None,
                rtt: 0.0,
                jitter: 0.0,
                probes: 0,
                timeouts: 0,
                recent_loss: 0.0,
                standby_since: Some(Instant::now()),
                rotating: false,
                rate_sample: (Instant::now(), 0, 0),
                tx_bps: 0.0,
                rx_bps: 0.0,
                acked_generation: 0,
                tx_copies: 0,
                tx_bytes: 0,
                rx_copies: 0,
                rx_bytes: 0,
                queue_drops: 0,
            },
        );
    }
    let _registered = Registered {
        shared: shared.clone(),
        id,
        connection: conn.clone(),
    };
    let mut welcome = vec![2];
    welcome.extend_from_slice(&peer);
    welcome.extend_from_slice(&shared.boot);
    welcome.extend_from_slice(&id.to_be_bytes());
    if !client {
        conn.send_datagram(session.active.encode(&welcome))?;
    }
    eprintln!(
        "隧道路径已连接 id={id:016x} local={local} remote={}",
        conn.remote_address()
    );
    let active = session.active.clone();
    let result = tokio::select! {
        r=receive_loop(&mut session,&config,&shared,&incoming,id,peer,&welcome)=>r,
        r=send_loop(rx,&active,&shared,id)=>r,
    };
    if shared
        .state
        .lock()
        .unwrap()
        .paths
        .get(&id)
        .is_some_and(|p| p.rotating)
        || matches!(conn.close_reason(),Some(quinn::ConnectionError::ApplicationClosed(ref close)) if close.error_code==quinn::VarInt::from_u32(0x300))
    {
        Ok(())
    } else {
        result
    }
}
async fn send_loop(
    mut queue: mpsc::Receiver<Bytes>,
    active: &http3::ActiveSession,
    shared: &Shared,
    id: u64,
) -> Result<()> {
    while let Some(data) = queue.recv().await {
        shared.available.notify_waiters();
        if let Err(error) = active
            .connection
            .send_datagram_wait(active.encode(&data))
            .await
        {
            shared.counters(|c| c.send_errors += 1);
            return Err(error.into());
        }
        let mut s = shared.state.lock().unwrap();
        s.counters.tx_copies += 1;
        if let Some(p) = s.paths.get_mut(&id) {
            p.tx_copies += 1;
            p.tx_bytes += data.len().saturating_sub(9) as u64;
        }
    }
    bail!("路径发送队列关闭")
}
struct PathReceiver<'a> {
    session: &'a mut Session,
    config: &'a Config,
    shared: &'a Shared,
    incoming: &'a mpsc::Sender<Bytes>,
    id: u64,
    peer: Epoch,
    welcome: &'a [u8],
    pending: VecDeque<(u64, Instant)>,
    nonce: u64,
}
impl PathReceiver<'_> {
    fn probe(&mut self) -> Result<()> {
        self.nonce = self.nonce.checked_add(1).context("探测序号耗尽")?;
        let mut state = self.shared.state.lock().unwrap();
        let generation = state.generation;
        let selected = state.active.clone();
        let path = state.paths.get_mut(&self.id).context("路径已移除")?;
        while self
            .pending
            .front()
            .is_some_and(|(_, sent)| sent.elapsed() >= DEAD_AFTER)
        {
            self.pending.pop_front();
            path.timeouts += 1;
            path.recent_loss = path.recent_loss * 0.8 + 0.2;
        }
        path.probes += 1;
        let client = self.config.mode == Mode::Client;
        let mut data = vec![if client { 4 } else { 6 }];
        data.extend_from_slice(&self.nonce.to_be_bytes());
        if client {
            data.extend_from_slice(&generation.to_be_bytes());
            data.push(selected.len() as u8);
            for id in selected {
                data.extend_from_slice(&id.to_be_bytes());
            }
        }
        self.pending.push_back((self.nonce, Instant::now()));
        self.session
            .active
            .connection
            .send_datagram(self.session.active.encode(&data))?;
        Ok(())
    }
    fn receive(&mut self, data: Bytes) -> Result<()> {
        let Some(payload) = self.session.active.decode(&data) else {
            self.shared.counters(|c| c.invalid += 1);
            return Ok(());
        };
        let Some(kind) = payload.first() else {
            return Ok(());
        };
        let client = self.config.mode == Mode::Client;
        {
            let state = self.shared.state.lock().unwrap();
            let current = if client {
                state.server_epoch
            } else {
                state.client_epoch
            };
            ensure!(
                current == Some(self.peer) && state.paths.contains_key(&self.id),
                "旧代际路径已关闭"
            );
        }
        match *kind {
            1 if !client
                && payload.len() == 27
                && payload[1..17] == self.peer
                && number(&payload[17..25]) == Some(self.id) =>
            {
                self.session
                    .active
                    .connection
                    .send_datagram(self.session.active.encode(self.welcome))?;
            }
            2 if client => (),
            3 if payload.len() >= 9 => {
                let packet = &payload[9..];
                if !valid_ipv4(
                    packet,
                    self.config.peer_address,
                    self.config.tun_address.addr(),
                    self.config.mtu,
                ) {
                    self.shared.counters(|c| c.invalid += 1);
                    return Ok(());
                }
                let sequence = number(&payload[1..9]).unwrap();
                let mut state = self.shared.state.lock().unwrap();
                if let Some(path) = state.paths.get_mut(&self.id) {
                    path.rx_copies += 1;
                    path.rx_bytes += packet.len() as u64;
                }
                match state.dedup.insert(sequence) {
                    Verdict::Duplicate => state.counters.duplicates += 1,
                    Verdict::TooOld => state.counters.too_old += 1,
                    Verdict::New => {
                        if self
                            .incoming
                            .try_send(Bytes::copy_from_slice(packet))
                            .is_err()
                        {
                            state.counters.rx_queue_drops += 1;
                        }
                    }
                }
            }
            4 if !client => {
                if payload.len() < 18
                    || payload[17] > 32
                    || payload.len() != 18 + usize::from(payload[17]) * 8
                {
                    self.shared.counters(|c| c.invalid += 1);
                    return Ok(());
                }
                let generation = number(&payload[9..17]).unwrap();
                let selected: Vec<_> = payload[18..]
                    .chunks_exact(8)
                    .map(|b| number(b).unwrap())
                    .collect();
                let mut state = self.shared.state.lock().unwrap();
                if selected.len() > state.configured_active
                    || selected
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != selected.len()
                {
                    state.counters.invalid += 1;
                    return Ok(());
                }
                if generation > state.generation {
                    state.generation = generation;
                    state.active = selected;
                    state.switches += 1;
                    state.reason = "客户端同步激活集合".into();
                }
                let mut pong = vec![5];
                pong.extend_from_slice(&payload[1..9]);
                pong.extend_from_slice(&state.generation.to_be_bytes());
                self.shared.publish(&state);
                self.session
                    .active
                    .connection
                    .send_datagram(self.session.active.encode(&pong))?;
            }
            6 if client && payload.len() == 9 => {
                let generation = self.shared.state.lock().unwrap().generation;
                let mut pong = vec![7];
                pong.extend_from_slice(&payload[1..9]);
                pong.extend_from_slice(&generation.to_be_bytes());
                self.session
                    .active
                    .connection
                    .send_datagram(self.session.active.encode(&pong))?;
            }
            response
                if ((response == 5 && client) || (response == 7 && !client))
                    && payload.len() == 17 =>
            {
                if let Some(index) = self
                    .pending
                    .iter()
                    .position(|(nonce, _)| Some(*nonce) == number(&payload[1..9]))
                {
                    let (_, sent) = self.pending.remove(index).unwrap();
                    if sent.elapsed() >= DEAD_AFTER {
                        return Ok(());
                    }
                    let mut state = self.shared.state.lock().unwrap();
                    if let Some(path) = state.paths.get_mut(&self.id) {
                        let rtt = sent.elapsed().as_secs_f64() * 1000.0;
                        if path.seen.is_none() {
                            path.rtt = rtt;
                        } else {
                            path.jitter = path.jitter * 0.75 + (rtt - path.rtt).abs() * 0.25;
                            path.rtt = path.rtt * 0.875 + rtt * 0.125;
                        }
                        path.seen = Some(Instant::now());
                        path.acked_generation = number(&payload[9..17]).unwrap();
                        path.recent_loss *= 0.8;
                    }
                }
            }
            _ => self.shared.counters(|c| c.invalid += 1),
        }
        Ok(())
    }
}
async fn receive_loop(
    session: &mut Session,
    config: &Config,
    shared: &Shared,
    incoming: &mpsc::Sender<Bytes>,
    id: u64,
    peer: Epoch,
    welcome: &[u8],
) -> Result<()> {
    let mut receiver = PathReceiver {
        session,
        config,
        shared,
        incoming,
        id,
        peer,
        welcome,
        pending: VecDeque::new(),
        nonce: 0,
    };
    let mut timer = tokio::time::interval(PROBE_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = timer.tick() => receiver.probe()?,
            data = receiver.session.read_datagram() => receiver.receive(data?)?,
        }
    }
}

/// 所有激活路径共享一份不可变数据。只在所有路径队列满时等待。
pub async fn replicate(
    data: Bytes,
    selected: &mut watch::Receiver<Vec<PathSender>>,
    shared: &Shared,
) -> bool {
    loop {
        let notified = shared.available.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let paths = selected.borrow_and_update().clone();
        if paths.is_empty() {
            shared.counters(|c| c.disconnected += 1);
            return false;
        }
        let mut sent = 0;
        let mut full = Vec::new();
        for p in &paths {
            match p.sender.try_send(data.clone()) {
                Ok(()) => sent += 1,
                Err(mpsc::error::TrySendError::Full(_)) => full.push(p.id),
                Err(_) => (),
            }
        }
        if sent > 0 {
            for id in full {
                shared.queue_drop(id);
            }
            if sent < paths.len() {
                shared.counters(|c| c.partial_replication += 1);
            }
            return true;
        }
        tokio::select! {_=notified=>(),r=selected.changed()=>{if r.is_err(){return false;}}}
    }
}

fn fresh_client_endpoint(
    bind: SocketAddr,
    config: &quinn::ClientConfig,
    previous: Option<u16>,
) -> Result<Endpoint> {
    for _ in 0..16 {
        let socket = std::net::UdpSocket::bind(bind)?;
        if bind.port() == 0 && Some(socket.local_addr()?.port()) == previous {
            continue;
        }
        #[cfg(target_os = "linux")]
        {
            use nix::sys::socket::{setsockopt, sockopt};
            let bytes = 7 * 1024 * 1024;
            setsockopt(&socket, sockopt::RcvBuf, &bytes)?;
            setsockopt(&socket, sockopt::SndBuf, &bytes)?;
            let _ = setsockopt(&socket, sockopt::RcvBufForce, &bytes);
            let _ = setsockopt(&socket, sockopt::SndBufForce, &bytes);
        }
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(config.clone());
        return Ok(endpoint);
    }
    bail!("无法分配新的 UDP 源端口")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(mode: Mode, peer: &PublicKey, port: u16) -> Config {
        let (local, remote) = if mode == Mode::Server { (1, 2) } else { (2, 1) };
        let text = format!(
            "mode = {:?}\nbind = {:?}\nprivate_key_file = 'unused.key'\npeer_public_key = {:?}\ntun_name='qw0'\ntun_address='10.77.0.{local}/30'\npeer_address='10.77.0.{remote}'\n",
            if mode == Mode::Server {
                "server"
            } else {
                "client"
            },
            if mode == Mode::Server {
                format!("127.0.0.1:{port}")
            } else {
                "127.0.0.1:0".into()
            },
            peer.encode()
        );
        toml::from_str(&text).unwrap()
    }
    fn clone_identity(id: &Identity) -> Identity {
        Identity {
            public: id.public.clone(),
            certified_key: id.certified_key.clone(),
        }
    }
    fn packet(seq: u64, reverse: bool) -> Bytes {
        let mut b = vec![0u8; 20];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&20u16.to_be_bytes());
        b[12..16].copy_from_slice(&[10, 77, 0, if reverse { 1 } else { 2 }]);
        b[16..20].copy_from_slice(&[10, 77, 0, if reverse { 2 } else { 1 }]);
        let mut out = vec![3];
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend(b);
        out.into()
    }
    async fn until(f: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(12), async {
            while !f() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("状态未在期限内达到");
    }
    fn free_ports() -> u16 {
        loop {
            let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = a.local_addr().unwrap().port();
            if port > 65000 {
                continue;
            }
            if let (Ok(_b), Ok(_c)) = (
                std::net::UdpSocket::bind(("127.0.0.1", port + 1)),
                std::net::UdpSocket::bind(("127.0.0.1", port + 2)),
            ) {
                return port;
            }
        }
    }
    #[test]
    fn dedup_window_accepts_reorder_and_rejects_replay() {
        let mut d = Dedup::default();
        assert_eq!(d.insert(10), Verdict::New);
        assert_eq!(d.insert(8), Verdict::New);
        assert_eq!(d.insert(10), Verdict::Duplicate);
        assert_eq!(d.insert(8), Verdict::Duplicate);
        assert_eq!(d.insert(WINDOW + 10), Verdict::New);
        assert_eq!(d.insert(10), Verdict::TooOld);
        assert_eq!(d.insert(11), Verdict::New);
        assert_eq!(d.insert(11), Verdict::Duplicate);
        assert_eq!(d.insert(u64::MAX), Verdict::New);
        assert_eq!(d.insert(u64::MAX - 2), Verdict::New);
        assert_eq!(d.insert(u64::MAX), Verdict::Duplicate);
    }
    #[test]
    fn configurable_score_and_ttl_threshold_boundaries() {
        assert!(!score_improves(145.0, 135.0, 20.0));
        assert!(score_improves(145.0, 135.0, 5.0));
        assert!(!score_improves(100.0, 95.0, 5.0));
        assert!(!score_improves(100.0, 100.0, 0.0));
        assert!(ttl_degraded(110.0, 100.0, 10.0));
        assert!(!ttl_degraded(109.9, 100.0, 10.0));
        assert!(!ttl_degraded(95.0, 100.0, 10.0));
        assert!(ttl_degraded(95.0, 100.0, 0.0));
        assert!(!ttl_degraded(0.0, 0.0, 10.0));
    }

    #[tokio::test]
    async fn ordered_start_reservation_ttl_deferral_and_acknowledged_handover() {
        let (sid, _) = Identity::generate().unwrap();
        let (cid, _) = Identity::generate().unwrap();
        let port = free_ports();
        let mut sc = config(Mode::Server, &cid.public, port);
        sc.bind = "0.0.0.0:0".parse().unwrap();
        sc.listen = vec![format!("127.0.0.1:{port}-{}", port + 2)];
        let mut cc = config(Mode::Client, &sid.public, port);
        cc.endpoints = sc.listen.clone();
        cc.max_sessions = 3;
        cc.active_sessions = 1;
        cc.standby_rotate_secs = 5;
        cc.stable_session_ttl_secs = 5;
        cc.switch_threshold_percent = 99.0;
        let mut server = Multipath::start(sc, sid).unwrap();
        let mut client = Multipath::start(cc, cid).unwrap();
        until(|| client.shared.snapshot().healthy == 3 && server.shared.snapshot().active == 1)
            .await;
        let (old, reserve, old_port) = {
            let mut s = client.shared.state.lock().unwrap();
            let old = s.active[0];
            assert_eq!(s.paths[&old].slot, 0, "启动必须选配置第一条，而非最低评分");
            let reserve = s.paths.values().find(|p| p.slot == 1).unwrap().id;
            let old_port = s.paths[&old].local.port();
            let now = Instant::now();
            s.last_rotation = now - Duration::from_secs(3);
            for p in s.paths.values_mut() {
                p.connected = now - Duration::from_secs(6);
                p.standby_since = Some(now - Duration::from_secs(6));
                p.seen = Some(now);
                p.rtt = if p.id == old {
                    100.0
                } else if p.id == reserve {
                    95.0
                } else {
                    120.0
                };
                p.jitter = 0.0;
                p.recent_loss = 0.0;
            }
            (old, reserve, old_port)
        };
        {
            let mut s = client.shared.state.lock().unwrap();
            for p in s.paths.values_mut().filter(|p| p.id != old) {
                p.seen = None;
                p.standby_since = Some(Instant::now());
            }
        }
        client.shared.tick();
        {
            let mut s = client.shared.state.lock().unwrap();
            assert_eq!(s.active, vec![old], "没有健康备用时必须延后 TTL");
            assert!(s.paths[&old].connection.close_reason().is_none());
            assert!(s.ttl_waiting_reason.as_ref().unwrap().contains("缺少"));
            for p in s.paths.values_mut().filter(|p| p.id != old) {
                p.seen = Some(Instant::now());
                p.standby_since = Some(Instant::now() - Duration::from_secs(6));
            }
        }
        client.shared.tick();
        {
            let mut s = client.shared.state.lock().unwrap();
            assert_eq!(s.active, vec![old], "TTL 到期但劣化不达 10% 时不能切换");
            assert!(s.reserved.contains(&reserve));
            assert!(
                !s.paths[&reserve].rotating,
                "更快预留候选不能按普通备用周期丢弃"
            );
            assert!(s.ttl_waiting_reason.as_ref().unwrap().contains("未达门槛"));
            s.paths.get_mut(&old).unwrap().rtt = 110.0;
            s.last_rotation = Instant::now() - Duration::from_secs(3);
        }
        client.shared.tick();
        {
            let s = client.shared.state.lock().unwrap();
            assert_eq!(s.active, vec![reserve]);
            assert_eq!(s.retiring, Some(old));
            assert!(
                s.paths[&old].connection.close_reason().is_none(),
                "对端未确认前不能断开旧会话"
            );
        }
        until(|| {
            let s = client.shared.state.lock().unwrap();
            s.ttl_rotations >= 1
                && !s.paths.contains_key(&old)
                && s.paths
                    .values()
                    .any(|p| p.slot == 0 && p.healthy(Instant::now()))
        })
        .await;
        assert_ne!(
            client
                .shared
                .state
                .lock()
                .unwrap()
                .paths
                .values()
                .find(|p| p.slot == 0)
                .unwrap()
                .local
                .port(),
            old_port
        );
        assert!(
            replicate(
                packet(1, false),
                &mut client.selected.clone(),
                &client.shared
            )
            .await
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), server.received.recv())
                .await
                .unwrap()
                .is_some()
        );
        client.shutdown().await;
        server.shutdown().await;
    }

    #[test]
    fn ranges_limits_and_rotation_validation() {
        use crate::config::expand_addresses;
        assert_eq!(
            expand_addresses(&["127.0.0.1:10-12".into(), "127.0.0.1:11".into()])
                .unwrap()
                .len(),
            3
        );
        assert_eq!(expand_addresses(&["[::1]:10-11".into()]).unwrap().len(), 2);
        for value in [
            "127.0.0.1:0",
            "127.0.0.1:20-10",
            "127.0.0.1:1-300",
            "example.org:443",
            "::1:443",
        ] {
            assert!(expand_addresses(&[value.into()]).is_err());
        }
        let (id, _) = Identity::generate().unwrap();
        let mut cfg = config(Mode::Client, &id.public, 4433);
        cfg.endpoints = vec!["192.0.2.1:4433-4435".into(), "192.0.2.2:4433".into()];
        cfg.max_sessions = 3;
        cfg.active_sessions = 2;
        assert!(cfg.validate().is_ok());
        for threshold in [-1.0, 100.0, f64::NAN, f64::INFINITY] {
            cfg.switch_threshold_percent = threshold;
            assert!(cfg.validate().is_err());
        }
        cfg.switch_threshold_percent = 5.0;
        for threshold in [-1.0, 1001.0, f64::NAN] {
            cfg.ttl_degradation_percent = threshold;
            assert!(cfg.validate().is_err());
        }
        cfg.ttl_degradation_percent = 10.0;
        cfg.stable_session_ttl_secs = 4;
        assert!(cfg.validate().is_err());
        cfg.stable_session_ttl_secs = 300;
        cfg.reserve_sessions = 33;
        assert!(cfg.validate().is_err());
        cfg.reserve_sessions = 1;
        assert!(cfg.validate().is_ok());
        assert_eq!(
            cfg.remote_addresses().unwrap()[1].ip().to_string(),
            "192.0.2.2"
        );
        cfg.active_sessions = 4;
        assert!(cfg.validate().is_err());
        cfg.active_sessions = 2;
        cfg.bind.set_port(40000);
        assert!(cfg.validate().is_err());
        cfg.bind.set_port(0);
        cfg.endpoint = Some("192.0.2.3:4433".parse().unwrap());
        assert!(cfg.validate().is_err());
        let mut server = config(Mode::Server, &id.public, 4433);
        server.listen = vec!["0.0.0.0:4433".into(), "127.0.0.1:4433".into()];
        server.bind = "0.0.0.0:0".parse().unwrap();
        assert!(server.validate().is_err());
    }
    #[tokio::test]
    async fn real_h3_replication_rotation_failover_and_epoch_restart() {
        let (sid, _) = Identity::generate().unwrap();
        let (cid, _) = Identity::generate().unwrap();
        let port = free_ports();
        let mut sc = config(Mode::Server, &cid.public, port);
        sc.bind = "0.0.0.0:0".parse().unwrap();
        sc.listen = vec![format!("127.0.0.1:{port}-{}", port + 2)];
        let mut cc = config(Mode::Client, &sid.public, port);
        cc.endpoints = sc.listen.clone();
        cc.max_sessions = 3;
        cc.active_sessions = 2;
        cc.standby_rotate_secs = 5;
        cc.reserve_sessions = 0;
        let mut server = Multipath::start(sc.clone(), clone_identity(&sid)).unwrap();
        let mut client = Multipath::start(cc, clone_identity(&cid)).unwrap();
        until(|| {
            client.shared.snapshot().healthy == 3
                && client.shared.snapshot().active == 2
                && server.shared.snapshot().active == 2
        })
        .await;
        let first = client.shared.snapshot();
        let standby = first.paths.iter().find(|p| p.state == "standby").unwrap();
        let old_id = standby.id.clone();
        let old_port = standby.local.port();
        let target = standby.remote;
        let old_active: Vec<_> = first
            .paths
            .iter()
            .filter(|p| p.state == "active")
            .map(|p| p.id.clone())
            .collect();
        let mut selected = client.selected.clone();
        assert!(replicate(packet(1, false), &mut selected, &client.shared).await);
        let got = tokio::time::timeout(Duration::from_secs(2), server.received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], &packet(1, false)[9..]);
        until(|| server.shared.snapshot().counters.duplicates == 1).await;
        assert!(server.received.try_recv().is_err());
        let mut selected = server.selected.clone();
        assert!(replicate(packet(1, true), &mut selected, &server.shared).await);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.received.recv())
                .await
                .unwrap()
                .is_some()
        );
        until(|| client.shared.snapshot().counters.duplicates == 1).await;
        // 无效包的大序号不能污染去重窗口。
        let mut invalid = packet(u64::MAX, false).to_vec();
        invalid[21] = 192;
        let mut selected = client.selected.clone();
        assert!(replicate(invalid.into(), &mut selected, &client.shared).await);
        assert!(replicate(packet(2, false), &mut selected, &client.shared).await);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), server.received.recv())
                .await
                .unwrap()
                .is_some()
        );
        until(|| {
            let s = client.shared.snapshot();
            s.rotations >= 1 && s.healthy == 3 && !s.paths.iter().any(|p| p.id == old_id)
        })
        .await;
        let after = client.shared.snapshot();
        let replacement = after.paths.iter().find(|p| p.remote == target).unwrap();
        assert_ne!(replacement.local.port(), old_port, "轮转必须真正改变源端口");
        for id in old_active {
            assert!(after.paths.iter().any(|p| p.id == id), "不应重建激活连接");
        }
        // 一个激活连接故障，备用必须补齐 K，另一条激活连接保持。
        let failed = {
            let s = client.shared.state.lock().unwrap();
            s.active[0]
        };
        client.shared.state.lock().unwrap().paths[&failed]
            .connection
            .close(42u32.into(), b"test failure");
        until(|| {
            let s = client.shared.state.lock().unwrap();
            s.active.len() == 2 && !s.active.contains(&failed)
        })
        .await;
        assert!(
            replicate(
                packet(3, false),
                &mut client.selected.clone(),
                &client.shared
            )
            .await
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), server.received.recv())
                .await
                .unwrap()
                .is_some()
        );
        // 服务端重启后，反向序号重新从 1 开始，不能被旧窗口错误去重。
        server.shutdown().await;
        drop(server);
        let server = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match Multipath::start(sc.clone(), clone_identity(&sid)) {
                    Ok(server) => break server,
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
        .expect("关闭后监听端口必须释放");
        until(|| server.shared.snapshot().active == 2 && client.shared.snapshot().healthy >= 2)
            .await;
        assert!(
            replicate(
                packet(1, true),
                &mut server.selected.clone(),
                &server.shared
            )
            .await
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.received.recv())
                .await
                .unwrap()
                .is_some()
        );
        // 一条发送队列满，不能阻塞另一条有空间的队列。
        let (full, _rx) = mpsc::channel(1);
        full.try_send(Bytes::from_static(b"busy")).unwrap();
        let (free, mut rx) = mpsc::channel(1);
        let (_tx, mut selected) = watch::channel(vec![
            PathSender {
                id: 10,
                sender: full,
            },
            PathSender {
                id: 11,
                sender: free,
            },
        ]);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                replicate(Bytes::from_static(b"packet"), &mut selected, &client.shared)
            )
            .await
            .unwrap()
        );
        assert_eq!(rx.recv().await.unwrap(), "packet");
    }
}
