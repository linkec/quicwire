//! 多条独立 H3 连接、双向复制、滑动窗口去重和健康选路。
use crate::{
    config::{Config, Mode},
    fec::{self, Decoder, Encoder, Frame},
    http3::{self, Session},
    identity::{Identity, PublicKey},
    packet::valid_ipv4,
    selection::{Candidate, SelectionPolicy},
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
    pub primary: bool,
    pub sender: mpsc::Sender<Bytes>,
}
#[derive(Default, Serialize, Clone)]
pub struct Counters {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_copies: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// 校验、跨路径去重后成功进入接收队列的业务包，不含探测和重复副本。
    pub rx_effective_packets: u64,
    pub rx_effective_bytes: u64,
    pub duplicates: u64,
    pub too_old: u64,
    pub invalid: u64,
    pub disconnected: u64,
    pub queue_drops: u64,
    pub rx_queue_drops: u64,
    pub send_errors: u64,
    pub partial_replication: u64,
    pub tx_data_bytes: u64,
    pub fec_tx_packets: u64,
    pub fec_tx_bytes: u64,
    pub fec_rx_packets: u64,
    pub fec_recovered_packets: u64,
    pub fec_recovered_bytes: u64,
    pub fec_queue_drops: u64,
}
struct Path {
    id: u64,
    slot: usize,
    local: SocketAddr,
    remote: SocketAddr,
    exclusive_group: Option<String>,
    backup: bool,
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
    rx_effective_packets: u64,
    rx_effective_bytes: u64,
    rx_duplicates: u64,
    queue_drops: u64,
    fec_tx_packets: u64,
    fec_tx_bytes: u64,
}
impl Path {
    fn healthy(&self, now: Instant) -> bool {
        self.connection.close_reason().is_none()
            && self
                .seen
                .is_some_and(|t| now.duration_since(t) < DEAD_AFTER)
    }
    fn candidate(&self) -> Candidate {
        Candidate {
            id: self.id,
            rtt_ms: self.rtt,
            jitter_ms: self.jitter,
            probe_loss: self.recent_loss,
        }
    }
    fn score(&self, policy: SelectionPolicy) -> f64 {
        policy.score(self.rtt, self.jitter, self.recent_loss)
    }
}
struct State {
    fec: bool,
    fec_backup_failover: bool,
    client_epoch: Option<Epoch>,
    server_epoch: Option<Epoch>,
    retired: VecDeque<(Epoch, Instant)>,
    paths: BTreeMap<u64, Path>,
    active: Vec<u64>,
    generation: u64,
    configured_max: usize,
    configured_active: usize,
    dedup: Dedup,
    fec_decoder: Decoder,
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
    pub exclusive_group: Option<String>,
    pub endpoint_backup: Option<bool>,
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
    pub rx_effective_packets: u64,
    pub rx_effective_bytes: u64,
    pub rx_duplicates: u64,
    pub queue_drops: u64,
    pub fec_tx_packets: u64,
    pub fec_tx_bytes: u64,
    pub score: f64,
    pub slot: Option<usize>,
    pub reserved: bool,
    pub selection_role: Option<&'static str>,
    pub retiring: bool,
    pub ttl_remaining_secs: Option<u64>,
}
#[derive(Serialize)]
pub struct Status {
    pub fec_primary: Option<String>,
    pub fec_backup_failover: Option<bool>,
    pub fec_failover_active: Option<bool>,
    pub fec: u8,
    pub fec_expired_groups: u64,
    pub fec_evictions: u64,
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
    pub ttl_max_degradation_percent: Option<f64>,
    pub selection_policy: Option<SelectionPolicy>,
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
        let policy = self.config.selection_policy;
        let s = self.state.lock().unwrap();
        let now = Instant::now();
        let guard = policy
            .rank(
                &s.paths
                    .values()
                    .filter(|p| s.active.contains(&p.id) && p.healthy(now))
                    .map(Path::candidate)
                    .collect::<Vec<_>>(),
            )
            .first()
            .map(|p| p.id);
        let paths: Vec<_> = s
            .paths
            .values()
            .map(|p| {
                let q = p.connection.stats();
                PathStatus {
                    id: format!("{:016x}", p.id),
                    local: p.local,
                    remote: p.remote,
                    exclusive_group: p.exclusive_group.clone(),
                    endpoint_backup: (self.config.mode == Mode::Client).then_some(p.backup),
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
                    rx_effective_packets: p.rx_effective_packets,
                    rx_effective_bytes: p.rx_effective_bytes,
                    rx_duplicates: p.rx_duplicates,
                    rx_copies: p.rx_copies,
                    rx_bytes: p.rx_bytes,
                    queue_drops: p.queue_drops,
                    fec_tx_packets: p.fec_tx_packets,
                    fec_tx_bytes: p.fec_tx_bytes,
                    score: p.score(policy),
                    slot: (self.config.mode == Mode::Client).then_some(p.slot),
                    reserved: s.reserved.contains(&p.id),
                    selection_role: if s.fec {
                        s.active
                            .contains(&p.id)
                            .then_some(if s.active.first() == Some(&p.id) {
                                "primary"
                            } else {
                                "backup"
                            })
                    } else {
                        (self.config.mode == Mode::Client
                            && (s.active.contains(&p.id) || s.reserved.contains(&p.id)))
                        .then(|| match policy {
                            SelectionPolicy::Balanced => "balanced",
                            SelectionPolicy::LowLatency => "latency",
                            SelectionPolicy::LowLoss => "loss_guard",
                            SelectionPolicy::Hybrid => {
                                if (s.active.contains(&p.id) && guard == Some(p.id))
                                    || (s.reserved.contains(&p.id)
                                        && s.reserved.first() == Some(&p.id))
                                {
                                    "loss_guard"
                                } else {
                                    "latency"
                                }
                            }
                        })
                    },
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
            fec_primary: s
                .fec
                .then(|| s.active.first().map(|id| format!("{id:016x}")))
                .flatten(),
            fec_backup_failover: (self.config.mode == Mode::Client && s.fec)
                .then_some(self.config.fec_backup_failover),
            fec_failover_active: (s.fec && self.config.mode == Mode::Client).then(|| {
                s.active
                    .first()
                    .is_some_and(|id| s.paths.get(id).is_some_and(|p| p.backup))
            }),
            fec: self.config.fec,
            fec_expired_groups: s.fec_decoder.expired_missing,
            fec_evictions: s.fec_decoder.evictions,
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
                if s.fec && self.config.mode == Mode::Client && !self.config.fec_backup_failover {
                    "没有健康主线路，备用接管已关闭".into()
                } else {
                    "没有可用激活连接".into()
                }
            } else if active < s.configured_active {
                if self.config.mode == Mode::Client
                    && paths.iter().any(|p| p.exclusive_group.is_some())
                {
                    "满足互斥组约束的健康路径不足，严格降级，不使用同组副本补齐".into()
                } else {
                    "健康连接不足，实际副本数降低".into()
                }
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
            selection_policy: (self.config.mode == Mode::Client).then_some(policy),
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
            ttl_max_degradation_percent: (self.config.mode == Mode::Client)
                .then_some(self.config.ttl_max_degradation_percent),
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
                    primary: s.active.first() == Some(&p.id),
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
        let policy = self.config.selection_policy;
        let now = Instant::now();
        let mut s = self.state.lock().unwrap();
        s.fec_decoder.expire(now);
        let ttl = Duration::from_secs(self.config.stable_session_ttl_secs);
        if self.config.mode == Mode::Client {
            let measured: Vec<_> = s
                .paths
                .values()
                .filter(|p| p.healthy(now) && !p.rotating)
                .map(Path::candidate)
                .collect();
            let candidates: Vec<_> = policy
                .rank(&measured)
                .iter()
                .map(|p| (p.id, policy.score(p.rtt_ms, p.jitter_ms, p.probe_loss)))
                .collect();
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
                let slots = self.config.client_slots().unwrap_or_default();
                let mut groups = std::collections::BTreeSet::new();
                let initial: Vec<_> = slots
                    .iter()
                    .enumerate()
                    .filter(|(_, targets)| match &targets[0].exclusive_group {
                        Some(g) => groups.insert(g.clone()),
                        None => true,
                    })
                    .take(s.configured_active)
                    .map(|(slot, _)| slot)
                    .collect();
                let initial_ready = initial
                    .iter()
                    .all(|slot| ordered.iter().any(|(_, i)| i == slot));
                if initial_ready
                    || now.duration_since(s.selection_started) >= transport::HANDSHAKE_TIMEOUT
                {
                    next = active_paths(&s, ordered.into_iter().map(|p| p.0), s.configured_active);
                    if !next.is_empty() {
                        s.startup_pending = false;
                    }
                    reason = "启动按配置顺序激活";
                }
            } else {
                next = active_paths(
                    &s,
                    next.into_iter().chain(candidates.iter().map(|p| p.0)),
                    s.configured_active,
                );
                let best_order = if s.fec && policy == SelectionPolicy::Hybrid {
                    let mut ids: Vec<_> = candidates.iter().map(|p| p.0).collect();
                    ids.sort_by(|a, b| s.paths[a].rtt.total_cmp(&s.paths[b].rtt));
                    // 主线路按低延迟挑选，其余校验备用按低丢包排序。
                    let primary =
                        ids.iter()
                            .copied()
                            .find(|id| !s.paths[id].backup)
                            .or_else(|| {
                                s.fec_backup_failover
                                    .then(|| ids.first().copied())
                                    .flatten()
                            });
                    ids.sort_by(|a, b| {
                        (Some(*a) != primary)
                            .cmp(&(Some(*b) != primary))
                            .then_with(|| {
                                s.paths[a]
                                    .score(SelectionPolicy::LowLoss)
                                    .total_cmp(&s.paths[b].score(SelectionPolicy::LowLoss))
                            })
                    });
                    ids
                } else {
                    candidates.iter().map(|p| p.0).collect()
                };
                let best = active_paths(&s, best_order, s.configured_active);
                if next == s.active
                    && !best.is_empty()
                    && s.retiring.is_none()
                    && now.duration_since(s.last_switch) >= Duration::from_secs(5)
                {
                    let old_scores = group_scores(&s, &next, policy);
                    let qualifies = |ids: &[u64]| {
                        ids.len() == s.configured_active
                            && active_paths(&s, ids.iter().copied(), ids.len()) == ids
                            && ids.iter().all(|id| {
                                s.paths
                                    .get(id)
                                    .is_some_and(|p| p.healthy(now) && !p.rotating)
                            })
                            && policy.improves(
                                &old_scores,
                                &group_scores(&s, ids, policy),
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
                        let replacements: Vec<_> = candidates
                            .iter()
                            .map(|p| p.0)
                            .filter(|id| {
                                !next.contains(id)
                                    && now.duration_since(s.paths[id].connected)
                                        >= Duration::from_secs(3)
                            })
                            .collect();
                        let mut handover = None;
                        for old in expired {
                            let mut eligible: Vec<_> = replacements
                                .iter()
                                .filter_map(|new| {
                                    let mut trial = next.clone();
                                    let pos = trial.iter().position(|id| *id == old).unwrap();
                                    trial[pos] = *new;
                                    if active_paths(&s, trial.iter().copied(), trial.len()) != trial
                                        || (s.fec && s.paths[&old].backup != s.paths[new].backup)
                                    {
                                        return None;
                                    }
                                    let acceptable = if s.fec {
                                        group_scores(&s, &next, policy)
                                            .iter()
                                            .zip(group_scores(&s, &trial, policy))
                                            .all(|(old, new)| {
                                                ttl_replacement_acceptable(
                                                    *old,
                                                    new,
                                                    self.config.ttl_max_degradation_percent,
                                                )
                                            })
                                    } else if policy == SelectionPolicy::Hybrid {
                                        policy.ttl_allows(
                                            &path_candidates(&s, &next),
                                            &path_candidates(&s, &trial),
                                            self.config.ttl_max_degradation_percent,
                                        )
                                    } else {
                                        ttl_replacement_acceptable(
                                            s.paths[&old].score(policy),
                                            s.paths[new].score(policy),
                                            self.config.ttl_max_degradation_percent,
                                        )
                                    };
                                    acceptable
                                        .then(|| (trial.clone(), group_scores(&s, &trial, policy)))
                                })
                                .collect();
                            eligible.sort_by(|a, b| compare_scores(&a.1, &b.1));
                            if let Some((trial, _)) = eligible.into_iter().next() {
                                handover = Some((old, trial));
                                break;
                            }
                        }
                        if let Some((old, trial)) = handover {
                            next = trial;
                            s.retiring = Some(old);
                            reason = "TTL 到期，备用质量在容忍范围内，接替轮换";
                        } else if replacements.is_empty() {
                            s.ttl_waiting_reason =
                                Some("TTL 到期，缺少经过至少 3 秒观察的健康备用，延后轮换".into());
                        } else {
                            s.ttl_waiting_reason = Some(
                                "TTL 到期，备用与互斥组冲突或质量劣化超过容忍上限，继续使用并定期复查".into(),
                            );
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
            let standby: Vec<_> = measured
                .into_iter()
                .filter(|p| {
                    !s.active.contains(&p.id)
                        && s.retiring != Some(p.id)
                        && s.paths.get(&p.id).is_some_and(|p| !p.rotating)
                })
                .collect();
            let ranked: Vec<_> = policy.rank(&standby).iter().map(|p| p.id).collect();
            // 有限预留名额先覆盖不同组，多余名额才允许保留同组额外候选。
            let mut reserved =
                distinct_paths(&s, ranked.iter().copied(), self.config.reserve_sessions);
            for id in ranked {
                if reserved.len() >= self.config.reserve_sessions {
                    break;
                }
                if !reserved.contains(&id) {
                    reserved.push(id);
                }
            }
            s.reserved = reserved;
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
                        // 预留候选跨越普通备用周期；TTL 到期后有质量在容忍范围内的备用才重采样。
                        let reserve_policy = if policy == SelectionPolicy::Hybrid
                            && s.reserved.first() != Some(&p.id)
                        {
                            SelectionPolicy::LowLatency
                        } else {
                            policy
                        };
                        let best_other = s
                            .paths
                            .values()
                            .filter(|other| {
                                other.id != p.id
                                    && (!s.fec || other.backup == p.backup)
                                    && (p.exclusive_group.is_none()
                                        || other.exclusive_group == p.exclusive_group)
                                    && !active.contains(&other.id)
                                    && other.healthy(now)
                                    && now.duration_since(other.connected) >= Duration::from_secs(3)
                                    && !other.rotating
                            })
                            .map(|p| p.score(reserve_policy))
                            .min_by(f64::total_cmp);
                        (!ttl.is_zero()
                            && now.duration_since(p.connected) >= ttl
                            && best_other.is_some_and(|score| {
                                ttl_replacement_acceptable(
                                    p.score(reserve_policy),
                                    score,
                                    self.config.ttl_max_degradation_percent,
                                )
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

fn can_add_path(s: &State, selected: &[u64], id: u64) -> bool {
    !selected.contains(&id)
        && s.paths.get(&id).is_some_and(|p| {
            p.exclusive_group.as_ref().is_none_or(|group| {
                !selected
                    .iter()
                    .any(|other| s.paths[other].exclusive_group.as_ref() == Some(group))
            })
        })
}
fn distinct_paths(s: &State, ordered: impl IntoIterator<Item = u64>, limit: usize) -> Vec<u64> {
    let mut selected = Vec::new();
    for id in ordered {
        if selected.len() >= limit {
            break;
        }
        if can_add_path(s, &selected, id) {
            selected.push(id);
        }
    }
    selected
}

// FEC 的 active[0] 是双方共同使用的主线路。显式备用永远不抢正常主路。
fn active_paths(s: &State, ordered: impl IntoIterator<Item = u64>, limit: usize) -> Vec<u64> {
    let ids: Vec<_> = ordered.into_iter().collect();
    if !s.fec {
        return distinct_paths(s, ids, limit);
    }
    let primary = ids
        .iter()
        .copied()
        .find(|id| !s.paths[id].backup)
        .or_else(|| {
            if s.fec_backup_failover {
                ids.first().copied()
            } else {
                None
            }
        });
    let Some(primary) = primary else {
        return Vec::new();
    };
    // 手动备用优先占用校验席位，其余普通端点也可作为自动备用。
    distinct_paths(
        s,
        std::iter::once(primary)
            .chain(
                ids.iter()
                    .copied()
                    .filter(|id| *id != primary && s.paths[id].backup),
            )
            .chain(
                ids.iter()
                    .copied()
                    .filter(|id| *id != primary && !s.paths[id].backup),
            ),
        limit,
    )
}
fn path_candidates(s: &State, ids: &[u64]) -> Vec<Candidate> {
    ids.iter().map(|id| s.paths[id].candidate()).collect()
}
fn group_scores(s: &State, ids: &[u64], policy: SelectionPolicy) -> Vec<f64> {
    if s.fec && policy == SelectionPolicy::Hybrid {
        let Some(first) = ids.first() else {
            return Vec::new();
        };
        let mut backup: Vec<_> = ids[1..]
            .iter()
            .map(|id| s.paths[id].score(SelectionPolicy::LowLoss))
            .collect();
        backup.sort_by(f64::total_cmp);
        let mut scores = vec![s.paths[first].rtt];
        scores.extend(backup);
        scores
    } else {
        policy.group_scores(&path_candidates(s, ids))
    }
}
fn compare_scores(a: &[f64], b: &[f64]) -> std::cmp::Ordering {
    a.iter()
        .zip(b)
        .map(|(a, b)| a.total_cmp(b))
        .find(|c| !c.is_eq())
        .unwrap_or(a.len().cmp(&b.len()))
}

fn ttl_replacement_acceptable(current: f64, candidate: f64, tolerance: f64) -> bool {
    // 以待退役会话为基准，允许更好、相等，或仅在容忍范围内变差的备用。
    candidate <= current || candidate - current <= current * tolerance / 100.0
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
                fec: config.fec > 0,
                fec_backup_failover: config.fec_backup_failover,
                client_epoch: (config.mode == Mode::Client).then_some(boot),
                server_epoch: (config.mode == Mode::Server).then_some(boot),
                retired: VecDeque::new(),
                paths: BTreeMap::new(),
                active: Vec::new(),
                generation: 0,
                configured_max: config.max_sessions,
                configured_active: config.active_sessions,
                dedup: Dedup::default(),
                fec_decoder: Decoder::default(),
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
            for (slot, candidates) in config.client_slots()?.into_iter().enumerate() {
                let client_config = client_config.clone();
                let shared = shared.clone();
                let config = config.clone();
                let incoming = incoming.clone();
                tasks.spawn(async move {
                    let mut attempt = 0usize;
                    let mut backoff = 1u64;
                    let mut last_port = None;
                    loop {
                        let address = candidates[attempt % candidates.len()].address;
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
        s.fec_decoder = Decoder::default();
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
                exclusive_group: if client {
                    shared.config.exclusive_group(conn.remote_address())
                } else {
                    None
                },
                backup: client && shared.config.endpoint_backup(conn.remote_address()),
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
                rx_effective_packets: 0,
                rx_effective_bytes: 0,
                rx_duplicates: 0,
                rx_copies: 0,
                rx_bytes: 0,
                queue_drops: 0,
                fec_tx_packets: 0,
                fec_tx_bytes: 0,
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
        if data.first() == Some(&fec::REPAIR) {
            s.counters.fec_tx_packets += 1;
            s.counters.fec_tx_bytes += data.len() as u64;
        } else {
            s.counters.tx_copies += 1;
            s.counters.tx_data_bytes += data.len() as u64;
        }
        if let Some(p) = s.paths.get_mut(&id) {
            if data.first() != Some(&fec::REPAIR) {
                p.tx_copies += 1;
            } else {
                p.fec_tx_packets += 1;
                p.fec_tx_bytes += data.len() as u64;
            }
            p.tx_bytes += data.len() as u64;
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
    fn deliver(&self, sequence: u64, packet: Bytes, recovered: bool) {
        if !valid_ipv4(
            &packet,
            self.config.peer_address,
            self.config.tun_address.addr(),
            self.config.mtu,
        ) {
            self.shared.counters(|c| c.invalid += 1);
            return;
        }
        let mut state = self.shared.state.lock().unwrap();
        if !recovered && let Some(path) = state.paths.get_mut(&self.id) {
            path.rx_copies += 1;
            path.rx_bytes += packet.len() as u64;
        }
        match state.dedup.insert(sequence) {
            Verdict::Duplicate => {
                state.counters.duplicates += 1;
                if let Some(path) = state.paths.get_mut(&self.id) {
                    path.rx_duplicates += 1;
                }
            }
            Verdict::TooOld => state.counters.too_old += 1,
            Verdict::New => {
                let size = packet.len() as u64;
                if self.incoming.try_send(packet).is_err() {
                    state.counters.rx_queue_drops += 1;
                } else {
                    state.counters.rx_effective_packets += 1;
                    state.counters.rx_effective_bytes += size;
                    if recovered {
                        state.counters.fec_recovered_packets += 1;
                        state.counters.fec_recovered_bytes += size;
                    }
                    if let Some(path) = state.paths.get_mut(&self.id) {
                        path.rx_effective_packets += 1;
                        path.rx_effective_bytes += size;
                    }
                }
            }
        }
    }
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
            3 if payload.len() >= 9 && self.config.fec == 0 => {
                self.deliver(
                    number(&payload[1..9]).unwrap(),
                    Bytes::copy_from_slice(&payload[9..]),
                    false,
                );
            }
            fec::DATA | fec::REPAIR if self.config.fec > 0 => {
                let Some(frame) = Frame::parse(payload, self.config.mtu as usize) else {
                    self.shared.counters(|c| c.invalid += 1);
                    return Ok(());
                };
                if let Frame::Data {
                    base,
                    index,
                    packet,
                } = &frame
                {
                    if !valid_ipv4(
                        packet,
                        self.config.peer_address,
                        self.config.tun_address.addr(),
                        self.config.mtu,
                    ) {
                        self.shared.counters(|c| c.invalid += 1);
                        return Ok(());
                    }
                    self.deliver(*base + *index as u64, packet.clone(), false);
                } else {
                    self.shared.counters(|c| c.fec_rx_packets += 1);
                }
                let recovered = self
                    .shared
                    .state
                    .lock()
                    .unwrap()
                    .fec_decoder
                    .receive(frame, Instant::now());
                match recovered {
                    Ok(Some((seq, packet))) => self.deliver(seq, packet, true),
                    Err(_) => self.shared.counters(|c| c.invalid += 1),
                    _ => (),
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

/// FEC 原始包只走控制面指定主路，校验只走激活备用；队列背压不改变角色。
#[derive(Default)]
pub struct FecSender {
    encoder: Encoder,
}
impl FecSender {
    pub fn deadline(&self) -> Option<Instant> {
        self.encoder.deadline()
    }
    fn repair(
        &mut self,
        data: Bytes,
        selected: &watch::Receiver<Vec<PathSender>>,
        shared: &Shared,
    ) {
        let paths: Vec<_> = selected
            .borrow()
            .iter()
            .filter(|p| !p.primary)
            .cloned()
            .collect();
        // 同一份校验最多发 3 份，先分散到不同激活路径；路径不足时循环复用。
        // 每份只成功入队一次；排队失败时尝试其它激活备用，不阻塞原始数据。
        let count = paths.len();
        for copy in 0..shared.config.fec as usize {
            let mut sent = false;
            for offset in 0..count {
                let p = &paths[(copy + offset) % count];
                if p.sender.try_send(data.clone()).is_ok() {
                    sent = true;
                    break;
                }
            }
            if !sent {
                shared.counters(|c| c.fec_queue_drops += 1);
            }
        }
    }
    pub fn flush(&mut self, selected: &watch::Receiver<Vec<PathSender>>, shared: &Shared) {
        if let Some(data) = self.encoder.flush() {
            self.repair(data, selected, shared);
        }
    }
    pub async fn send(
        &mut self,
        data: Bytes,
        selected: &mut watch::Receiver<Vec<PathSender>>,
        shared: &Shared,
    ) -> bool {
        if shared.config.fec == 0 {
            return replicate(data, selected, shared).await;
        }
        let seq = number(&data[1..9]).expect("内部业务包序号");
        if !self.encoder.accepts(seq) {
            self.flush(selected, shared);
        }
        let frame = self.encoder.data(seq, &data[9..]);
        loop {
            let notified = shared.available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let paths: Vec<_> = selected
                .borrow_and_update()
                .iter()
                .filter(|p| p.primary)
                .cloned()
                .collect();
            if paths.is_empty() {
                shared.counters(|c| c.disconnected += 1);
                return false;
            }
            for p in paths {
                if p.sender.try_send(frame.clone()).is_ok() {
                    if let Some(repair) = self.encoder.push(seq, data.slice(9..), Instant::now()) {
                        self.repair(repair, selected, shared);
                    }
                    return true;
                }
            }
            tokio::select! { _=notified=>(), r=selected.changed()=>{if r.is_err(){return false;}} }
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
    #[tokio::test]
    async fn policy_presets_select_expected_authenticated_paths() {
        for (policy, count, expected) in [
            (SelectionPolicy::LowLatency, 1, vec![0]),
            (SelectionPolicy::Balanced, 1, vec![1]),
            (SelectionPolicy::LowLoss, 1, vec![2]),
            (SelectionPolicy::Hybrid, 2, vec![0, 2]),
        ] {
            let (sid, _) = Identity::generate().unwrap();
            let (cid, _) = Identity::generate().unwrap();
            let port = free_ports();
            let mut sc = config(Mode::Server, &cid.public, port);
            sc.bind = "0.0.0.0:0".parse().unwrap();
            sc.listen = vec![format!("127.0.0.1:{port}-{}", port + 2)];
            let mut cc = config(Mode::Client, &sid.public, port);
            cc.endpoints = sc.listen.iter().cloned().map(Into::into).collect();
            cc.max_sessions = 3;
            cc.active_sessions = count;
            cc.selection_policy = policy;
            cc.stable_session_ttl_secs = 0;
            cc.standby_rotate_secs = 0;
            cc.switch_threshold_percent = 5.0;
            let mut server = Multipath::start(sc, sid).unwrap();
            let mut client = Multipath::start(cc, cid).unwrap();
            until(|| {
                client.shared.snapshot().healthy == 3 && server.shared.snapshot().active == count
            })
            .await;
            {
                let mut s = client.shared.state.lock().unwrap();
                s.last_switch = Instant::now() - Duration::from_secs(6);
                for p in s.paths.values_mut() {
                    let metrics = [(20.0, 10.0, 0.02), (35.0, 1.0, 0.01), (55.0, 1.0, 0.0)][p.slot];
                    p.rtt = metrics.0;
                    p.jitter = metrics.1;
                    p.recent_loss = metrics.2;
                    p.seen = Some(Instant::now());
                }
            }
            client.shared.tick();
            {
                let mut s = client.shared.state.lock().unwrap();
                if let Some((_, since)) = &mut s.challenger {
                    *since = Instant::now() - Duration::from_secs(4);
                }
            }
            client.shared.tick();
            let snapshot = client.shared.snapshot();
            let mut actual: Vec<_> = snapshot
                .paths
                .iter()
                .filter(|p| p.state == "active")
                .map(|p| p.slot.unwrap())
                .collect();
            actual.sort();
            assert_eq!(actual, expected, "策略 {policy:?}");
            assert_eq!(snapshot.selection_policy, Some(policy));
            if policy == SelectionPolicy::Hybrid {
                assert_eq!(
                    snapshot
                        .paths
                        .iter()
                        .find(|p| p.slot == Some(2))
                        .unwrap()
                        .selection_role,
                    Some("loss_guard")
                );
                assert_eq!(
                    snapshot
                        .paths
                        .iter()
                        .find(|p| p.slot == Some(0))
                        .unwrap()
                        .selection_role,
                    Some("latency")
                );
            }
            client.shutdown().await;
            server.shutdown().await;
        }
    }

    #[tokio::test]
    async fn hybrid_ttl_keeps_loss_guard_and_rotates_acceptable_latency_path() {
        let (sid, _) = Identity::generate().unwrap();
        let (cid, _) = Identity::generate().unwrap();
        let port = free_ports();
        let mut sc = config(Mode::Server, &cid.public, port);
        sc.bind = "0.0.0.0:0".parse().unwrap();
        sc.listen = vec![format!("127.0.0.1:{port}-{}", port + 2)];
        let mut cc = config(Mode::Client, &sid.public, port);
        cc.endpoints = sc.listen.iter().cloned().map(Into::into).collect();
        cc.max_sessions = 3;
        cc.active_sessions = 2;
        cc.selection_policy = SelectionPolicy::Hybrid;
        cc.stable_session_ttl_secs = 5;
        let mut server = Multipath::start(sc, sid).unwrap();
        let mut client = Multipath::start(cc, cid).unwrap();
        until(|| client.shared.snapshot().healthy == 3 && server.shared.snapshot().active == 2)
            .await;
        let (guard, old_fast, new_fast, old_port) = {
            let mut s = client.shared.state.lock().unwrap();
            let ids: Vec<_> = (0..3)
                .map(|slot| s.paths.values().find(|p| p.slot == slot).unwrap().id)
                .collect();
            let now = Instant::now();
            s.last_rotation = now - Duration::from_secs(3);
            // 保障路径先到期，替掉它会显著增加丢包评分；应跳过它再检查低延迟路径。
            for p in s.paths.values_mut() {
                let (r, j, l) = [(55.0, 1.0, 0.0), (20.0, 10.0, 0.02), (21.0, 10.0, 0.02)][p.slot];
                p.rtt = r;
                p.jitter = j;
                p.recent_loss = l;
                p.seen = Some(now);
                p.connected = now - Duration::from_secs(if p.slot == 0 { 7 } else { 6 });
            }
            (ids[0], ids[1], ids[2], s.paths[&ids[1]].local.port())
        };
        client.shared.tick();
        {
            let s = client.shared.state.lock().unwrap();
            assert!(
                s.active.contains(&guard),
                "TTL不能用高探测丢包备用替掉保障路径"
            );
            assert!(s.active.contains(&new_fast));
            assert_eq!(s.retiring, Some(old_fast));
            assert!(s.paths[&old_fast].connection.close_reason().is_none());
        }
        until(|| {
            let s = client.shared.state.lock().unwrap();
            s.ttl_rotations >= 1
                && !s.paths.contains_key(&old_fast)
                && s.paths
                    .values()
                    .any(|p| p.slot == 1 && p.healthy(Instant::now()))
        })
        .await;
        let snapshot = client.shared.snapshot();
        assert_ne!(
            snapshot
                .paths
                .iter()
                .find(|p| p.slot == Some(1))
                .unwrap()
                .local
                .port(),
            old_port
        );
        assert_eq!(server.shared.snapshot().active, 2);
        client.shutdown().await;
        server.shutdown().await;
    }

    #[test]
    fn configurable_score_and_ttl_threshold_boundaries() {
        assert!(ttl_replacement_acceptable(100.0, 95.0, 10.0));
        assert!(ttl_replacement_acceptable(100.0, 100.0, 10.0));
        assert!(ttl_replacement_acceptable(100.0, 105.0, 10.0));
        assert!(ttl_replacement_acceptable(100.0, 110.0, 10.0));
        assert!(!ttl_replacement_acceptable(100.0, 110.1, 10.0));
        assert!(ttl_replacement_acceptable(100.0, 100.0, 0.0));
        assert!(ttl_replacement_acceptable(100.0, 95.0, 0.0));
        assert!(!ttl_replacement_acceptable(100.0, 100.1, 0.0));
        assert!(ttl_replacement_acceptable(0.0, 0.0, 10.0));
        assert!(!ttl_replacement_acceptable(0.0, 0.1, 10.0));
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
        cc.endpoints = sc.listen.iter().cloned().map(Into::into).collect();
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
                    115.0
                } else {
                    140.0
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
            assert_eq!(
                s.active,
                vec![old],
                "TTL 到期但备用比当前差超过 10% 时必须延期"
            );
            assert!(s.reserved.contains(&reserve));
            assert!(
                !s.paths[&reserve].rotating,
                "最佳预留候选不能按普通备用周期丢弃"
            );
            assert!(
                s.ttl_waiting_reason
                    .as_ref()
                    .unwrap()
                    .contains("超过容忍上限")
            );
            s.paths.get_mut(&reserve).unwrap().rtt = 105.0;
            s.last_rotation = Instant::now() - Duration::from_secs(3);
        }
        client.shared.tick();
        {
            let s = client.shared.state.lock().unwrap();
            assert_eq!(
                s.active,
                vec![reserve],
                "即使当前会话最好，也应允许稍差备用接替"
            );
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

    fn grouped(address: String, group: &str) -> crate::config::EndpointSpec {
        crate::config::EndpointSpec::Options(crate::config::EndpointOptions {
            address,
            exclusive_group: Some(group.into()),
            backup: false,
        })
    }

    #[test]
    fn exclusive_config_preserves_groups_across_odd_slot_rotation() {
        let (id, _) = Identity::generate().unwrap();
        let mut cfg = config(Mode::Client, &id.public, 4433);
        cfg.max_sessions = 5;
        cfg.active_sessions = 2;
        cfg.endpoints = vec![
            grouped("192.0.2.2:4433-4440".into(), "direct"),
            grouped("192.0.2.1:4433-4438".into(), "jp"),
        ];
        cfg.validate().unwrap();
        let slots = cfg.client_slots().unwrap();
        assert_eq!(slots.len(), 5);
        assert_eq!(slots[0][0].exclusive_group.as_deref(), Some("direct"));
        assert_eq!(slots[1][0].exclusive_group.as_deref(), Some("jp"));
        let mut addresses = std::collections::BTreeSet::new();
        for slot in slots {
            assert!(
                slot.iter()
                    .all(|t| t.exclusive_group == slot[0].exclusive_group)
            );
            for t in slot {
                assert!(addresses.insert(t.address));
            }
        }
        assert_eq!(addresses.len(), 14, "轮转覆盖全部端点，且不重复占槽");
        cfg.endpoints
            .push(grouped("192.0.2.3:4433".into(), "direct"));
        cfg.validate().unwrap();
        cfg.active_sessions = 3;
        assert!(cfg.validate().is_err(), "两个组不能配置三副本");
        cfg.endpoints.push("192.0.2.4:4433".into());
        cfg.validate().unwrap();
        cfg.endpoints.push(grouped("192.0.2.2:4433".into(), "jp"));
        assert!(cfg.validate().is_err(), "同一端点不能归属两个组");
        cfg.endpoints = vec![grouped("192.0.2.1:4433".into(), "")];
        assert!(cfg.validate().is_err());
        #[derive(serde::Deserialize)]
        struct Entries {
            endpoints: Vec<crate::config::EndpointSpec>,
        }
        let entries: Entries = toml::from_str(
            "endpoints = ['192.0.2.1:4433', {address='192.0.2.2:4433',exclusive_group='jp'}]",
        )
        .unwrap();
        assert_eq!(entries.endpoints.len(), 2);
        assert!(
            toml::from_str::<Entries>(
                "endpoints = [{address='192.0.2.1:4433',exclusive_grop='jp'}]"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn exclusive_groups_cover_start_selection_ttl_failure_and_recovery() {
        for policy in [
            SelectionPolicy::Balanced,
            SelectionPolicy::LowLatency,
            SelectionPolicy::LowLoss,
            SelectionPolicy::Hybrid,
        ] {
            let (sid, _) = Identity::generate().unwrap();
            let (cid, _) = Identity::generate().unwrap();
            let port = free_ports();
            let mut sc = config(Mode::Server, &cid.public, port);
            sc.bind = "0.0.0.0:0".parse().unwrap();
            sc.listen = vec![format!("127.0.0.1:{port}-{}", port + 2)];
            let mut cc = config(Mode::Client, &sid.public, port);
            cc.endpoints = vec![
                grouped(format!("127.0.0.1:{port}-{}", port + 1), "direct"),
                grouped(format!("127.0.0.1:{}", port + 2), "jp"),
            ];
            cc.max_sessions = 3;
            cc.active_sessions = 2;
            cc.selection_policy = policy;
            cc.standby_rotate_secs = 0;
            cc.stable_session_ttl_secs = 5;
            cc.switch_threshold_percent = 1.0;
            cc.validate().unwrap();
            let mut server = Multipath::start(sc, sid).unwrap();
            let mut client = Multipath::start(cc, cid).unwrap();
            until(|| client.shared.snapshot().healthy == 3 && server.shared.snapshot().active == 2)
                .await;
            let ids: Vec<_> = {
                let s = client.shared.state.lock().unwrap();
                (0..3)
                    .map(|i| s.paths.values().find(|p| p.slot == i).unwrap().id)
                    .collect()
            };
            // 未等待到 JP 时只能启动一条直连，即使另一条直连更快。
            {
                let mut s = client.shared.state.lock().unwrap();
                s.active.clear();
                s.startup_pending = true;
                s.selection_started = Instant::now() - Duration::from_secs(11);
                for p in s.paths.values_mut() {
                    p.seen = if p.slot == 1 {
                        None
                    } else {
                        Some(Instant::now())
                    };
                }
            }
            client.shared.tick();
            assert_eq!(client.shared.state.lock().unwrap().active, vec![ids[0]]);
            assert!(client.shared.snapshot().reason.contains("互斥组"));
            {
                let mut s = client.shared.state.lock().unwrap();
                for p in s.paths.values_mut() {
                    p.seen = Some(Instant::now());
                    p.connected = Instant::now();
                    p.rtt = [10.0, 100.0, 5.0][p.slot];
                    p.jitter = 0.0;
                    p.recent_loss = 0.0;
                }
            }
            client.shared.tick();
            assert!(client.shared.state.lock().unwrap().active.contains(&ids[1]));
            client.shared.state.lock().unwrap().last_switch =
                Instant::now() - Duration::from_secs(6);
            client.shared.tick();
            {
                let mut s = client.shared.state.lock().unwrap();
                let (_, since) = s.challenger.as_mut().expect("更快同组候选应进入观察");
                *since = Instant::now() - Duration::from_secs(4);
            }
            client.shared.tick();
            {
                let mut s = client.shared.state.lock().unwrap();
                assert!(s.active.contains(&ids[2]) && s.active.contains(&ids[1]));
                s.last_rotation = Instant::now() - Duration::from_secs(3);
                // JP 到期但无同组备用，不能拿直连备用把它挤掉。
                for p in s.paths.values_mut() {
                    p.connected =
                        Instant::now() - Duration::from_secs(if p.slot == 1 { 6 } else { 4 });
                }
            }
            client.shared.tick();
            assert!(client.shared.state.lock().unwrap().retiring.is_none());
            {
                let mut s = client.shared.state.lock().unwrap();
                s.paths.get_mut(&ids[0]).unwrap().rtt = 5.2;
                s.paths.get_mut(&ids[1]).unwrap().connected = Instant::now();
                s.paths.get_mut(&ids[2]).unwrap().connected =
                    Instant::now() - Duration::from_secs(6);
            }
            client.shared.tick();
            {
                let s = client.shared.state.lock().unwrap();
                assert_eq!(s.retiring, Some(ids[2]));
                assert!(s.active.contains(&ids[0]) && s.active.contains(&ids[1]));
                assert!(s.paths[&ids[2]].connection.close_reason().is_none());
            }
            // 交接中 JP 失效：严格单副本，不能把保留中的直连旧会话再激活。
            client
                .shared
                .state
                .lock()
                .unwrap()
                .paths
                .get_mut(&ids[1])
                .unwrap()
                .seen = None;
            client.shared.tick();
            assert_eq!(client.shared.state.lock().unwrap().active, vec![ids[0]]);
            assert_eq!(client.shared.selected.borrow().len(), 1);
            client
                .shared
                .state
                .lock()
                .unwrap()
                .paths
                .get_mut(&ids[1])
                .unwrap()
                .seen = Some(Instant::now());
            client.shared.tick();
            until(|| {
                server.shared.snapshot().active == 2 && client.shared.snapshot().ttl_rotations >= 1
            })
            .await;
            let status = client.shared.snapshot();
            let groups: std::collections::BTreeSet<_> = status
                .paths
                .iter()
                .filter(|p| p.state == "active")
                .map(|p| p.exclusive_group.clone())
                .collect();
            assert_eq!(groups.len(), 2);
            client.shutdown().await;
            server.shutdown().await;
        }
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
            cfg.ttl_max_degradation_percent = threshold;
            assert!(cfg.validate().is_err());
        }
        cfg.ttl_max_degradation_percent = 10.0;
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
    async fn effective_packets_exclude_probes_invalid_and_rejected_delivery() {
        let (sid, _) = Identity::generate().unwrap();
        let (cid, _) = Identity::generate().unwrap();
        let port = free_ports();
        let sc = config(Mode::Server, &cid.public, port);
        let mut cc = config(Mode::Client, &sid.public, port);
        cc.endpoint = Some(format!("127.0.0.1:{port}").parse().unwrap());
        let mut server = Multipath::start(sc, sid).unwrap();
        let mut client = Multipath::start(cc, cid).unwrap();
        until(|| client.shared.snapshot().healthy == 1 && server.shared.snapshot().active == 1)
            .await;
        assert_eq!(
            server.shared.snapshot().counters.rx_effective_packets,
            0,
            "探测不计业务包"
        );
        let mut selected = client.selected.clone();
        let mut invalid = packet(1, false).to_vec();
        invalid[21] = 192;
        assert!(replicate(invalid.into(), &mut selected, &client.shared).await);
        until(|| server.shared.snapshot().counters.invalid == 1).await;
        assert_eq!(server.shared.snapshot().counters.rx_effective_packets, 0);
        assert!(replicate(packet(1, false), &mut selected, &client.shared).await);
        until(|| server.shared.snapshot().counters.rx_effective_packets == 1).await;
        assert!(server.received.recv().await.is_some());
        assert!(replicate(packet(1, false), &mut selected, &client.shared).await);
        until(|| server.shared.snapshot().counters.duplicates == 1).await;
        server.received.close();
        assert!(replicate(packet(2, false), &mut selected, &client.shared).await);
        until(|| server.shared.snapshot().counters.rx_queue_drops == 1).await;
        let snapshot = server.shared.snapshot();
        assert_eq!(snapshot.counters.rx_effective_packets, 1);
        assert_eq!(snapshot.counters.rx_effective_bytes, 20);
        assert_eq!(snapshot.paths[0].rx_effective_packets, 1);
        assert_eq!(snapshot.paths[0].rx_effective_bytes, 20);
        assert_eq!(snapshot.paths[0].rx_duplicates, 1);
        client.shutdown().await;
        server.shutdown().await;
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
        cc.endpoints = sc.listen.iter().cloned().map(Into::into).collect();
        cc.max_sessions = 3;
        cc.active_sessions = 2;
        cc.standby_rotate_secs = 5;
        cc.reserve_sessions = 0;
        // 本例只验证备用到龄轮转与故障提升；真实 RTT 抖动不能把目标备用提前激活。
        // 质量切换由独立预设及 netem 测试覆盖，故障替换仍绕过此阈值。
        cc.switch_threshold_percent = 99.9999;
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
        let measured = server.shared.snapshot();
        assert_eq!(measured.counters.rx_effective_packets, 1);
        assert_eq!(measured.counters.rx_effective_bytes, 20);
        assert_eq!(measured.counters.rx_packets, 0, "入队不等于已经写入 TUN");
        assert_eq!(
            measured
                .paths
                .iter()
                .map(|p| p.rx_effective_packets)
                .sum::<u64>(),
            1
        );
        assert_eq!(
            measured.paths.iter().map(|p| p.rx_duplicates).sum::<u64>(),
            1
        );
        assert_eq!(measured.paths.iter().map(|p| p.rx_copies).sum::<u64>(), 2);
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
                primary: true,
                sender: full,
            },
            PathSender {
                id: 11,
                primary: false,
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
    #[tokio::test]
    async fn fec_cross_path_recovery_both_directions_and_late_duplicate() {
        for copies in 1..=3 {
            let (sid, _) = Identity::generate().unwrap();
            let (cid, _) = Identity::generate().unwrap();
            let port = free_ports();
            let mut sc = config(Mode::Server, &cid.public, port);
            sc.bind = "0.0.0.0:0".parse().unwrap();
            sc.listen = vec![format!("127.0.0.1:{port}-{}", port + 1)];
            sc.fec = copies;
            let mut cc = config(Mode::Client, &sid.public, port);
            cc.endpoints = sc.listen.iter().cloned().map(Into::into).collect();
            cc.max_sessions = 2;
            cc.active_sessions = 2;
            cc.fec = copies;
            let mut server = Multipath::start(sc, sid).unwrap();
            let mut client = Multipath::start(cc, cid).unwrap();
            until(|| client.shared.snapshot().active == 2 && server.shared.snapshot().active == 2)
                .await;
            for reverse in [false, true] {
                let (source, dest) = if reverse {
                    (&mut server, &mut client)
                } else {
                    (&mut client, &mut server)
                };
                let paths = source.selected.borrow().clone();
                let mut e = Encoder::default();
                let mut frames = Vec::new();
                let mut repair = None;
                for seq in 1..=4 {
                    let p = packet(seq, reverse);
                    frames.push(e.data(seq, &p[9..]));
                    repair = e.push(seq, p.slice(9..), Instant::now());
                }
                // 模拟中间一个原始业务包丢失，校验通过另一条真实 H3/QUIC 连接发送。
                paths[1].sender.send(repair.unwrap()).await.unwrap();
                for i in [3, 0, 2] {
                    paths[0].sender.send(frames[i].clone()).await.unwrap();
                }
                for _ in 0..4 {
                    tokio::time::timeout(Duration::from_secs(2), dest.received.recv())
                        .await
                        .unwrap()
                        .unwrap();
                }
                until(|| dest.shared.snapshot().counters.fec_recovered_packets == 1).await;
                paths[0].sender.send(frames[1].clone()).await.unwrap();
                until(|| dest.shared.snapshot().counters.duplicates == 1).await;
                assert!(dest.received.try_recv().is_err());
                assert_eq!(dest.shared.snapshot().counters.rx_effective_packets, 4);
            }
            // 正常高密度发送：4 份原始数据 + 1 份校验，不再双发原始包。
            let before = client.shared.snapshot().counters;
            let mut tx = FecSender::default();
            let mut selected = client.selected.clone();
            for seq in 10..14 {
                assert!(
                    tx.send(packet(seq, false), &mut selected, &client.shared)
                        .await
                );
            }
            for _ in 0..4 {
                tokio::time::timeout(Duration::from_secs(2), server.received.recv())
                    .await
                    .unwrap()
                    .unwrap();
            }
            until(|| {
                client.shared.snapshot().counters.fec_tx_packets
                    == before.fec_tx_packets + u64::from(copies)
            })
            .await;
            assert_eq!(
                client.shared.snapshot().counters.tx_copies,
                before.tx_copies + 4
            );
            // 尾包无后续流量时也可以独立 flush。
            assert!(
                tx.send(packet(20, false), &mut selected, &client.shared)
                    .await
            );
            assert!(tx.deadline().is_some());
            tx.flush(&selected, &client.shared);
            until(|| {
                client.shared.snapshot().counters.fec_tx_packets
                    == before.fec_tx_packets + 2 * u64::from(copies)
            })
            .await;
            client.shutdown().await;
            server.shutdown().await;
        }
    }

    #[test]
    fn fec_backup_config_preserves_roles_across_rotation_and_rejects_conflicts() {
        let (id, _) = Identity::generate().unwrap();
        let mut c = config(Mode::Client, &id.public, 4000);
        c.fec = 2;
        c.max_sessions = 2;
        c.active_sessions = 2;
        c.endpoints = toml::from_str::<Config>(&format!(
            r#"
mode = "client"
endpoints = [{{address="127.0.0.1:4000-4003"}}, {{address="127.0.0.1:4004-4007", backup=true}}]
private_key_file = "unused.key"
peer_public_key = "{}"
tun_name = "qw0"
tun_address = "10.77.0.2/30"
peer_address = "10.77.0.1"
"#,
            id.public.encode()
        ))
        .unwrap()
        .endpoints;
        c.validate().unwrap();
        let slots = c.client_slots().unwrap();
        assert_eq!(slots.len(), 2);
        assert!(!slots[0][0].backup);
        assert!(slots[1][0].backup);
        assert!(
            slots
                .iter()
                .all(|v| v.len() == 4 && v.iter().all(|t| t.backup == v[0].backup))
        );
        c.fec_backup_failover = true;
        c.validate().unwrap();
        c.fec = 0;
        assert!(c.validate().is_err());
        c.fec = 2;
        c.endpoints.push("127.0.0.1:4004".into());
        assert!(c.validate().is_err());
        c.endpoints.pop();
        c.endpoints.remove(0);
        assert!(c.validate().is_err(), "即使允许接管也必须配置主线路池");
    }

    #[tokio::test]
    async fn fec_manual_backup_roles_failover_switch_and_bidirectional_routing() {
        for failover in [false, true] {
            let (sid, _) = Identity::generate().unwrap();
            let (cid, _) = Identity::generate().unwrap();
            let port = free_ports();
            let mut sc = config(Mode::Server, &cid.public, port);
            sc.bind = "0.0.0.0:0".parse().unwrap();
            sc.listen = vec![format!("127.0.0.1:{port}-{}", port + 2)];
            sc.fec = 2;
            let mut cc = config(Mode::Client, &sid.public, port);
            cc.endpoints = vec![
                format!("127.0.0.1:{port}").into(),
                crate::config::EndpointSpec::Options(crate::config::EndpointOptions {
                    address: format!("127.0.0.1:{}-{}", port + 1, port + 2),
                    exclusive_group: None,
                    backup: true,
                }),
            ];
            cc.fec = 2;
            cc.max_sessions = 3;
            cc.active_sessions = 3;
            cc.fec_backup_failover = failover;
            cc.selection_policy = SelectionPolicy::Hybrid;
            cc.stable_session_ttl_secs = 0;
            cc.standby_rotate_secs = 0;
            let mut server = Multipath::start(sc, sid).unwrap();
            let mut client = Multipath::start(cc, cid).unwrap();
            until(|| client.shared.snapshot().active == 3 && server.shared.snapshot().active == 3)
                .await;
            let primary = client.shared.state.lock().unwrap().active[0];
            assert_eq!(
                client.shared.state.lock().unwrap().paths[&primary]
                    .remote
                    .port(),
                port
            );
            assert_eq!(
                client.shared.snapshot().fec_primary,
                server.shared.snapshot().fec_primary
            );
            // RTT 更低的手动备用也不能在正常情况下抢占主路。
            {
                let mut state = client.shared.state.lock().unwrap();
                let now = Instant::now();
                state.last_switch = now - Duration::from_secs(10);
                for p in state.paths.values_mut() {
                    p.seen = Some(now);
                    p.rtt = if p.backup { 1.0 } else { 100.0 };
                    p.jitter = 0.0;
                    p.recent_loss = 0.0;
                }
            }
            client.shared.tick();
            assert_eq!(client.shared.state.lock().unwrap().active[0], primary);
            for reverse in [false, true] {
                let (source, dest) = if reverse {
                    (&mut server, &mut client)
                } else {
                    (&mut client, &mut server)
                };
                let mut sender = FecSender::default();
                let mut selected = source.selected.clone();
                for seq in 1..=8 {
                    assert!(
                        sender
                            .send(packet(seq, reverse), &mut selected, &source.shared)
                            .await
                    );
                }
                for _ in 0..8 {
                    tokio::time::timeout(Duration::from_secs(2), dest.received.recv())
                        .await
                        .unwrap()
                        .unwrap();
                }
                until(|| source.shared.snapshot().counters.fec_tx_packets == 4).await;
                let snapshot = source.shared.snapshot();
                for p in snapshot.paths {
                    if p.selection_role == Some("primary") {
                        assert_eq!(p.tx_copies, 8);
                        assert_eq!(p.fec_tx_packets, 0);
                    } else {
                        assert_eq!(p.tx_copies, 0);
                        assert_eq!(p.fec_tx_packets, 2);
                    }
                }
            }
            // 已同步的主路在服务端失去健康状态时，不能静默把校验路提升为主路。
            {
                let mut state = server.shared.state.lock().unwrap();
                state.paths.get_mut(&primary).unwrap().seen = None;
                server.shared.publish(&state);
                assert!(server.selected.borrow().iter().all(|p| !p.primary));
                state.paths.get_mut(&primary).unwrap().seen = Some(Instant::now());
                server.shared.publish(&state);
            }
            // 主队列满时不能偷发到备用队列。
            let (full, _hold) = mpsc::channel(1);
            full.try_send(Bytes::from_static(b"busy")).unwrap();
            let (spare, mut spare_rx) = mpsc::channel(4);
            let (_hold_watch, mut selected) = watch::channel(vec![
                PathSender {
                    id: primary,
                    primary: true,
                    sender: full,
                },
                PathSender {
                    id: primary.wrapping_add(1),
                    primary: false,
                    sender: spare,
                },
            ]);
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(50),
                    FecSender::default().send(packet(20, false), &mut selected, &client.shared)
                )
                .await
                .is_err()
            );
            assert!(spare_rx.try_recv().is_err());
            // 模拟控制面观测到所有主线路失效，检查开关两种结果与恢复回切。
            {
                let mut state = client.shared.state.lock().unwrap();
                state.paths.get_mut(&primary).unwrap().seen = None;
                for p in state.paths.values_mut().filter(|p| p.backup) {
                    p.seen = Some(Instant::now());
                }
            }
            client.shared.tick();
            if failover {
                assert_eq!(client.shared.snapshot().active, 2);
                assert_eq!(client.shared.snapshot().fec_failover_active, Some(true));
            } else {
                assert_eq!(client.shared.snapshot().active, 0);
                assert!(client.selected.borrow().is_empty());
            }
            {
                let mut state = client.shared.state.lock().unwrap();
                state.paths.get_mut(&primary).unwrap().seen = Some(Instant::now());
            }
            client.shared.tick();
            assert_eq!(client.shared.state.lock().unwrap().active[0], primary);
            assert_eq!(client.shared.snapshot().fec_failover_active, Some(false));
            client.shutdown().await;
            server.shutdown().await;
        }
    }

    #[tokio::test]
    async fn fec_mismatch_rejected_before_registering_path() {
        let (sid, _) = Identity::generate().unwrap();
        let (cid, _) = Identity::generate().unwrap();
        let port = free_ports();
        let sc = config(Mode::Server, &cid.public, port);
        let mut cc = config(Mode::Client, &sid.public, port);
        cc.endpoints = vec![format!("127.0.0.1:{port}").into()];
        cc.max_sessions = 2;
        cc.active_sessions = 2;
        cc.fec = 1;
        let mut server = Multipath::start(sc, sid).unwrap();
        let mut client = Multipath::start(cc, cid).unwrap();
        until(|| client.shared.snapshot().connection_failures > 0).await;
        assert_eq!(client.shared.snapshot().connected, 0);
        assert_eq!(server.shared.snapshot().connected, 0);
        client.shutdown().await;
        server.shutdown().await;
    }
    #[test]
    fn fec_numeric_config_limits_and_default() {
        let (identity, _) = Identity::generate().unwrap();
        let mut c = config(Mode::Client, &identity.public, 4433);
        c.endpoints = vec!["127.0.0.1:4433-4434".into()];
        assert_eq!(c.fec, 0);
        c.max_sessions = 2;
        c.active_sessions = 2;
        for copies in 0..=3 {
            c.fec = copies;
            assert!(c.validate().is_ok());
        }
        c.fec = 4;
        assert!(c.validate().is_err());
        c.fec = 1;
        c.active_sessions = 1;
        assert!(c.validate().is_err());
    }
}
