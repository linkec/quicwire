use crate::{identity::PublicKey, selection::SelectionPolicy};
use anyhow::{Context, Result, ensure};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

/// 字符串保留旧格式；对象可把多个入口归入同一互斥组。
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum EndpointSpec {
    Address(String),
    Options(EndpointOptions),
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointOptions {
    pub address: String,
    pub exclusive_group: Option<String>,
    #[serde(default)]
    pub backup: bool,
}
impl From<String> for EndpointSpec {
    fn from(value: String) -> Self {
        Self::Address(value)
    }
}
impl From<&str> for EndpointSpec {
    fn from(value: &str) -> Self {
        Self::Address(value.into())
    }
}
#[derive(Clone, Debug)]
pub struct RemoteTarget {
    pub address: SocketAddr,
    pub exclusive_group: Option<String>,
    pub backup: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<EndpointSpec>,
    #[serde(default = "one")]
    pub max_sessions: usize,
    #[serde(default = "one")]
    pub active_sessions: usize,
    #[serde(default = "default_rotation")]
    pub standby_rotate_secs: u64,
    #[serde(default = "default_switch_threshold")]
    pub switch_threshold_percent: f64,
    #[serde(default)]
    pub selection_policy: SelectionPolicy,
    #[serde(default = "default_stable_ttl")]
    pub stable_session_ttl_secs: u64,
    #[serde(default = "one")]
    pub reserve_sessions: usize,
    #[serde(default = "default_ttl_max_degradation")]
    pub ttl_max_degradation_percent: f64,
    pub endpoint: Option<SocketAddr>,
    /// 可选 DNS 名称，用于 SNI 与 HTTP authority；身份仍按 peer 公钥固定。
    pub server_name: Option<String>,
    pub private_key_file: PathBuf,
    pub peer_public_key: String,
    pub tun_name: String,
    pub tun_address: Ipv4Net,
    pub peer_address: Ipv4Addr,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Linux TUN 的 TCP/UDP 分段与合并；兼容不支持 offload 的环境时可关闭。
    #[serde(default = "default_tun_offload")]
    pub tun_offload: bool,
    /// 0 关闭，1–3 为每组 XOR 校验的发送份数；两端必须一致。
    #[serde(default)]
    pub fec: u8,
    /// 客户端允许手动备用在所有主线路不可用时接管原始数据。
    #[serde(default)]
    pub fec_backup_failover: bool,
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:0".parse().unwrap()
}
fn one() -> usize {
    1
}
fn default_rotation() -> u64 {
    180
}
fn default_switch_threshold() -> f64 {
    20.0
}
fn default_stable_ttl() -> u64 {
    300
}
fn default_ttl_max_degradation() -> f64 {
    10.0
}

fn default_tun_offload() -> bool {
    true
}

fn default_mtu() -> u16 {
    1100
}

impl Config {
    pub fn tls_server_name(&self) -> Result<String> {
        Ok(self
            .server_name
            .clone()
            .unwrap_or(self.endpoint.context("缺少 endpoint")?.ip().to_string()))
    }

    pub fn http_authority(&self) -> Result<String> {
        let endpoint = self.endpoint.context("缺少 endpoint")?;
        Ok(match &self.server_name {
            Some(name) => format!("{name}:{}", endpoint.port()),
            None => endpoint.to_string(),
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            std::fs::metadata(path)?.len() <= 65536,
            "配置文件超过 64 KiB"
        );
        let mut config: Self =
            toml::from_str(&std::fs::read_to_string(path)?).context("TOML 配置无效")?;
        if config.private_key_file.is_relative() {
            config.private_key_file = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(&config.private_key_file);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        PublicKey::parse(&self.peer_public_key)?;
        ensure!(
            !self.fec_backup_failover || (self.mode == Mode::Client && self.fec > 0),
            "fec_backup_failover 仅用于启用 FEC 的客户端"
        );
        ensure!(
            self.fec <= 3,
            "fec 必须为 0–3：0 关闭，1–3 为每组校验副本数"
        );
        ensure!(
            self.switch_threshold_percent.is_finite()
                && (0.0..100.0).contains(&self.switch_threshold_percent),
            "switch_threshold_percent 必须为 0（任何严格改善）至小于 100 的有限数值"
        );
        ensure!(
            self.stable_session_ttl_secs == 0
                || (5..=86400).contains(&self.stable_session_ttl_secs),
            "stable_session_ttl_secs 为 0（关闭）或 5–86400 秒"
        );
        ensure!(self.reserve_sessions <= 32, "reserve_sessions 必须为 0–32");
        ensure!(
            self.ttl_max_degradation_percent.is_finite()
                && (0.0..=1000.0).contains(&self.ttl_max_degradation_percent),
            "ttl_max_degradation_percent 必须为 0–1000 的有限数值"
        );
        ensure!(
            self.standby_rotate_secs == 0 || (5..=86400).contains(&self.standby_rotate_secs),
            "standby_rotate_secs 为 0（关闭）或 5–86400 秒"
        );
        ensure!(
            (1..=32).contains(&self.max_sessions),
            "max_sessions 必须为 1–32"
        );
        ensure!(
            (1..=self.max_sessions).contains(&self.active_sessions),
            "active_sessions 必须为 1..max_sessions"
        );
        if let Some(name) = &self.server_name {
            ensure!(self.mode == Mode::Client, "server_name 仅用于 client 模式");
            ensure!(
                matches!(
                    rustls::pki_types::ServerName::try_from(name.as_str()),
                    Ok(rustls::pki_types::ServerName::DnsName(_))
                ),
                "server_name 必须是有效 DNS 名称"
            );
        }
        ensure!(
            !self.tun_name.is_empty()
                && self.tun_name.len() <= 15
                && self
                    .tun_name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
            "TUN 名称必须为 1 至 15 个字母、数字、下划线或连字符"
        );
        ensure!(
            (576..=1100).contains(&self.mtu),
            "基础版 MTU 必须为 576 至 1100"
        );
        ensure!(
            self.tun_address.prefix_len() >= 24 && self.tun_address.prefix_len() <= 30,
            "基础版隧道前缀必须为 /24 至 /30"
        );
        let local = self.tun_address.addr();
        for address in [local, self.peer_address] {
            ensure!(
                self.tun_address.contains(&address)
                    && address != self.tun_address.network()
                    && address != self.tun_address.broadcast()
                    && !address.is_unspecified()
                    && !address.is_loopback()
                    && !address.is_multicast(),
                "隧道地址必须是同一子网内不同的有效主机地址"
            );
        }
        ensure!(local != self.peer_address, "本地与对端隧道地址不能相同");
        match self.mode {
            Mode::Server => {
                ensure!(
                    self.endpoint.is_none() && self.endpoints.is_empty(),
                    "server 模式不能设置 endpoint/endpoints"
                );
                ensure!(
                    self.max_sessions == 1 && self.active_sessions == 1,
                    "N/K 由客户端配置，服务端不能设置"
                );
                ensure!(
                    self.standby_rotate_secs == default_rotation(),
                    "备用轮转周期仅在客户端配置"
                );
                ensure!(
                    self.switch_threshold_percent == default_switch_threshold()
                        && self.stable_session_ttl_secs == default_stable_ttl()
                        && self.reserve_sessions == 1,
                    "评分阈值、稳定会话 TTL 和预留数量仅在客户端配置"
                );
                ensure!(
                    self.ttl_max_degradation_percent == default_ttl_max_degradation(),
                    "TTL 最大容忍劣化仅在客户端配置"
                );
                ensure!(
                    self.selection_policy == SelectionPolicy::Balanced,
                    "selection_policy 仅在客户端配置"
                );
                self.listen_addresses()?;
            }
            Mode::Client => {
                ensure!(
                    self.fec == 0 || self.active_sessions >= 2,
                    "fec 要求 active_sessions 至少为 2"
                );
                ensure!(self.listen.is_empty(), "client 模式不能设置 listen");
                ensure!(
                    self.max_sessions == 1 || self.bind.port() == 0,
                    "多会话使用独立 socket，bind 必须使用端口 0"
                );
                ensure!(
                    self.standby_rotate_secs == 0 || self.bind.port() == 0,
                    "启用备用轮转时 bind 必须使用端口 0，以更换五元组"
                );
                let slots = self.client_slots()?;
                ensure!(
                    self.fec > 0 || slots.iter().all(|v| !v[0].backup),
                    "endpoint backup 仅用于 FEC 模式"
                );
                ensure!(
                    slots.iter().any(|v| !v[0].backup),
                    "必须至少配置一个非 backup 的主线路端点"
                );
                if slots.iter().any(|v| v[0].exclusive_group.is_some()) {
                    let mut groups = std::collections::BTreeSet::new();
                    let capacity = slots
                        .iter()
                        .filter(|v| match &v[0].exclusive_group {
                            Some(g) => groups.insert(g.clone()),
                            None => true,
                        })
                        .count();
                    ensure!(
                        capacity >= self.active_sessions,
                        "exclusive_group 互斥约束下无法满足 active_sessions；增加不同组或减少激活数量"
                    );
                }
                for endpoint in self.remote_addresses()? {
                    ensure!(
                        endpoint.port() != 0
                            && !endpoint.ip().is_unspecified()
                            && !endpoint.ip().is_multicast(),
                        "endpoint 必须是有效的单播地址和非零端口"
                    );
                    ensure!(
                        endpoint.is_ipv4() == self.bind.is_ipv4(),
                        "bind 与 endpoint 地址族必须相同"
                    );
                    if let std::net::IpAddr::V4(ip) = endpoint.ip() {
                        ensure!(
                            !self.tun_address.contains(&ip),
                            "外层 endpoint 不能落在隧道子网内，避免路由递归"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

impl Config {
    pub fn remote_targets(&self) -> Result<Vec<RemoteTarget>> {
        ensure!(
            self.endpoint.is_none() || self.endpoints.is_empty(),
            "endpoint 与 endpoints 不能同时设置"
        );
        ensure!(self.endpoints.len() <= 256, "地址列表过长");
        if let Some(address) = self.endpoint {
            return Ok(vec![RemoteTarget {
                address,
                exclusive_group: None,
                backup: false,
            }]);
        }
        let mut targets = std::collections::BTreeMap::new();
        // 保留显式组的配置顺序；无分组旧配置仍按 IP 交错。
        let mut group_order = Vec::new();
        for spec in &self.endpoints {
            let (address, group, backup) = match spec {
                EndpointSpec::Address(a) => (a, None, false),
                EndpointSpec::Options(o) => (&o.address, o.exclusive_group.clone(), o.backup),
            };
            if let Some(name) = &group {
                ensure!(
                    !name.is_empty()
                        && name.len() <= 64
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                    "exclusive_group 必须为 1–64 个字母、数字、下划线或连字符"
                );
                if !group_order.contains(name) {
                    group_order.push(name.clone());
                }
            }
            for address in expand_addresses(std::slice::from_ref(address))? {
                if let Some(existing) = targets.get(&address) {
                    ensure!(
                        existing == &(group.clone(), backup),
                        "同一端点不能配置冲突的 exclusive_group 或 backup：{address}"
                    );
                } else {
                    targets.insert(address, (group.clone(), backup));
                }
            }
            ensure!(targets.len() <= 256, "地址展开后超过 256 个");
        }
        ensure!(!targets.is_empty(), "client 必须设置 endpoint 或 endpoints");
        let mut buckets: std::collections::BTreeMap<_, std::collections::VecDeque<_>> =
            std::collections::BTreeMap::new();
        for (address, (exclusive_group, backup)) in targets {
            let key = match &exclusive_group {
                Some(g) => (
                    0,
                    group_order.iter().position(|n| n == g).unwrap(),
                    address.ip(),
                ),
                None => (1, 0, address.ip()),
            };
            // 同名组跨 IP 也放在同一个桶内。
            let key = if key.0 == 0 {
                (key.0, key.1, "0.0.0.0".parse().unwrap())
            } else {
                key
            };
            buckets
                .entry((key, backup))
                .or_default()
                .push_back(RemoteTarget {
                    address,
                    exclusive_group,
                    backup,
                });
        }
        let mut result = Vec::new();
        while !buckets.is_empty() {
            buckets.retain(|_, values| {
                if let Some(a) = values.pop_front() {
                    result.push(a);
                }
                !values.is_empty()
            });
        }
        Ok(result)
    }
    pub fn remote_addresses(&self) -> Result<Vec<SocketAddr>> {
        Ok(self
            .remote_targets()?
            .into_iter()
            .map(|t| t.address)
            .collect())
    }
    /// 每个槽位只在同组入口中轮转，避免奇数 N 或不均匀组大小使分组漂移。
    pub fn client_slots(&self) -> Result<Vec<Vec<RemoteTarget>>> {
        let targets = self.remote_targets()?;
        let count = self.max_sessions.min(targets.len());
        if !targets
            .iter()
            .any(|t| t.exclusive_group.is_some() || t.backup)
        {
            return Ok((0..count)
                .map(|slot| targets.iter().skip(slot).step_by(count).cloned().collect())
                .collect());
        }
        let mut result: Vec<Vec<RemoteTarget>> = targets
            .iter()
            .take(count)
            .cloned()
            .map(|t| vec![t])
            .collect();
        let mut cursor = std::collections::BTreeMap::new();
        for target in targets.into_iter().skip(count) {
            let slots: Vec<_> = result
                .iter()
                .enumerate()
                .filter(|(_, v)| {
                    v[0].exclusive_group == target.exclusive_group && v[0].backup == target.backup
                })
                .map(|(i, _)| i)
                .collect();
            ensure!(
                !slots.is_empty(),
                "max_sessions 不足以为每个互斥组与主备角色组合（及未分组入口）分配候选槽位"
            );
            let next = cursor
                .entry((target.exclusive_group.clone(), target.backup))
                .or_insert(0usize);
            result[slots[*next % slots.len()]].push(target);
            *next += 1;
        }
        Ok(result)
    }
    pub fn endpoint_backup(&self, address: SocketAddr) -> bool {
        self.remote_targets()
            .unwrap_or_default()
            .iter()
            .any(|t| t.address == address && t.backup)
    }
    pub fn exclusive_group(&self, address: SocketAddr) -> Option<String> {
        self.remote_targets()
            .ok()?
            .into_iter()
            .find(|t| t.address == address)?
            .exclusive_group
    }
    pub fn listen_addresses(&self) -> Result<Vec<SocketAddr>> {
        ensure!(
            self.listen.is_empty() || self.bind == default_bind(),
            "listen 与旧 bind 监听配置不能同时设置"
        );
        let values = if self.listen.is_empty() {
            vec![self.bind]
        } else {
            let specs: Vec<_> = self
                .listen
                .iter()
                .map(|s| {
                    if s.contains(':') {
                        s.clone()
                    } else {
                        format!("0.0.0.0:{s}")
                    }
                })
                .collect();
            expand_addresses(&specs)?
        };
        ensure!(
            !values.is_empty()
                && values
                    .iter()
                    .all(|a| a.port() != 0 && !a.ip().is_multicast()),
            "监听地址或端口无效"
        );
        for (i, a) in values.iter().enumerate() {
            for b in &values[..i] {
                ensure!(
                    !(a.port() == b.port()
                        && a.is_ipv4() == b.is_ipv4()
                        && (a.ip().is_unspecified() || b.ip().is_unspecified())),
                    "监听通配地址与指定地址重叠"
                );
            }
        }
        Ok(values)
    }
    pub fn status_path(&self) -> PathBuf {
        // network namespace 独立，但共享文件系统；加入 netns 标识避免 qw0 冲突。
        #[cfg(target_os = "linux")]
        let namespace = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata("/proc/self/ns/net")
                .map(|m| m.ino())
                .unwrap_or(0)
        };
        #[cfg(not(target_os = "linux"))]
        let namespace = 0u64;
        PathBuf::from(format!("/run/quicwire/{namespace}-{}.sock", self.tun_name))
    }
}

pub fn expand_addresses(specs: &[String]) -> Result<Vec<SocketAddr>> {
    let mut result = std::collections::BTreeSet::new();
    ensure!(specs.len() <= 256, "地址列表过长");
    for spec in specs {
        let (host, port) = spec
            .rsplit_once(':')
            .context("地址必须是 IP:端口或 IP:起始-结束")?;
        let ip: std::net::IpAddr = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .context("仅支持 IP 地址")?;
        ensure!(
            !ip.is_ipv6() || (host.starts_with('[') && host.ends_with(']')),
            "IPv6 必须使用 [地址]:端口"
        );
        let (start, end) = match port.split_once('-') {
            Some((a, b)) => (a.parse::<u16>()?, b.parse::<u16>()?),
            None => {
                let p = port.parse::<u16>()?;
                (p, p)
            }
        };
        ensure!(
            start > 0 && start <= end && u32::from(end) - u32::from(start) < 256,
            "端口范围无效或超过 256"
        );
        for port in start..=end {
            result.insert(SocketAddr::new(ip, port));
        }
        ensure!(result.len() <= 256, "地址展开后超过 256 个");
    }
    Ok(result.into_iter().collect())
}
