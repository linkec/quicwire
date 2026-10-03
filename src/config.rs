use crate::identity::PublicKey;
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default = "one")]
    pub max_sessions: usize,
    #[serde(default = "one")]
    pub active_sessions: usize,
    #[serde(default = "default_rotation")]
    pub standby_rotate_secs: u64,
    #[serde(default = "default_switch_threshold")]
    pub switch_threshold_percent: f64,
    #[serde(default = "default_stable_ttl")]
    pub stable_session_ttl_secs: u64,
    #[serde(default = "one")]
    pub reserve_sessions: usize,
    #[serde(default = "default_ttl_degradation")]
    pub ttl_degradation_percent: f64,
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
fn default_ttl_degradation() -> f64 {
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
            self.ttl_degradation_percent.is_finite()
                && (0.0..=1000.0).contains(&self.ttl_degradation_percent),
            "ttl_degradation_percent 必须为 0–1000 的有限数值"
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
                    self.ttl_degradation_percent == default_ttl_degradation(),
                    "TTL 劣化门槛仅在客户端配置"
                );
                self.listen_addresses()?;
            }
            Mode::Client => {
                ensure!(self.listen.is_empty(), "client 模式不能设置 listen");
                ensure!(
                    self.max_sessions == 1 || self.bind.port() == 0,
                    "多会话使用独立 socket，bind 必须使用端口 0"
                );
                ensure!(
                    self.standby_rotate_secs == 0 || self.bind.port() == 0,
                    "启用备用轮转时 bind 必须使用端口 0，以更换五元组"
                );
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
    pub fn remote_addresses(&self) -> Result<Vec<SocketAddr>> {
        ensure!(
            self.endpoint.is_none() || self.endpoints.is_empty(),
            "endpoint 与 endpoints 不能同时设置"
        );
        let addresses = match self.endpoint {
            Some(a) => vec![a],
            None => expand_addresses(&self.endpoints)?,
        };
        ensure!(
            !addresses.is_empty(),
            "client 必须设置 endpoint 或 endpoints"
        );
        // 按 IP 轮转，避免连续端口优先占满全部连接名额。
        let mut groups: std::collections::BTreeMap<_, std::collections::VecDeque<_>> =
            std::collections::BTreeMap::new();
        for a in addresses {
            groups.entry(a.ip()).or_default().push_back(a);
        }
        let mut result = Vec::new();
        while !groups.is_empty() {
            groups.retain(|_, values| {
                if let Some(a) = values.pop_front() {
                    result.push(a);
                }
                !values.is_empty()
            });
        }
        Ok(result)
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
