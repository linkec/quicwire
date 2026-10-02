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
    pub bind: SocketAddr,
    pub endpoint: Option<SocketAddr>,
    pub private_key_file: PathBuf,
    pub peer_public_key: String,
    pub tun_name: String,
    pub tun_address: Ipv4Net,
    pub peer_address: Ipv4Addr,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_mtu() -> u16 {
    1100
}

impl Config {
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
                ensure!(self.endpoint.is_none(), "server 模式不能设置 endpoint");
                ensure!(self.bind.port() != 0, "server 监听端口不能为 0");
            }
            Mode::Client => {
                let endpoint = self.endpoint.context("client 模式必须设置 endpoint")?;
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
        Ok(())
    }
}
