//! 仅本机 Unix socket 只读状态；无网络管理端口。
use crate::{config::Config, multipath::Shared};
use anyhow::{Context, Result, ensure};
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

pub struct Server {
    listener: UnixListener,
    path: std::path::PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
impl Server {
    pub fn bind(config: &Config) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
        let path = config.status_path();
        let parent = path.parent().unwrap();
        if !parent.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(parent)?;
        }
        let metadata = std::fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0,
            "状态目录必须为不可被其他用户写入的真实目录"
        );
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            ensure!(
                metadata.file_type().is_socket(),
                "状态路径已存在且不是 socket"
            );
            ensure!(
                std::os::unix::net::UnixStream::connect(&path).is_err(),
                "该 TUN 的状态服务已运行"
            );
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }
    pub async fn run(&self, shared: Arc<Shared>) -> Result<()> {
        loop {
            let (mut socket, _) = self.listener.accept().await?;
            let mut json = serde_json::to_vec(&shared.snapshot())?;
            json.push(b'\n');
            // 单个只读快照限时写入，慢本机读者不影响数据面。
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                socket.write_all(&json),
            )
            .await;
        }
    }
}
pub async fn read(path: &Path, json: bool) -> Result<()> {
    let mut socket = UnixStream::connect(path)
        .await
        .context("无法读取状态：请确认服务正在运行，并在同一网络命名空间内执行")?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        (&mut socket).take(1024 * 1024).read_to_end(&mut bytes),
    )
    .await??;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!(
        "QW {}  mode={} 运行={}秒",
        value["tun"].as_str().unwrap_or(""),
        value["mode"].as_str().unwrap_or(""),
        value["uptime_seconds"]
    );
    println!(
        "连接 {}/{}，激活 {}/{}，健康 {}，降级 {}",
        value["connected"],
        value["max_sessions"],
        value["active"],
        value["active_sessions"],
        value["healthy"],
        value["degraded"]
    );
    println!(
        "状态：{}；切换 {} 次，备用轮转 {} 次",
        value["reason"].as_str().unwrap_or(""),
        value["switches"],
        value["rotations"]
    );
    println!(
        "路径ID           状态       本地绑定 → 对端                            RTT(ms)  抖动(ms)  探测超时/次数  备用秒"
    );
    if let Some(paths) = value["paths"].as_array() {
        for p in paths {
            println!(
                "{} {:<10} {} → {}  {:.2}  {:.2}  {}/{}  {}",
                p["id"].as_str().unwrap_or(""),
                p["state"].as_str().unwrap_or(""),
                p["local"].as_str().unwrap_or(""),
                p["remote"].as_str().unwrap_or(""),
                p["probe_rtt_ms"].as_f64().unwrap_or(0.0),
                p["jitter_ms"].as_f64().unwrap_or(0.0),
                p["probe_timeouts"],
                p["probes"],
                p["standby_seconds"]
            );
        }
    }
    println!(
        "TUN 内核队列丢弃：发送={} 接收={}（与 QW 副本队列分开统计）",
        value["tun_tx_dropped"], value["tun_rx_dropped"]
    );
    println!("计数：{}", value["counters"]);
    Ok(())
}
