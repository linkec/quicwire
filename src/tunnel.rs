use crate::{
    config::{Config, Mode},
    identity::{Identity, PublicKey},
    packet::valid_ipv4,
    transport,
};
use anyhow::{Context, Result, ensure};
use quinn::{Connection, Endpoint};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::watch;

#[derive(Default)]
struct Counters {
    tx: AtomicU64,
    rx: AtomicU64,
    disconnected: AtomicU64,
    invalid: AtomicU64,
    queue_full: AtomicU64,
    send_error: AtomicU64,
}
impl Counters {
    fn log(&self) {
        eprintln!(
            "统计 tx_queued={} rx_delivered={} drop_disconnected={} drop_invalid={} drop_queue_full={} drop_send_error={}",
            self.tx.load(Ordering::Relaxed),
            self.rx.load(Ordering::Relaxed),
            self.disconnected.load(Ordering::Relaxed),
            self.invalid.load(Ordering::Relaxed),
            self.queue_full.load(Ordering::Relaxed),
            self.send_error.load(Ordering::Relaxed)
        );
    }
}

pub async fn run(config: Config, identity: Identity) -> Result<()> {
    let peer = PublicKey::parse(&config.peer_public_key)?;
    let endpoint = match config.mode {
        Mode::Server => Endpoint::server(transport::server_config(&identity, &peer)?, config.bind)?,
        Mode::Client => {
            let mut endpoint = Endpoint::client(config.bind)?;
            endpoint.set_default_client_config(transport::client_config(&identity, &peer)?);
            endpoint
        }
    };
    ensure!(
        !std::path::Path::new("/sys/class/net")
            .join(&config.tun_name)
            .exists(),
        "TUN 名称已存在，请选择其他名称"
    );
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&config.tun_name)
        .address(config.tun_address.addr())
        .netmask(config.tun_address.netmask())
        .mtu(config.mtu)
        .up();
    let device =
        tun::create_as_async(&tun_config).context("无法创建 TUN，需要 root 或 CAP_NET_ADMIN")?;
    let (active, current) = watch::channel(None::<Connection>);
    let counters = Counters::default();
    eprintln!(
        "已启动 mode={:?} bind={} tun={} address={} mtu={}",
        config.mode,
        endpoint.local_addr()?,
        config.tun_name,
        config.tun_address,
        config.mtu
    );
    let result = tokio::select! {
        result = send_packets(&device, &config, current, &counters) => result,
        result = manage_connections(&endpoint, &device, &config, active, &counters) => result,
        result = shutdown_signal() => result,
        _ = log_periodically(&counters) => unreachable!(),
    };
    endpoint.close(0_u32.into(), b"shutdown");
    endpoint.set_server_config(None);
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    counters.log();
    eprintln!("已停止，释放本进程创建的 TUN");
    result
}

async fn send_packets(
    device: &tun::AsyncDevice,
    config: &Config,
    active: watch::Receiver<Option<Connection>>,
    counters: &Counters,
) -> Result<()> {
    let mut packet = vec![0u8; 65536];
    loop {
        let length = device.recv(&mut packet).await.context("读取 TUN 失败")?;
        if !valid_ipv4(
            &packet[..length],
            config.tun_address.addr(),
            config.peer_address,
            config.mtu,
        ) {
            counters.invalid.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let connection = active.borrow().clone();
        let Some(connection) = connection else {
            counters.disconnected.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        // 唯一 DATAGRAM 生产者，先查余量以避免淘汰旧包而统计不可见。
        if connection.datagram_send_buffer_space() < length {
            counters.queue_full.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        match connection.send_datagram(packet[..length].to_vec().into()) {
            Ok(()) => {
                counters.tx.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                counters.send_error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn manage_connections(
    endpoint: &Endpoint,
    device: &tun::AsyncDevice,
    config: &Config,
    active: watch::Sender<Option<Connection>>,
    counters: &Counters,
) -> Result<()> {
    let mut backoff = 1u64;
    loop {
        let connected: Result<Connection> = match config.mode {
            Mode::Client => {
                let connecting =
                    endpoint.connect(config.endpoint.context("缺少 endpoint")?, "quicwire")?;
                tokio::time::timeout(transport::HANDSHAKE_TIMEOUT, connecting)
                    .await
                    .context("QUIC 握手超时")
                    .and_then(|result| result.map_err(Into::into))
            }
            Mode::Server => {
                let incoming = endpoint.accept().await.context("监听端已关闭")?;
                tokio::time::timeout(transport::HANDSHAKE_TIMEOUT, incoming)
                    .await
                    .context("QUIC 握手超时")
                    .and_then(|result| result.map_err(Into::into))
            }
        };
        let session = async {
            let connection = connected?;
            transport::negotiate(&connection, config).await?;
            eprintln!(
                "隧道已连接 peer={} remote={}",
                config.peer_address,
                connection.remote_address()
            );
            active.send_replace(Some(connection.clone()));
            backoff = 1;
            let result = receive_packets(endpoint, &connection, device, config, counters).await;
            active.send_replace(None);
            connection.close(0_u32.into(), b"session ended");
            result
        }
        .await;
        if let Err(error) = session {
            eprintln!("连接结束或建立失败：{error:#}");
        }
        if config.mode == Mode::Client {
            eprintln!("{backoff} 秒后重连");
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(8);
        }
    }
}

async fn receive_packets(
    endpoint: &Endpoint,
    connection: &Connection,
    device: &tun::AsyncDevice,
    config: &Config,
    counters: &Counters,
) -> Result<()> {
    loop {
        tokio::select! {
            data = connection.read_datagram() => {
                let data = data?;
                if !valid_ipv4(&data, config.peer_address, config.tun_address.addr(), config.mtu) {
                    counters.invalid.fetch_add(1, Ordering::Relaxed); continue;
                }
                let written = device.send(&data).await.context("写入 TUN 失败")?;
                ensure!(written == data.len(), "TUN 写入不完整");
                counters.rx.fetch_add(1, Ordering::Relaxed);
            }
            incoming = endpoint.accept(), if config.mode == Mode::Server => {
                // 基础版单 peer，新连接不抢占正在传输的连接。
                if let Some(incoming) = incoming { incoming.refuse(); }
            }
        }
    }
}

async fn log_periodically(counters: &Counters) {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        counters.log();
    }
}

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {}, }
    Ok(())
}
