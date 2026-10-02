use crate::{
    config::{Config, Mode},
    identity::{Identity, PublicKey},
    packet::valid_ipv4,
    transport,
};
use anyhow::{Context, Result, ensure};
use quinn::{Connection, Endpoint};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::watch;
use tun_rs::{AsyncDevice, DeviceBuilder, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

#[derive(Default)]
struct Counters {
    tx: AtomicU64,
    rx: AtomicU64,
    disconnected: AtomicU64,
    invalid: AtomicU64,
    send_error: AtomicU64,
}
impl Counters {
    fn log(&self) {
        eprintln!(
            "统计 tx_queued={} rx_delivered={} drop_disconnected={} drop_invalid={} drop_send_error={}",
            self.tx.load(Ordering::Relaxed),
            self.rx.load(Ordering::Relaxed),
            self.disconnected.load(Ordering::Relaxed),
            self.invalid.load(Ordering::Relaxed),
            self.send_error.load(Ordering::Relaxed)
        );
    }
}

pub async fn run(config: Config, identity: Identity) -> Result<()> {
    config.validate()?;
    let peer = PublicKey::parse(&config.peer_public_key)?;
    let socket = std::net::UdpSocket::bind(config.bind)?;
    // 只调整本进程 socket，不修改系统 sysctl。权限不足时保留普通设置。
    // Linux 报告的缓冲值包含内核为簿记而加倍的部分。
    {
        use nix::sys::socket::{getsockopt, setsockopt, sockopt};
        let bytes = 7 * 1024 * 1024;
        setsockopt(&socket, sockopt::RcvBuf, &bytes)?;
        setsockopt(&socket, sockopt::SndBuf, &bytes)?;
        let _ = setsockopt(&socket, sockopt::RcvBufForce, &bytes);
        let _ = setsockopt(&socket, sockopt::SndBufForce, &bytes);
        eprintln!(
            "UDP缓冲 recv={} send={}",
            getsockopt(&socket, sockopt::RcvBuf)?,
            getsockopt(&socket, sockopt::SndBuf)?
        );
    }
    let server_config = match config.mode {
        Mode::Server => Some(transport::server_config(&identity, &peer)?),
        Mode::Client => None,
    };
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        server_config,
        socket,
        std::sync::Arc::new(quinn::TokioRuntime),
    )?;
    if config.mode == Mode::Client {
        endpoint.set_default_client_config(transport::client_config(&identity, &peer)?);
    }
    ensure!(
        !std::path::Path::new("/sys/class/net")
            .join(&config.tun_name)
            .exists(),
        "TUN 名称已存在，请选择其他名称"
    );
    let device = DeviceBuilder::new()
        .name(&config.tun_name)
        .ipv4(
            config.tun_address.addr(),
            config.tun_address.prefix_len(),
            None,
        )
        .mtu(config.mtu)
        .offload(config.tun_offload)
        .enable(true)
        .build_async()
        .context("无法创建 TUN，需要 root 或 CAP_NET_ADMIN")?;
    // 限制 TUN 发送积压，避免背压把延迟转移到内核队列。
    device.set_tx_queue_len(64)?;
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
    let stats_current = current.clone();
    let result = tokio::select! {
        result = send_packets(&device, &config, current, &counters) => result,
        result = manage_connections(&endpoint, &device, &config, active, &counters) => result,
        result = shutdown_signal() => result,
        _ = log_periodically(&counters, stats_current) => unreachable!(),
    };
    endpoint.close(0_u32.into(), b"shutdown");
    endpoint.set_server_config(None);
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    counters.log();
    eprintln!("已停止，释放本进程创建的 TUN");
    result
}

async fn send_packets(
    device: &AsyncDevice,
    config: &Config,
    active: watch::Receiver<Option<Connection>>,
    counters: &Counters,
) -> Result<()> {
    let mut original = vec![0u8; 65535 + VIRTIO_NET_HDR_LEN];
    // 低 MTU 加上最大 IPv4/TCP options 时，单个 GSO 包可能拆出超过 128 段。
    let batch_size = IDEAL_BATCH_SIZE.max(65535_usize.div_ceil(usize::from(config.mtu) - 120));
    let mut packets = vec![vec![0u8; 65535]; batch_size];
    let mut sizes = vec![0; batch_size];
    loop {
        let count = device
            .recv_multiple(&mut original, &mut packets, &mut sizes, 0)
            .await
            .context("批量读取 TUN 失败")?;
        let Some(connection) = active.borrow().clone() else {
            counters
                .disconnected
                .fetch_add(count as u64, Ordering::Relaxed);
            continue;
        };
        for i in 0..count {
            let packet = &packets[i];
            let length = sizes[i];
            if !valid_ipv4(
                &packet[..length],
                config.tun_address.addr(),
                config.peer_address,
                config.mtu,
            ) {
                counters.invalid.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // 等待空间，避免 TCP 突发被小发送队列直接丢弃。
            // 连接关闭会唤醒等待；外层 select 仍可处理退出和接收。
            let result = connection
                .send_datagram_wait(packet[..length].to_vec().into())
                .await;
            match result {
                Ok(()) => {
                    counters.tx.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    counters.send_error.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

async fn manage_connections(
    endpoint: &Endpoint,
    device: &AsyncDevice,
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
    device: &AsyncDevice,
    config: &Config,
    counters: &Counters,
) -> Result<()> {
    let mut gro = GROTable::default();
    let mut packets: Vec<Vec<u8>> = (0..IDEAL_BATCH_SIZE)
        .map(|_| Vec::with_capacity(65535 + VIRTIO_NET_HDR_LEN))
        .collect();
    loop {
        tokio::select! {
            data = connection.read_datagram() => {
                let mut data = data?;
                let mut count = 0;
                for index in 0..IDEAL_BATCH_SIZE {
                    if valid_ipv4(&data, config.peer_address, config.tun_address.addr(), config.mtu) {
                        let packet = &mut packets[count];
                        packet.clear();
                        packet.resize(VIRTIO_NET_HDR_LEN, 0);
                        packet.extend_from_slice(&data);
                        count += 1;
                    } else {
                        counters.invalid.fetch_add(1, Ordering::Relaxed);
                    }
                    if index + 1 == IDEAL_BATCH_SIZE { break; }
                    let next = poll_fn(|cx| {
                        let mut read = pin!(connection.read_datagram());
                        Poll::Ready(match read.as_mut().poll(cx) {
                            Poll::Ready(value) => Some(value),
                            Poll::Pending => None,
                        })
                    }).await;
                    match next { Some(value) => data = value?, None => break }
                }
                if count != 0 {
                    device.send_multiple(&mut gro, &mut packets[..count], VIRTIO_NET_HDR_LEN).await.context("批量写入 TUN 失败")?;
                    counters.rx.fetch_add(count as u64, Ordering::Relaxed);
                }
            }
            incoming = endpoint.accept(), if config.mode == Mode::Server => {
                if let Some(incoming) = incoming { incoming.refuse(); }
            }
        }
    }
}

async fn log_periodically(counters: &Counters, active: watch::Receiver<Option<Connection>>) {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        counters.log();
        if let Some(connection) = active.borrow().as_ref() {
            let stats = connection.stats();
            eprintln!(
                "QUIC统计 rtt_us={} cwnd={} sent={} lost={} rx_datagrams={}",
                stats.path.rtt.as_micros(),
                stats.path.cwnd,
                stats.path.sent_packets,
                stats.path.lost_packets,
                stats.frame_rx.datagram
            );
        }
    }
}

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {}, }
    Ok(())
}
