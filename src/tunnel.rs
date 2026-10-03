use crate::{
    config::Config,
    identity::Identity,
    multipath::{FecSender, Multipath, PathSender, Shared},
    packet::valid_ipv4,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};
use tun_rs::{AsyncDevice, DeviceBuilder, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

pub async fn run(config: Config, identity: Identity) -> Result<()> {
    config.validate()?;
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
    device.set_tx_queue_len(64)?;
    let status = crate::status::Server::bind(&config)?;
    let mut engine = Multipath::start(config.clone(), identity)?;
    let shared = engine.shared.clone();
    eprintln!(
        "已启动 mode={:?} tun={} address={} mtu={}",
        config.mode, config.tun_name, config.tun_address, config.mtu
    );
    let result = tokio::select! {
        r=send_packets(&device,&config,engine.selected.clone(),&shared)=>r,
        r=receive_packets(&device,&mut engine.received,&shared)=>r,
        r=engine.manager.as_mut().unwrap()=>{engine.manager.take();r.context("连接管理任务异常")?},
        r=status.run(shared.clone())=>r,
        r=shutdown_signal()=>r,
        _=log_periodically(&shared)=>unreachable!(),
    };
    engine.shutdown().await;
    drop(engine);
    eprintln!("已停止，释放本进程创建的 TUN");
    result
}
async fn send_packets(
    device: &AsyncDevice,
    config: &Config,
    mut active: watch::Receiver<Vec<PathSender>>,
    shared: &Shared,
) -> Result<()> {
    let mut original = vec![0u8; 65535 + VIRTIO_NET_HDR_LEN];
    let batch_size = IDEAL_BATCH_SIZE.max(65535_usize.div_ceil(usize::from(config.mtu) - 120));
    let mut packets = vec![vec![0u8; 65535]; batch_size];
    let mut sizes = vec![0; batch_size];
    let mut sequence = 0u64;
    let mut fec = FecSender::default();
    loop {
        let deadline = fec.deadline();
        let count = tokio::select! {
            result = device.recv_multiple(&mut original, &mut packets, &mut sizes, 0) => result.context("批量读取 TUN 失败")?,
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(std::time::Instant::now).into()), if deadline.is_some() => {
                fec.flush(&active,shared); continue;
            }
        };
        for i in 0..count {
            let packet = &packets[i][..sizes[i]];
            if !valid_ipv4(
                packet,
                config.tun_address.addr(),
                config.peer_address,
                config.mtu,
            ) {
                shared.counters(|c| c.invalid += 1);
                continue;
            }
            sequence = sequence
                .checked_add(1)
                .context("数据包序号耗尽，需要重启")?;
            let mut data = Vec::with_capacity(packet.len() + 9);
            data.push(3);
            data.extend_from_slice(&sequence.to_be_bytes());
            data.extend_from_slice(packet);
            if fec
                .deadline()
                .is_some_and(|t| t <= std::time::Instant::now())
            {
                fec.flush(&active, shared);
            }
            if fec.send(data.into(), &mut active, shared).await {
                shared.counters(|c| {
                    c.tx_packets += 1;
                    c.tx_bytes += packet.len() as u64;
                });
            }
        }
    }
}
async fn receive_packets(
    device: &AsyncDevice,
    received: &mut mpsc::Receiver<Bytes>,
    shared: &Shared,
) -> Result<()> {
    let mut gro = GROTable::default();
    let mut packets: Vec<Vec<u8>> = (0..IDEAL_BATCH_SIZE)
        .map(|_| Vec::with_capacity(65535 + VIRTIO_NET_HDR_LEN))
        .collect();
    loop {
        let mut data = received.recv().await.context("接收队列已关闭")?;
        let mut count = 0;
        let mut bytes = 0;
        for (index, packet) in packets.iter_mut().enumerate() {
            packet.clear();
            packet.resize(VIRTIO_NET_HDR_LEN, 0);
            packet.extend_from_slice(&data);
            count += 1;
            bytes += data.len();
            if index + 1 == IDEAL_BATCH_SIZE {
                break;
            }
            match received.try_recv() {
                Ok(next) => data = next,
                Err(_) => break,
            }
        }
        device
            .send_multiple(&mut gro, &mut packets[..count], VIRTIO_NET_HDR_LEN)
            .await
            .context("批量写入 TUN 失败")?;
        shared.counters(|c| {
            c.rx_packets += count as u64;
            c.rx_bytes += bytes as u64;
        });
    }
}
async fn log_periodically(shared: &Arc<Shared>) {
    let mut timer = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        if let Ok(text) = serde_json::to_string(&shared.snapshot()) {
            eprintln!("多路径统计 {text}");
        }
    }
}
async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r?,_=terminate.recv()=>(),}
    Ok(())
}
