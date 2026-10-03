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
pub async fn read(path: &Path, json: bool, verbose: bool) -> Result<()> {
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
    print!("{}", render(&value, verbose));
    Ok(())
}

fn text(value: &serde_json::Value) -> &str {
    value.as_str().unwrap_or("-")
}
fn count(value: &serde_json::Value) -> String {
    value
        .as_u64()
        .map(group_number)
        .unwrap_or_else(|| "-".into())
}
fn group_number(n: u64) -> String {
    let raw = n.to_string();
    raw.chars()
        .enumerate()
        .fold(String::new(), |mut out, (i, c)| {
            if i > 0 && (raw.len() - i).is_multiple_of(3) {
                out.push(',');
            }
            out.push(c);
            out
        })
}
fn bytes(value: &serde_json::Value) -> String {
    let Some(n) = value.as_u64() else {
        return "-".into();
    };
    let mut amount = n as f64;
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0;
    while amount >= 1024.0 && unit + 1 < units.len() {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{amount:.2} {}", units[unit])
    }
}
fn duration(value: &serde_json::Value) -> String {
    let Some(s) = value.as_u64() else {
        return "-".into();
    };
    if s >= 86400 {
        format!(
            "{}天 {:02}:{:02}:{:02}",
            s / 86400,
            s / 3600 % 24,
            s / 60 % 60,
            s % 60
        )
    } else {
        format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    }
}
fn decimal(value: &serde_json::Value) -> String {
    value
        .as_f64()
        .filter(|n| n.is_finite())
        .map(|n| format!("{n:.2}"))
        .unwrap_or_else(|| "-".into())
}
fn policy_name(value: &serde_json::Value) -> &str {
    match value.as_str() {
        Some("hybrid") => "混合",
        Some("balanced") => "综合",
        Some("primary") => "主路",
        Some("backup") => "校验备用",
        Some("low_latency") => "低延迟",
        Some("low_loss") => "低丢包",
        _ => text(value),
    }
}
fn state_name(value: &serde_json::Value) -> &str {
    match value.as_str() {
        Some("active") => "激活",
        Some("standby") => "备用",
        Some("probing") => "探测中",
        Some("unhealthy") => "不健康",
        _ => text(value),
    }
}
fn role_name(value: &serde_json::Value) -> &str {
    match value.as_str() {
        Some("latency") => "延迟",
        Some("loss_guard") => "保障",
        Some("balanced") => "综合",
        Some("primary") => "主路",
        Some("backup") => "校验备用",
        _ => "",
    }
}
// 表中只有 ASCII 标识与中文标签；地址另起一行，IPv6 不挤占数字列。
fn width(s: &str) -> usize {
    s.chars().map(|c| if c.is_ascii() { 1 } else { 2 }).sum()
}
fn table(out: &mut String, rows: &[Vec<String>]) {
    use std::fmt::Write;
    let mut widths = vec![0; rows.first().map_or(0, Vec::len)];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(width(cell));
        }
    }
    for row in rows {
        out.push_str("  ");
        for (i, cell) in row.iter().enumerate() {
            let _ = write!(
                out,
                "{cell}{}",
                " ".repeat(widths[i] - width(cell) + if i + 1 < row.len() { 2 } else { 0 })
            );
        }
        out.push('\n');
    }
}
fn render(v: &serde_json::Value, verbose: bool) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let client = v["mode"] == "client";
    let health = if v["degraded"] == true {
        "降级"
    } else {
        "正常"
    };
    let _ = writeln!(
        out,
        "QW {} · {} · {} · 运行 {}",
        text(&v["tun"]),
        if client { "客户端" } else { "服务端" },
        health,
        duration(&v["uptime_seconds"])
    );
    let _ = writeln!(
        out,
        "会话 {}/{}  健康 {}  激活 {}/{}",
        count(&v["connected"]),
        count(&v["max_sessions"]),
        count(&v["healthy"]),
        count(&v["active"]),
        count(&v["active_sessions"])
    );
    let _ = writeln!(out, "状态：{}", text(&v["reason"]));
    if client {
        let _ = writeln!(
            out,
            "选路：{}  切换门槛 {}%  预留 {}/{}",
            policy_name(&v["selection_policy"]),
            decimal(&v["switch_threshold_percent"]),
            count(&v["reserved"]),
            count(&v["reserve_sessions"])
        );
        let _ = writeln!(
            out,
            "轮换：稳定 TTL {} 秒  允许退让 {}%  已轮换 {} 次（TTL {} 次）",
            count(&v["stable_session_ttl_secs"]),
            decimal(&v["ttl_max_degradation_percent"]),
            count(&v["rotations"]),
            count(&v["ttl_rotations"])
        );
        if v["startup_pending"] == true {
            out.push_str("提示：等待按配置顺序选择初始会话\n");
        }
        if let Some(reason) = v["ttl_waiting_reason"].as_str() {
            let _ = writeln!(out, "TTL：{reason}");
        }
    }
    let c = &v["counters"];
    out.push_str("\n业务统计（本进程累计）\n");
    table(
        &mut out,
        &[
            vec!["项目".into(), "包数".into(), "IP 字节数".into()],
            vec![
                "有效接收".into(),
                count(&c["rx_effective_packets"]),
                bytes(&c["rx_effective_bytes"]),
            ],
            vec![
                "已写入 TUN".into(),
                count(&c["rx_packets"]),
                bytes(&c["rx_bytes"]),
            ],
            vec![
                "业务发送".into(),
                count(&c["tx_packets"]),
                bytes(&c["tx_bytes"]),
            ],
        ],
    );
    let _ = writeln!(
        out,
        "  重复副本丢弃 {}  已发副本 {}",
        count(&c["duplicates"]),
        count(&c["tx_copies"])
    );
    out.push_str("  有效接收＝校验、去重后成功入队；业务发送＝至少一条路径成功入队。\n");
    if v["fec"].as_u64().unwrap_or(0) > 0 {
        let _ = writeln!(
            out,
            "  FEC{} XOR(4+1) / 5 ms：校验发送 {}  收到 {}  恢复 {}  未恢复过期组 {}  校验队列丢弃 {}",
            count(&v["fec"]),
            count(&c["fec_tx_packets"]),
            count(&c["fec_rx_packets"]),
            count(&c["fec_recovered_packets"]),
            count(&v["fec_expired_groups"]),
            count(&c["fec_queue_drops"])
        );
    }
    out.push_str("\n路径（激活优先；计数从各会话建立起累计）\n");
    let mut paths: Vec<_> = v["paths"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    paths.sort_by_key(|p| {
        (
            match p["state"].as_str() {
                Some("active") => 0,
                Some("standby") if p["reserved"] == true => 1,
                Some("standby") => 2,
                Some("probing") => 3,
                _ => 4,
            },
            text(&p["exclusive_group"]),
            p["slot"].as_u64().unwrap_or(u64::MAX),
            text(&p["id"]),
        )
    });
    if paths.is_empty() {
        out.push_str("  暂无已建立会话\n");
    }
    for (index, p) in paths.into_iter().enumerate() {
        let role = role_name(&p["selection_role"]);
        let marker = if p["retiring"] == true {
            " · 等待交接"
        } else if p["reserved"] == true {
            " · 预留"
        } else {
            ""
        };
        let group = p["exclusive_group"]
            .as_str()
            .map(|s| format!(" · {s}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {:02} [{}{}]{}{}  RTT {} ms  有效 {}  重复 {}",
            index + 1,
            state_name(&p["state"]),
            if role.is_empty() {
                String::new()
            } else {
                format!("/{role}")
            },
            group,
            marker,
            decimal(&p["probe_rtt_ms"]),
            count(&p["rx_effective_packets"]),
            count(&p["rx_duplicates"])
        );
        let _ = writeln!(out, "     {} → {}", text(&p["local"]), text(&p["remote"]));
        if verbose {
            let _ = writeln!(
                out,
                "     ID {}  槽位 {}  抖动 {} ms  评分 {}  探测超时 {}/{}",
                text(&p["id"]),
                count(&p["slot"]),
                decimal(&p["jitter_ms"]),
                decimal(&p["score"]),
                count(&p["probe_timeouts"]),
                count(&p["probes"])
            );
            let _ = writeln!(
                out,
                "     已连接 {}  备用 {}  TTL 剩余 {} 秒  已确认版本 {}",
                duration(&p["connected_seconds"]),
                duration(&p["standby_seconds"]),
                count(&p["ttl_remaining_secs"]),
                count(&p["acked_generation"])
            );
            let _ = writeln!(
                out,
                "     副本收/发 {}/{}  接收有效字节 {}  副本队列丢弃 {}",
                count(&p["rx_copies"]),
                count(&p["tx_copies"]),
                bytes(&p["rx_effective_bytes"]),
                count(&p["queue_drops"])
            );
            let _ = writeln!(
                out,
                "     QUIC RTT {} ms  QUIC 丢包/发送 {}/{}  收/发 {:.1}/{:.1} kbit/s",
                decimal(&p["quic_rtt_ms"]),
                count(&p["quic_lost_packets"]),
                count(&p["quic_sent_packets"]),
                p["rx_bps"].as_f64().unwrap_or(0.0) / 1000.0,
                p["tx_bps"].as_f64().unwrap_or(0.0) / 1000.0
            );
        }
    }
    out.push_str("\n异常计数（本进程累计；TUN 内核计数属于当前接口）\n");
    let _ = writeln!(
        out,
        "  接收入队失败 {}  发送副本队列满 {}  无可用路径 {}",
        count(&c["rx_queue_drops"]),
        count(&c["queue_drops"]),
        count(&c["disconnected"])
    );
    let _ = writeln!(
        out,
        "  无效报文 {}  过旧副本 {}  发送错误 {}  副本不足 {}",
        count(&c["invalid"]),
        count(&c["too_old"]),
        count(&c["send_errors"]),
        count(&c["partial_replication"])
    );
    let _ = writeln!(
        out,
        "  TUN 内核丢弃：TX {} / RX {}",
        count(&v["tun_tx_dropped"]),
        count(&v["tun_rx_dropped"])
    );
    if verbose {
        let _ = writeln!(
            out,
            "  连接失败累计 {}  激活变更 {} 次  控制版本 {}",
            count(&v["connection_failures"]),
            count(&v["switches"]),
            count(&v["selection_generation"])
        );
        if let Some(error) = v["latest_error"].as_str() {
            let _ = writeln!(out, "  最近连接错误（可能已恢复）：{error}");
        }
    } else {
        out.push_str("\n使用 --verbose 展开路径详情；--json 输出完整结构化数据。\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn status_separates_effective_delivery_and_duplicates_and_sorts_active_first() {
        let v = json!({"mode":"server","tun":"qw0","uptime_seconds":3661,"connected":2,"healthy":2,"active":1,"max_sessions":2,"active_sessions":1,"degraded":false,"reason":"正常",
            "counters":{"rx_effective_packets":1234,"rx_effective_bytes":2048,"rx_packets":1200,"rx_bytes":2000,"tx_packets":10,"tx_bytes":200,"duplicates":1230,"tx_copies":20},
            "paths":[{"id":"standby-id","state":"standby","remote":"192.0.2.2:4000","local":"192.0.2.1:4433","probe_rtt_ms":20.0,"rx_effective_packets":0,"rx_duplicates":1230},
                {"id":"active-id","state":"active","remote":"[2001:db8::1234]:65535","local":"[2001:db8::1]:4433","probe_rtt_ms":10.0,"rx_effective_packets":1234,"rx_duplicates":0}]});
        let out = render(&v, false);
        assert!(out.contains("1,234") && out.contains("1,200") && out.contains("2.00 KiB"));
        assert!(out.contains("01:01:01") && out.contains("[2001:db8::1234]:65535"));
        assert!(out.find("[激活]").unwrap() < out.find("[备用]").unwrap());
        assert!(!out.contains("选路：") && !out.contains("active-id") && !out.contains("null"));
        assert!(render(&v, true).contains("active-id"));
        // 老服务缺少新增字段时显示未知，不把已写 TUN 或副本计数冒充有效包。
        let legacy = render(
            &json!({"mode":"server","counters":{"rx_packets":123}}),
            false,
        );
        assert!(legacy.contains("有效接收    -"));
    }
}
