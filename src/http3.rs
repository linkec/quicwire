//! 单 peer、静态 IPv4 地址的 HTTP/3 CONNECT-IP 隧道。
use std::{future::poll_fn, task::Poll};

use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes, BytesMut};
use h3::ConnectionState;
use http::{HeaderMap, Request, Response, StatusCode};
use quinn::Connection;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use crate::{
    config::{Config, Mode},
    transport::HANDSHAKE_TIMEOUT,
};

const PATH: &str = "/.well-known/masque/ip/*/*/";
const MAX_CAPSULE: usize = 65536;

#[derive(Clone)]
pub struct ActiveSession {
    pub connection: Connection,
    pub request_id: u64,
}

impl ActiveSession {
    pub fn encode(&self, packet: &[u8]) -> Bytes {
        let mut data = Vec::with_capacity(packet.len() + 9);
        put_varint(self.request_id / 4, &mut data);
        data.push(0); // RFC 9484 IP Context ID
        data.extend_from_slice(packet);
        data.into()
    }
    pub fn decode<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let (request, n) = varint(data)?;
        let (context, m) = varint(&data[n..])?;
        (request == self.request_id / 4 && context == 0).then_some(&data[n + m..])
    }
}

pub struct Session {
    pub active: ActiveSession,
    capsules: mpsc::Receiver<Bytes>,
    driver: JoinHandle<()>,
}

impl Session {
    pub async fn read_datagram(&mut self) -> Result<Bytes> {
        tokio::select! {
            result = self.active.connection.read_datagram() => Ok(result?),
            packet = self.capsules.recv() => packet.context("HTTP/3 控制流已关闭"),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
        if self.active.connection.close_reason().is_none() {
            self.active.connection.close(0u32.into(), b"session ended");
        }
    }
}

pub async fn negotiate(connection: &Connection, config: &Config) -> Result<Session> {
    negotiate_mode(connection, config, false).await
}
pub async fn negotiate_multipath(connection: &Connection, config: &Config) -> Result<Session> {
    negotiate_mode(connection, config, true).await
}
async fn negotiate_mode(
    connection: &Connection,
    config: &Config,
    multipath: bool,
) -> Result<Session> {
    ensure!(
        connection.max_datagram_size().unwrap_or(0) >= usize::from(config.mtu) + 32,
        "对端 DATAGRAM 能力不足"
    );
    let (ready_tx, ready_rx) = oneshot::channel();
    let (packet_tx, packet_rx) = mpsc::channel(64);
    let conn = connection.clone();
    let cfg = config.clone();
    let driver = tokio::spawn(async move {
        let result = match cfg.mode {
            Mode::Client => client(&conn, &cfg, ready_tx, packet_tx, multipath).await,
            Mode::Server => server(&conn, &cfg, ready_tx, packet_tx, multipath).await,
        };
        if let Err(error) = result {
            eprintln!("HTTP/3 会话结束：{error:#}");
        }
        if conn.close_reason().is_none() {
            conn.close(0x100u32.into(), b"HTTP session ended");
        }
    });
    // 提前构造守卫，外层取消协商也会释放驱动任务与连接。
    let mut session = Session {
        active: ActiveSession {
            connection: connection.clone(),
            request_id: 0,
        },
        capsules: packet_rx,
        driver,
    };
    session.active.request_id = tokio::time::timeout(HANDSHAKE_TIMEOUT, ready_rx)
        .await
        .context("HTTP/3 隧道协商超时")?
        .context("HTTP/3 隧道协商失败")?;
    Ok(session)
}

fn fec_protocol(config: &Config) -> String {
    if config.fec_repair_shards == 1 {
        format!("xor4-v2-primary-backup-{}", config.fec)
    } else {
        format!(
            "cauchy4-v1-primary-backup-{}-{}",
            config.fec_repair_shards, config.fec
        )
    }
}
fn headers(config: &Config, multipath: bool) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("capsule-protocol", "?1".parse().unwrap());
    h.insert(
        "x-tunnel-address",
        config.tun_address.addr().to_string().parse().unwrap(),
    );
    h.insert(
        "x-tunnel-peer",
        config.peer_address.to_string().parse().unwrap(),
    );
    h.insert("x-tunnel-mtu", config.mtu.to_string().parse().unwrap());
    if multipath {
        h.insert("x-tunnel-version", "3".parse().unwrap());
    }
    if config.fec > 0 {
        h.insert("x-tunnel-fec", fec_protocol(config).parse().unwrap());
    }
    h
}

fn check_headers(h: &HeaderMap, config: &Config, multipath: bool) -> Result<()> {
    ensure!(
        if multipath {
            h.get_all("x-tunnel-version").iter().count() == 1
                && h.get("x-tunnel-version").is_some_and(|v| v == "3")
        } else {
            !h.contains_key("x-tunnel-version")
        },
        "隧道版本不匹配"
    );
    ensure!(
        if config.fec > 0 {
            h.get_all("x-tunnel-fec").iter().count() == 1
                && h.get("x-tunnel-fec")
                    .is_some_and(|v| v == fec_protocol(config).as_str())
        } else {
            !h.contains_key("x-tunnel-fec")
        },
        "FEC 配置不匹配，必须两端一致"
    );
    let expected = [
        ("capsule-protocol", "?1".to_string()),
        ("x-tunnel-address", config.peer_address.to_string()),
        ("x-tunnel-peer", config.tun_address.addr().to_string()),
        ("x-tunnel-mtu", config.mtu.to_string()),
    ];
    for (name, value) in expected {
        ensure!(
            h.get_all(name).iter().count() == 1
                && h.get(name).and_then(|v| v.to_str().ok()) == Some(value.as_str()),
            "隧道参数不匹配：{name}"
        );
    }
    Ok(())
}

async fn client(
    connection: &Connection,
    config: &Config,
    ready: oneshot::Sender<u64>,
    packets: mpsc::Sender<Bytes>,
    multipath: bool,
) -> Result<()> {
    let (mut driver, mut sender) = h3::client::builder()
        .enable_datagram(true)
        .max_field_section_size(8192)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await?;
    // CONNECT 必须等待服务端声明支持，不能用固定 sleep 代替 SETTINGS。
    poll_fn(|cx| {
        if let Poll::Ready(error) = driver.poll_close(cx) {
            return Poll::Ready(Err(anyhow::anyhow!(error)));
        }
        match sender.peer_datagram_settings() {
            Some((true, true)) => Poll::Ready(Ok(())),
            Some(_) => Poll::Ready(Err(anyhow::anyhow!(
                "对端未启用 HTTP Datagram / Extended CONNECT"
            ))),
            None => Poll::Pending,
        }
    })
    .await?;
    let mut request = Request::builder()
        .method("CONNECT")
        .uri(format!("https://{}{PATH}", config.http_authority()?))
        .extension(if multipath {
            h3::ext::Protocol::QUICWIRE
        } else {
            h3::ext::Protocol::CONNECT_IP
        })
        .body(())?;
    *request.headers_mut() = headers(config, multipath);
    let mut stream = tokio::select! {
        result = sender.send_request(request) => result?,
        error = driver.wait_idle() => bail!("HTTP/3 连接关闭：{error}"),
    };
    let response = tokio::select! {
        result = stream.recv_response() => result?,
        error = driver.wait_idle() => bail!("HTTP/3 连接关闭：{error}"),
    };
    ensure!(
        response.status().is_success(),
        "CONNECT-IP 被拒绝：{}",
        response.status()
    );
    check_headers(response.headers(), config, multipath)?;
    let id = stream.id().into_inner();
    ready.send(id).map_err(|_| anyhow::anyhow!("隧道已取消"))?;
    let active = ActiveSession {
        connection: connection.clone(),
        request_id: id,
    };
    let mut capsules = Capsules::default();
    loop {
        tokio::select! {
            error = driver.wait_idle() => bail!("HTTP/3 连接关闭：{error}"),
            data = stream.recv_data() => {
                let mut data = data?.context("CONNECT-IP 响应已结束")?;
                capsules.append(data.copy_to_bytes(data.remaining()))?;
                while let Some((kind, payload)) = capsules.next()? {
                    handle_capsule(kind, payload, &active, config, &packets, multipath).await?;
                }
            }
        }
    }
}

async fn server(
    connection: &Connection,
    config: &Config,
    ready: oneshot::Sender<u64>,
    packets: mpsc::Sender<Bytes>,
    multipath: bool,
) -> Result<()> {
    let mut driver = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_field_section_size(8192)
        .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await?;
    let resolver = driver.accept().await?.context("对端未发送 HTTP 请求")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    let valid = request.method() == http::Method::CONNECT
        && request.extensions().get::<h3::ext::Protocol>()
            == Some(&if multipath {
                h3::ext::Protocol::QUICWIRE
            } else {
                h3::ext::Protocol::CONNECT_IP
            })
        && request.uri().scheme_str() == Some("https")
        && request.uri().path_and_query().map(|p| p.as_str()) == Some(PATH)
        && request.uri().authority().is_some();
    if !valid || check_headers(request.headers(), config, multipath).is_err() {
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        bail!("无效的 CONNECT-IP 请求或隧道配置不匹配");
    }
    // 请求流可能比控制流先到；继续驱动控制流直到 SETTINGS 到达。
    poll_fn(|cx| {
        match driver.poll_accept_request_stream(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(anyhow::anyhow!(e))),
            Poll::Ready(Ok(_)) => {
                return Poll::Ready(Err(anyhow::anyhow!("协商时收到额外请求或连接关闭")));
            }
            Poll::Pending => (),
        }
        match driver.peer_datagram_settings() {
            Some((_, true)) => Poll::Ready(Ok(())),
            Some(_) => Poll::Ready(Err(anyhow::anyhow!("对端未启用 HTTP Datagram"))),
            None => Poll::Pending,
        }
    })
    .await?;
    let mut response = Response::builder().status(StatusCode::OK).body(())?;
    *response.headers_mut() = headers(config, multipath);
    stream.send_response(response).await?;
    let id = stream.id().into_inner();
    ready.send(id).map_err(|_| anyhow::anyhow!("隧道已取消"))?;
    let active = ActiveSession {
        connection: connection.clone(),
        request_id: id,
    };
    let mut capsules = Capsules::default();
    loop {
        tokio::select! {
            next = driver.accept() => {
                let resolver = next?.context("HTTP/3 连接已关闭")?;
                let (_, mut extra) = resolver.resolve_request().await?;
                extra.send_response(Response::builder().status(StatusCode::NOT_FOUND).body(())?).await?;
                extra.finish().await?;
            }
            data = stream.recv_data() => {
                let mut data = data?.context("CONNECT-IP 请求已结束")?;
                capsules.append(data.copy_to_bytes(data.remaining()))?;
                while let Some((kind, payload)) = capsules.next()? {
                    handle_capsule(kind, payload, &active, config, &packets, multipath).await?;
                }
            }
        }
    }
}

#[derive(Default)]
struct Capsules {
    pending: BytesMut,
}
impl Capsules {
    fn append(&mut self, data: Bytes) -> Result<()> {
        ensure!(
            self.pending.len() + data.len() <= MAX_CAPSULE + 16,
            "Capsule 缓冲超过限制"
        );
        self.pending.extend_from_slice(&data);
        Ok(())
    }
    fn next(&mut self) -> Result<Option<(u64, Bytes)>> {
        let Some((kind, n)) = varint(&self.pending) else {
            return Ok(None);
        };
        let Some((len, m)) = varint(&self.pending[n..]) else {
            return Ok(None);
        };
        ensure!(len <= MAX_CAPSULE as u64, "Capsule 长度超过限制");
        let end = n + m + len as usize;
        if self.pending.len() < end {
            return Ok(None);
        }
        let mut frame = self.pending.split_to(end).freeze();
        frame.advance(n + m);
        Ok(Some((kind, frame)))
    }
}

async fn handle_capsule(
    kind: u64,
    payload: Bytes,
    active: &ActiveSession,
    config: &Config,
    packets: &mpsc::Sender<Bytes>,
    multipath: bool,
) -> Result<()> {
    match kind {
        0 => {
            let (context, offset) = varint(&payload).context("DATAGRAM Capsule 缺少 Context ID")?;
            if context == 0
                && payload.len() - offset
                    <= usize::from(config.mtu) + if multipath { 32 } else { 0 }
            {
                packets
                    .send(active.encode(&payload[offset..]))
                    .await
                    .context("隧道已关闭")?;
            }
        }
        // 静态地址由带外配置与 HTTP 头双向确认；拒绝在已建立会话中改变路由或地址。
        1..=3 => bail!("静态地址模式不接受动态地址或路由 Capsule"),
        _ => (), // RFC 9297: 忽略未知 Capsule，保留扩展能力。
    }
    Ok(())
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return None;
    }
    let value = bytes[1..length]
        .iter()
        .fold(u64::from(first & 0x3f), |v, b| (v << 8) | u64::from(*b));
    Some((value, length))
}
fn put_varint(value: u64, output: &mut Vec<u8>) {
    let (length, flag) = if value < 64 {
        (1, 0)
    } else if value < 16384 {
        (2, 0x40)
    } else if value < (1 << 30) {
        (4, 0x80)
    } else {
        (8, 0xc0)
    };
    let bytes = value.to_be_bytes();
    let start = output.len();
    output.extend_from_slice(&bytes[8 - length..]);
    output[start] |= flag;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn variable_integer_and_fragmented_capsules() {
        for value in [
            0,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut b = Vec::new();
            put_varint(value, &mut b);
            assert_eq!(varint(&b), Some((value, b.len())));
        }
        let mut decoder = Capsules::default();
        decoder.append(Bytes::from_static(&[0, 3, 0])).unwrap();
        assert!(decoder.next().unwrap().is_none());
        decoder.append(Bytes::from_static(&[1, 2, 23, 0])).unwrap();
        assert_eq!(
            decoder.next().unwrap(),
            Some((0, Bytes::from_static(&[0, 1, 2])))
        );
        assert_eq!(decoder.next().unwrap(), Some((23, Bytes::new())));
        let mut huge = vec![0];
        put_varint(65537, &mut huge);
        decoder.append(huge.into()).unwrap();
        assert!(decoder.next().is_err());
    }
}
