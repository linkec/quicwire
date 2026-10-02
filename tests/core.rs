use quicwire::{
    config::{Config, Mode},
    identity::{Identity, PublicKey},
    packet::valid_ipv4,
    transport,
};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

fn config(mode: Mode, peer: &PublicKey) -> Config {
    let (local, remote) = if mode == Mode::Server { (1, 2) } else { (2, 1) };
    Config {
        mode,
        bind: "127.0.0.1:4433".parse().unwrap(),
        endpoint: (mode == Mode::Client).then(|| "127.0.0.1:4433".parse().unwrap()),
        server_name: None,
        private_key_file: "unused.key".into(),
        peer_public_key: peer.encode(),
        tun_name: "qw0".into(),
        tun_address: format!("10.77.0.{local}/30").parse().unwrap(),
        peer_address: format!("10.77.0.{remote}").parse().unwrap(),
        mtu: 1100,
        tun_offload: true,
    }
}

async fn endpoints(
    server_id: &Identity,
    client_id: &Identity,
    allowed: &PublicKey,
    pinned: &PublicKey,
) -> (
    quinn::Endpoint,
    quinn::Endpoint,
    anyhow::Result<quinn::Connection>,
    anyhow::Result<quinn::Connection>,
) {
    let server = quinn::Endpoint::server(
        transport::server_config(server_id, allowed).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(transport::client_config(client_id, pinned).unwrap());
    let connecting = client
        .connect(server.local_addr().unwrap(), "quicwire")
        .unwrap();
    let (server_conn, client_conn) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async { server.accept().await.unwrap().await.map_err(Into::into) },
            async { connecting.await.map_err(Into::into) }
        )
    })
    .await
    .expect("握手必须在超时前成功或明确拒绝");
    (server, client, server_conn, client_conn)
}

#[tokio::test]
async fn mutual_pinned_public_keys_h3_and_bidirectional_datagrams() {
    let (server_id, _) = Identity::generate().unwrap();
    let (client_id, _) = Identity::generate().unwrap();
    let (_server, _client, server_conn, client_conn) =
        endpoints(&server_id, &client_id, &client_id.public, &server_id.public).await;
    let server_conn = server_conn.unwrap();
    let client_conn = client_conn.unwrap();
    let server_cfg = config(Mode::Server, &client_id.public);
    let client_cfg = config(Mode::Client, &server_id.public);
    let (s, c) = tokio::join!(
        transport::negotiate(&server_conn, &server_cfg),
        transport::negotiate(&client_conn, &client_cfg)
    );
    let mut server_session = s.unwrap();
    let mut client_session = c.unwrap();
    let handshake = client_conn
        .handshake_data()
        .unwrap()
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .unwrap();
    assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));
    let data = vec![0x5a; 1100];
    client_conn
        .send_datagram(client_session.active.encode(&data))
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), server_session.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_session.active.decode(&got).unwrap(), data);
    assert!(server_session.active.decode(&[1, 0, 0x45]).is_none());
    assert!(server_session.active.decode(&[0, 1, 0x45]).is_none());
    assert!(server_session.active.decode(&[0]).is_none());
    server_conn
        .send_datagram(server_session.active.encode(b"return-path"))
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), client_session.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client_session.active.decode(&received).unwrap(),
        b"return-path"
    );
    drop(server_session);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client_conn.closed())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn unknown_client_key_is_rejected() {
    let (server_id, _) = Identity::generate().unwrap();
    let (allowed, _) = Identity::generate().unwrap();
    let (attacker, _) = Identity::generate().unwrap();
    let (_s, _c, server_conn, _client_conn) =
        endpoints(&server_id, &attacker, &allowed.public, &server_id.public).await;
    assert!(server_conn.is_err(), "未知客户端不得通过双向 TLS 认证");
}

#[tokio::test]
async fn wrong_server_key_is_rejected() {
    let (server_id, _) = Identity::generate().unwrap();
    let (client_id, _) = Identity::generate().unwrap();
    let (wrong, _) = Identity::generate().unwrap();
    let (_s, _c, _server_conn, client_conn) =
        endpoints(&server_id, &client_id, &client_id.public, &wrong.public).await;
    assert!(client_conn.is_err(), "错误核心公钥不得通过认证");
}

#[tokio::test]
async fn copying_public_key_without_private_key_is_rejected() {
    let (server_id, _) = Identity::generate().unwrap();
    let (victim, _) = Identity::generate().unwrap();
    let (attacker, _) = Identity::generate().unwrap();
    let forged = Identity {
        public: victim.public.clone(),
        certified_key: Arc::new(rustls::sign::CertifiedKey::new(
            victim.certified_key.cert.clone(),
            attacker.certified_key.key.clone(),
        )),
    };
    let (_s, _c, server_conn, _client_conn) =
        endpoints(&server_id, &forged, &victim.public, &server_id.public).await;
    assert!(
        server_conn.is_err(),
        "必须验证 CertificateVerify，不能只比较公钥"
    );
}

#[tokio::test]
async fn mismatched_tunnel_config_is_rejected_after_tls() {
    let (server_id, _) = Identity::generate().unwrap();
    let (client_id, _) = Identity::generate().unwrap();
    let (_s, _c, server_conn, client_conn) =
        endpoints(&server_id, &client_id, &client_id.public, &server_id.public).await;
    let server_conn = server_conn.unwrap();
    let client_conn = client_conn.unwrap();
    let server_cfg = config(Mode::Server, &client_id.public);
    let mut client_cfg = config(Mode::Client, &server_id.public);
    client_cfg.mtu = 1000;
    let (s, c) = tokio::join!(
        transport::negotiate(&server_conn, &server_cfg),
        transport::negotiate(&client_conn, &client_cfg)
    );
    assert!(s.is_err());
    assert!(c.is_err());
}

#[tokio::test]
async fn non_http3_control_stream_is_rejected() {
    let (server_id, _) = Identity::generate().unwrap();
    let (client_id, _) = Identity::generate().unwrap();
    let (_s, _c, server_conn, client_conn) =
        endpoints(&server_id, &client_id, &client_id.public, &server_id.public).await;
    let server_conn = server_conn.unwrap();
    let client_conn = client_conn.unwrap();
    let cfg = config(Mode::Server, &client_id.public);
    let (result, ()) = tokio::join!(transport::negotiate(&server_conn, &cfg), async {
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        send.write_all(&[0; 17]).await.unwrap();
        send.finish().unwrap();
    });
    assert!(result.is_err());
}

#[test]
fn key_file_roundtrip_and_no_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.key");
    let public = Identity::generate_file(&path).unwrap();
    assert_eq!(
        Identity::load(&path).unwrap().public.encode(),
        public.encode()
    );
    assert_eq!(
        PublicKey::parse(&public.encode()).unwrap().encode(),
        public.encode()
    );
    assert!(Identity::generate_file(&path).is_err());
    assert_eq!(
        Identity::load(&path).unwrap().public.encode(),
        public.encode()
    );
    assert!(PublicKey::parse("quicwire-public-v1:AA==").is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Identity::load(&path).is_err());
    }
}

#[test]
fn reject_unsafe_config() {
    let (peer, _) = Identity::generate().unwrap();
    let base = config(Mode::Client, &peer.public);
    base.validate().unwrap();
    let mut c = base.clone();
    c.endpoint = Some("10.77.0.1:4433".parse().unwrap());
    assert!(c.validate().is_err());
    let mut c = base.clone();
    c.mtu = 1500;
    assert!(c.validate().is_err());
    let mut c = base.clone();
    c.peer_address = c.tun_address.addr();
    assert!(c.validate().is_err());
    let mut c = base.clone();
    c.tun_name = "../../x".into();
    assert!(c.validate().is_err());
    let mut c = base;
    c.endpoint = None;
    assert!(c.validate().is_err());
}

#[test]
fn packet_validation_rejects_spoofing_truncation_and_ipv6() {
    let source: Ipv4Addr = "10.77.0.1".parse().unwrap();
    let dest: Ipv4Addr = "10.77.0.2".parse().unwrap();
    let mut packet = vec![0; 64];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&64_u16.to_be_bytes());
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&dest.octets());
    assert!(valid_ipv4(&packet, source, dest, 1100));
    assert!(!valid_ipv4(&packet, dest, source, 1100));
    assert!(!valid_ipv4(&packet[..63], source, dest, 1100));
    assert!(!valid_ipv4(&packet, source, dest, 60));
    packet[0] = 0x65;
    assert!(!valid_ipv4(&packet, source, dest, 1100));
    packet[0] = 0x44;
    assert!(!valid_ipv4(&packet, source, dest, 1100));
    assert!(!valid_ipv4(&[], source, dest, 1100));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn data_plane_rejects_invalid_mtu_before_creating_devices() {
    let (identity, _) = Identity::generate().unwrap();
    let (peer, _) = Identity::generate().unwrap();
    let mut cfg = config(Mode::Client, &peer.public);
    cfg.mtu = 100;
    let error = quicwire::tunnel::run(cfg, identity).await.unwrap_err();
    assert!(error.to_string().contains("MTU"));
}

#[tokio::test]
async fn cancelling_h3_negotiation_closes_connection() {
    let (server_id, _) = Identity::generate().unwrap();
    let (client_id, _) = Identity::generate().unwrap();
    let (_s, _c, server_conn, client_conn) =
        endpoints(&server_id, &client_id, &client_id.public, &server_id.public).await;
    let server_conn = server_conn.unwrap();
    let client_conn = client_conn.unwrap();
    let cfg = config(Mode::Client, &server_id.public);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(30),
            transport::negotiate(&client_conn, &cfg)
        )
        .await
        .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server_conn.closed())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn http3_capsule_fallback_and_request_lifetime() {
    use bytes::Bytes;
    let (server_id, _) = Identity::generate().unwrap();
    let (client_id, _) = Identity::generate().unwrap();
    let (_s, _c, server_conn, client_conn) =
        endpoints(&server_id, &client_id, &client_id.public, &server_id.public).await;
    let server_conn = server_conn.unwrap();
    let client_conn = client_conn.unwrap();
    let cfg = config(Mode::Server, &client_id.public);
    let negotiation = tokio::spawn(async move { transport::negotiate(&server_conn, &cfg).await });
    let (mut driver, mut sender) = h3::client::builder()
        .enable_datagram(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(client_conn.clone()))
        .await
        .unwrap();
    use h3::ConnectionState;
    std::future::poll_fn(|cx| {
        assert!(driver.poll_close(cx).is_pending());
        match sender.peer_datagram_settings() {
            Some((true, true)) => std::task::Poll::Ready(()),
            _ => std::task::Poll::Pending,
        }
    })
    .await;
    let drive = tokio::spawn(async move { driver.wait_idle().await });
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://127.0.0.1/.well-known/masque/ip/*/*/")
        .extension(h3::ext::Protocol::CONNECT_IP)
        .header("capsule-protocol", "?1")
        .header("x-tunnel-address", "10.77.0.2")
        .header("x-tunnel-peer", "10.77.0.1")
        .header("x-tunnel-mtu", "1100")
        .body(())
        .unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), 200);
    let mut session = negotiation.await.unwrap().unwrap();
    // 未知 Capsule、未知 Context 忽略；合法 Capsule 可以跨多个 DATA 帧。
    stream
        .send_data(Bytes::from_static(&[23, 0, 0, 2, 1, 7, 0, 4, 0, b'a']))
        .await
        .unwrap();
    stream.send_data(Bytes::from_static(b"bc")).await.unwrap();
    let datagram = tokio::time::timeout(Duration::from_secs(2), session.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.active.decode(&datagram), Some(b"abc".as_slice()));
    stream.finish().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client_conn.closed())
            .await
            .is_ok()
    );
    drive.abort();
}

#[tokio::test]
async fn h3_peer_without_connect_settings_is_rejected() {
    let (server_id, _) = Identity::generate().unwrap();
    let (client_id, _) = Identity::generate().unwrap();
    let (_s, _c, server_conn, client_conn) =
        endpoints(&server_id, &client_id, &client_id.public, &server_id.public).await;
    let server_conn = server_conn.unwrap();
    let client_conn = client_conn.unwrap();
    let mut server = h3::server::builder()
        .build::<_, bytes::Bytes>(h3_quinn::Connection::new(server_conn))
        .await
        .unwrap();
    let drive = tokio::spawn(async move { server.accept().await });
    let cfg = config(Mode::Client, &server_id.public);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            transport::negotiate(&client_conn, &cfg)
        )
        .await
        .unwrap()
        .is_err()
    );
    drive.abort();
}

#[test]
fn identity_certificate_keeps_pinned_public_key_and_optional_sni() {
    let (id, _) = Identity::generate().unwrap();
    let (rest, cert) =
        x509_parser::parse_x509_certificate(id.certified_key.cert[0].as_ref()).unwrap();
    assert!(rest.is_empty());
    assert_eq!(cert.public_key().raw, id.public.spki());
    let mut cfg = config(Mode::Client, &id.public);
    assert_eq!(cfg.tls_server_name().unwrap(), "127.0.0.1");
    cfg.server_name = Some("vpn.example.com".into());
    cfg.validate().unwrap();
    assert_eq!(cfg.tls_server_name().unwrap(), "vpn.example.com");
    assert_eq!(cfg.http_authority().unwrap(), "vpn.example.com:4433");
    cfg.server_name = Some("https://bad.example/path".into());
    assert!(cfg.validate().is_err());
}
