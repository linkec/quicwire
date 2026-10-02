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
async fn mutual_raw_public_keys_and_bidirectional_datagrams() {
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
    s.unwrap();
    c.unwrap();
    let data = vec![0x5a; 1100];
    client_conn.send_datagram(data.clone().into()).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), server_conn.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.as_ref(), data);
    server_conn
        .send_datagram(b"return-path".to_vec().into())
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client_conn.read_datagram())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"return-path"
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
            vec![rustls::pki_types::CertificateDer::from(
                victim.public.spki(),
            )],
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
async fn oversized_control_message_is_rejected() {
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
