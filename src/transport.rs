use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use quinn::{ClientConfig, Connection, ServerConfig, TransportConfig};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::{
        AlwaysResolvesClientRawPublicKeys,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
    server::{
        AlwaysResolvesServerRawPublicKeys,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};

use crate::{
    config::{Config, Mode},
    identity::{Identity, PublicKey},
};

pub const ALPN: &[u8] = b"quicwire/0.1";
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(6);

/// 信任配置中的 Ed25519 SPKI；私钥持有证明仍由 TLS CertificateVerify 验证。
#[derive(Debug)]
struct PinnedPeer {
    spki: Vec<u8>,
}

impl PinnedPeer {
    fn check(
        &self,
        presented: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), Error> {
        if presented.as_ref() != self.spki || !intermediates.is_empty() {
            return Err(Error::General("对端公钥不在授权配置中".into()));
        }
        Ok(())
    }

    fn signature(
        &self,
        message: &[u8],
        key: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if signature.scheme != SignatureScheme::ED25519 {
            return Err(Error::General("仅接受 Ed25519 身份签名".into()));
        }
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(key.as_ref()),
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
}

impl ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("不支持 TLS 1.2".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PinnedPeer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.check(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("不支持 TLS 1.2".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn transport() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(1_u8.into());
    config.max_concurrent_uni_streams(0_u8.into());
    config.stream_receive_window(4096_u32.into());
    config.receive_window(8192_u32.into());
    config.datagram_receive_buffer_size(Some(256 * 1024));
    config.datagram_send_buffer_size(64 * 1024);
    config.keep_alive_interval(Some(Duration::from_secs(2)));
    config.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("固定超时有效")));
    // 固定外层 1200，保证 IPv4 TUN <=1100 的包在握手后即可传输。
    config.initial_mtu(1200);
    config.min_mtu(1200);
    config.mtu_discovery_config(None);
    Arc::new(config)
}

pub fn server_config(identity: &Identity, peer: &PublicKey) -> Result<ServerConfig> {
    let verifier = Arc::new(PinnedPeer { spki: peer.spki() });
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_client_cert_verifier(verifier)
    .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
        identity.certified_key.clone(),
    )));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    let mut config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    config.max_incoming(16);
    Ok(config)
}

pub fn client_config(identity: &Identity, peer: &PublicKey) -> Result<ClientConfig> {
    let verifier = Arc::new(PinnedPeer { spki: peer.spki() });
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
        identity.certified_key.clone(),
    )));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    Ok(config)
}

fn hello(config: &Config) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(b"QW01");
    bytes[4..8].copy_from_slice(&config.tun_address.addr().octets());
    bytes[8..12].copy_from_slice(&config.peer_address.octets());
    bytes[12..14].copy_from_slice(&config.mtu.to_be_bytes());
    bytes
}

fn check_hello(bytes: &[u8], config: &Config) -> Result<()> {
    ensure!(
        bytes.len() == 16 && &bytes[..4] == b"QW01",
        "隧道握手格式或版本错误"
    );
    ensure!(
        bytes[4..8] == config.peer_address.octets()
            && bytes[8..12] == config.tun_address.addr().octets(),
        "两端隧道地址配置不匹配"
    );
    ensure!(
        bytes[12..14] == config.mtu.to_be_bytes() && bytes[14..16] == [0, 0],
        "MTU 或保留字段不匹配"
    );
    Ok(())
}

/// TLS 完成后交换固定长度握手，确认双向认证、地址与 MTU，再放行数据。
pub async fn negotiate(connection: &Connection, config: &Config) -> Result<()> {
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        ensure!(
            connection.max_datagram_size().unwrap_or(0) >= usize::from(config.mtu),
            "对端 DATAGRAM 能力不足"
        );
        let (mut send, mut receive) = match config.mode {
            Mode::Client => connection.open_bi().await?,
            Mode::Server => connection.accept_bi().await?,
        };
        if config.mode == Mode::Client {
            send.write_all(&hello(config)).await?;
            send.finish()?;
            check_hello(&receive.read_to_end(16).await?, config)?;
        } else {
            check_hello(&receive.read_to_end(16).await?, config)?;
            send.write_all(&hello(config)).await?;
            send.finish()?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("隧道握手超时")
    .and_then(|result| result);
    if result.is_err() {
        connection.close(1_u32.into(), b"invalid tunnel handshake");
    }
    result
}
