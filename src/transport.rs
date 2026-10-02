use std::{sync::Arc, time::Duration};

use anyhow::Result;
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};

use crate::identity::{Identity, PublicKey};

pub const ALPN: &[u8] = b"h3";
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(6);

/// 从 X.509 容器提取 Ed25519 SPKI 精确固定；CertificateVerify 验证私钥持有。
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
        let (rest, certificate) = x509_parser::parse_x509_certificate(presented.as_ref())
            .map_err(|_| Error::General("对端证书格式无效".into()))?;
        if !rest.is_empty()
            || certificate.public_key().raw != self.spki
            || !intermediates.is_empty()
        {
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
        rustls::crypto::verify_tls13_signature(
            message,
            key,
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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn transport() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(32_u8.into());
    config.max_concurrent_uni_streams(16_u8.into());
    config.stream_receive_window((64 * 1024_u32).into());
    config.receive_window((256 * 1024_u32).into());
    // 接收突发与处理速度解耦；发送端保持小缓冲并采用背压。
    config.datagram_receive_buffer_size(Some(1024 * 1024));
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
    .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
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
    .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
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

pub use crate::http3::negotiate;
