use std::{fs::OpenOptions, io::Write, path::Path, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rustls::{pki_types::PrivatePkcs8KeyDer, sign::CertifiedKey};

const PRIVATE_PREFIX: &str = "quicwire-private-v1:";
const PUBLIC_PREFIX: &str = "quicwire-public-v1:";
// RFC 8410: Ed25519 SubjectPublicKeyInfo，后接 32 字节公钥。
const SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn parse(text: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(
                text.trim()
                    .strip_prefix(PUBLIC_PREFIX)
                    .context("公钥必须使用 quicwire-public-v1 格式")?,
            )
            .context("公钥 Base64 无效")?;
        Ok(Self(bytes.try_into().map_err(|_| {
            anyhow::anyhow!("Ed25519 公钥必须是 32 字节")
        })?))
    }

    pub fn encode(&self) -> String {
        format!("{PUBLIC_PREFIX}{}", STANDARD.encode(self.0))
    }

    pub fn spki(&self) -> Vec<u8> {
        [SPKI_PREFIX, self.0.as_slice()].concat()
    }
}

pub struct Identity {
    pub public: PublicKey,
    pub certified_key: Arc<CertifiedKey>,
}

impl Identity {
    pub fn generate() -> Result<(Self, String)> {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("无法生成 Ed25519 密钥"))?;
        let identity = Self::from_der(document.as_ref())?;
        Ok((
            identity,
            format!("{PRIVATE_PREFIX}{}\n", STANDARD.encode(document.as_ref())),
        ))
    }

    fn from_der(der: &[u8]) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8(der)
            .map_err(|_| anyhow::anyhow!("私钥不是有效的 Ed25519 PKCS#8 密钥"))?;
        let public = PublicKey(
            key.public_key()
                .as_ref()
                .try_into()
                .expect("Ed25519 key length"),
        );
        let signing = rustls::crypto::ring::sign::any_supported_type(
            &PrivatePkcs8KeyDer::from(der.to_vec()).into(),
        )?;
        // X.509 只是现有身份公钥的 TLS 容器；信任仍来自预配置 SPKI。
        let certificate_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(der.to_vec()),
            &rcgen::PKCS_ED25519,
        )?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "peer");
        let certificate = params.self_signed(&certificate_key)?;
        let certified_key = Arc::new(CertifiedKey::new(vec![certificate.der().clone()], signing));
        Ok(Self {
            public,
            certified_key,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).context("无法读取私钥文件")?;
        ensure!(
            metadata.file_type().is_file(),
            "私钥必须是普通文件，不接受符号链接"
        );
        ensure!(metadata.len() <= 4096, "私钥文件过大");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "私钥权限过宽，请执行 chmod 600"
            );
        }
        let text = std::fs::read_to_string(path).context("读取私钥失败")?;
        let encoded = text
            .trim()
            .strip_prefix(PRIVATE_PREFIX)
            .context("私钥文件格式无效")?;
        let der = STANDARD.decode(encoded).context("私钥 Base64 无效")?;
        Self::from_der(&der)
    }

    pub fn generate_file(path: &Path) -> Result<PublicKey> {
        let (identity, text) = Self::generate()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .context("无法新建私钥文件（不会覆盖已有文件）")?;
        if let Err(error) = file
            .write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
        {
            bail!("写入私钥失败，请检查并处理不完整文件：{error}");
        }
        Ok(identity.public)
    }
}
