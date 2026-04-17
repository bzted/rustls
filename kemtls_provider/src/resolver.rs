use log::debug;
use rustls::NamedGroup;
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openssl::pkey::{Id, PKey};

use crate::kem_key::{HybridKemKey, PureKemKey};

#[derive(Debug)]
pub struct ServerCertResolver {
    traditional_certified_key: Option<Arc<CertifiedKey>>,
    kemtls_certified_keys: HashMap<u16, Arc<CertifiedKey>>,
}

impl ServerCertResolver {
    pub fn new(
        traditional_certified_key: Option<Arc<CertifiedKey>>,
        kemtls_certified_keys: HashMap<u16, Arc<CertifiedKey>>,
    ) -> Self {
        Self {
            traditional_certified_key,
            kemtls_certified_keys,
        }
    }

    pub fn kemtls_only(kemtls_certified_keys: HashMap<u16, Arc<CertifiedKey>>) -> Self {
        Self::new(None, kemtls_certified_keys)
    }

    pub fn load_kemtls_keys(
        traditional_certified_key: Option<Arc<CertifiedKey>>,
        keys_dir: impl Into<PathBuf>,
        selected_groups: &[NamedGroup],
        signing_key: Arc<dyn rustls::sign::SigningKey>,
        x25519_key_path: Option<PathBuf>,
    ) -> Result<Self, rustls::Error> {
        let keys_dir = keys_dir.into();
        let mut kemtls_certified_keys = HashMap::new();

        for &group in selected_groups {
            let certified_key = load_kemtls_certified_key(
                &keys_dir,
                group,
                signing_key.clone(),
                x25519_key_path.clone(),
            )?;
            kemtls_certified_keys.insert(u16::from(group), certified_key);
        }

        Ok(Self::new(traditional_certified_key, kemtls_certified_keys))
    }
}

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(
        &self,
        _client_hello: ClientHello,
        selected_kemtls_group: Option<NamedGroup>,
    ) -> Option<Arc<CertifiedKey>> {
        match selected_kemtls_group {
            Some(selected_kemtls_group) => self.kemtls_certified_keys.get(&u16::from(selected_kemtls_group)).cloned().or_else(|| {
                debug!(
                    "ServerCertResolver::resolve missing preloaded key for negotiated group {:?}",
                    selected_kemtls_group
                );
                None
            }),
            None => {
                debug!("ServerCertResolver::resolve falling back to traditional CertifiedKey");
                self.traditional_certified_key.clone()
            }
        }
    }

    fn only_raw_public_keys(&self) -> bool {
        self.traditional_certified_key.is_none()
    }
}

#[derive(Debug)]
pub struct ClientCertResolver {
    key_pair: KeyPair,
}

impl ClientCertResolver {
    pub fn new(key_pair: KeyPair) -> Self {
        Self { key_pair }
    }
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        debug!("ClientCertResolver::resolve called");
        debug!(
            "PQ key size: {} bytes, X25519 key size: {} bytes",
            self.key_pair
                .pq_public_key
                .as_ref()
                .len(),
            self.key_pair
                .x25519_public_key
                .as_ref()
                .map_or(0, |k| k.len()),
        );

        let mut cert_bytes = self
            .key_pair
            .pq_public_key
            .as_ref()
            .to_vec();

        if let Some(x25519_key) = &self.key_pair.x25519_public_key {
            cert_bytes.extend_from_slice(x25519_key);
        }

        let cert = CertificateDer::from(cert_bytes);

        let certified_key = CertifiedKey {
            cert: vec![cert],
            key: self.key_pair.private_key.clone(),
            ocsp: None,
            kem_key: self.key_pair.kem_key.clone(),
        };

        Some(Arc::new(certified_key))
    }

    fn has_certs(&self) -> bool {
        true
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct KeyPair {
    pq_public_key: oqs::kem::PublicKey,
    x25519_public_key: Option<[u8; 32]>,
    private_key: Arc<dyn rustls::sign::SigningKey>,
    kem_key: Option<Arc<dyn rustls::sign::KemKey>>,
}

impl KeyPair {
    pub fn new(
        pq_public_key: oqs::kem::PublicKey,
        x25519_public_key: Option<[u8; 32]>,
        private_key: Arc<dyn rustls::sign::SigningKey>,
        kem_key: Option<Arc<dyn rustls::sign::KemKey>>,
    ) -> Self {
        Self {
            pq_public_key,
            x25519_public_key,
            private_key,
            kem_key,
        }
    }
}

pub fn default_keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("keys")
}

pub fn supported_kemtls_groups(hybrid: bool) -> Vec<NamedGroup> {
    if hybrid {
        vec![
            NamedGroup::X25519MLKEM512,
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519MLKEM1024,
            NamedGroup::X25519BikeL1,
            NamedGroup::X25519BikeL3,
            NamedGroup::X25519BikeL5,
            NamedGroup::X25519Hqc128,
            NamedGroup::X25519Hqc192,
            NamedGroup::X25519Hqc256,
            NamedGroup::X25519NtruPrimeSntrup761,
        ]
    } else {
        vec![
            NamedGroup::MLKEM512,
            NamedGroup::MLKEM768,
            NamedGroup::MLKEM1024,
            NamedGroup::BikeL1,
            NamedGroup::BikeL3,
            NamedGroup::BikeL5,
            NamedGroup::Hqc128,
            NamedGroup::Hqc192,
            NamedGroup::Hqc256,
            NamedGroup::NtruPrimeSntrup761,
        ]
    }
}

pub fn load_client_key_pair(
    keys_dir: impl Into<PathBuf>,
    selected_kemtls_group: NamedGroup,
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    x25519_key_path: Option<PathBuf>,
) -> Result<(KeyPair, Option<[u8; 32]>, Option<[u8; 32]>), rustls::Error> {
    let keys_dir = keys_dir.into();
    let (dir_name, algorithm, hybrid) = group_info(selected_kemtls_group)?;
    let group_dir = keys_dir.join("client").join(dir_name);
    let public_key_path = group_dir.join("public_key.bin");
    let secret_key_path = group_dir.join("secret_key.bin");

    let public_key = fs::read(&public_key_path).map_err(|e| {
        rustls::Error::General(format!("failed to read {}: {e}", public_key_path.display()))
    })?;

    let secret_key = fs::read(&secret_key_path).map_err(|e| {
        rustls::Error::General(format!("failed to read {}: {e}", secret_key_path.display()))
    })?;

    let kem = oqs::kem::Kem::new(algorithm)
        .map_err(|_| rustls::Error::General("Failed to create KEM instance".into()))?;

    let pq_public_key = kem
        .public_key_from_bytes(&public_key)
        .ok_or_else(|| rustls::Error::General("Invalid public key".into()))?
        .to_owned();

    let (kem_key, x25519_sk, x25519_pk) = if hybrid {
        let x25519_path = x25519_key_path.unwrap_or_else(|| keys_dir.join("x25519_client.key"));
        let (x25519_sk, x25519_pk) = load_x25519_keypair_from_pem(&x25519_path)?;
        (
            Some(
                Arc::new(HybridKemKey::new(algorithm, secret_key, x25519_sk))
                    as Arc<dyn rustls::sign::KemKey>,
            ),
            Some(x25519_sk),
            Some(x25519_pk),
        )
    } else {
        (
            Some(Arc::new(PureKemKey::new(algorithm, secret_key)) as Arc<dyn rustls::sign::KemKey>),
            None,
            None,
        )
    };

    Ok((
        KeyPair::new(pq_public_key, x25519_pk, signing_key, kem_key),
        x25519_sk,
        x25519_pk,
    ))
}

pub fn load_x25519_keypair_from_pem(path: &Path) -> Result<([u8; 32], [u8; 32]), rustls::Error> {
    let pem = fs::read(path)
        .map_err(|e| rustls::Error::General(format!("failed to read x25519 key file: {e}")))?;

    let pkey = PKey::private_key_from_pem(&pem).map_err(|e| {
        rustls::Error::General(format!("failed to parse x25519 private key PEM: {e}"))
    })?;

    if pkey.id() != Id::X25519 {
        return Err(rustls::Error::General("provided key is not X25519".into()));
    }

    let raw_sk = pkey.raw_private_key().map_err(|e| {
        rustls::Error::General(format!("failed to extract raw x25519 private key: {e}"))
    })?;

    let raw_pk = pkey.raw_public_key().map_err(|e| {
        rustls::Error::General(format!("failed to extract raw x25519 public key: {e}"))
    })?;

    let sk: [u8; 32] = raw_sk
        .as_slice()
        .try_into()
        .map_err(|_| rustls::Error::General("invalid raw x25519 private key length".into()))?;

    let pk: [u8; 32] = raw_pk
        .as_slice()
        .try_into()
        .map_err(|_| rustls::Error::General("invalid raw x25519 public key length".into()))?;

    Ok((sk, pk))
}

fn group_info(
    group: NamedGroup,
) -> Result<(&'static str, oqs::kem::Algorithm, bool), rustls::Error> {
    match group {
        NamedGroup::MLKEM512 => Ok(("mlkem512", oqs::kem::Algorithm::MlKem512, false)),
        NamedGroup::MLKEM768 => Ok(("mlkem768", oqs::kem::Algorithm::MlKem768, false)),
        NamedGroup::MLKEM1024 => Ok(("mlkem1024", oqs::kem::Algorithm::MlKem1024, false)),
        NamedGroup::BikeL1 => Ok(("bikel1", oqs::kem::Algorithm::BikeL1, false)),
        NamedGroup::BikeL3 => Ok(("bikel3", oqs::kem::Algorithm::BikeL3, false)),
        NamedGroup::BikeL5 => Ok(("bikel5", oqs::kem::Algorithm::BikeL5, false)),
        NamedGroup::Hqc128 => Ok(("hqc128", oqs::kem::Algorithm::Hqc128, false)),
        NamedGroup::Hqc192 => Ok(("hqc192", oqs::kem::Algorithm::Hqc192, false)),
        NamedGroup::Hqc256 => Ok(("hqc256", oqs::kem::Algorithm::Hqc256, false)),
        NamedGroup::NtruPrimeSntrup761 => Ok((
            "ntruprimesntrup761",
            oqs::kem::Algorithm::NtruPrimeSntrup761,
            false,
        )),
        NamedGroup::X25519MLKEM512 => Ok(("mlkem512", oqs::kem::Algorithm::MlKem512, true)),
        NamedGroup::X25519MLKEM768 => Ok(("mlkem768", oqs::kem::Algorithm::MlKem768, true)),
        NamedGroup::X25519MLKEM1024 => Ok(("mlkem1024", oqs::kem::Algorithm::MlKem1024, true)),
        NamedGroup::X25519BikeL1 => Ok(("bikel1", oqs::kem::Algorithm::BikeL1, true)),
        NamedGroup::X25519BikeL3 => Ok(("bikel3", oqs::kem::Algorithm::BikeL3, true)),
        NamedGroup::X25519BikeL5 => Ok(("bikel5", oqs::kem::Algorithm::BikeL5, true)),
        NamedGroup::X25519Hqc128 => Ok(("hqc128", oqs::kem::Algorithm::Hqc128, true)),
        NamedGroup::X25519Hqc192 => Ok(("hqc192", oqs::kem::Algorithm::Hqc192, true)),
        NamedGroup::X25519Hqc256 => Ok(("hqc256", oqs::kem::Algorithm::Hqc256, true)),
        NamedGroup::X25519NtruPrimeSntrup761 => Ok((
            "ntruprimesntrup761",
            oqs::kem::Algorithm::NtruPrimeSntrup761,
            true,
        )),
        _ => Err(rustls::Error::General("Unsupported KEMTLS group".into())),
    }
}

fn load_kemtls_certified_key(
    keys_dir: &Path,
    selected_kemtls_group: NamedGroup,
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    x25519_key_path: Option<PathBuf>,
) -> Result<Arc<CertifiedKey>, rustls::Error> {
    let (dir_name, algorithm, hybrid) = group_info(selected_kemtls_group)?;
    let group_dir = keys_dir.join("server").join(dir_name);
    let public_key_path = group_dir.join("public_key.bin");
    let secret_key_path = group_dir.join("secret_key.bin");

    let public_key = fs::read(&public_key_path).map_err(|e| {
        rustls::Error::General(format!("failed to read {}: {e}", public_key_path.display()))
    })?;

    let secret_key = fs::read(&secret_key_path).map_err(|e| {
        rustls::Error::General(format!("failed to read {}: {e}", secret_key_path.display()))
    })?;

    let kem = oqs::kem::Kem::new(algorithm)
        .map_err(|_| rustls::Error::General("Failed to create KEM instance".into()))?;

    kem.public_key_from_bytes(&public_key)
        .ok_or_else(|| rustls::Error::General("Invalid public key".into()))?;

    let (kem_key, x25519_pk) = if hybrid {
        let x25519_path = x25519_key_path.unwrap_or_else(|| keys_dir.join("x25519_server.key"));
        let (x25519_sk, x25519_pk) = load_x25519_keypair_from_pem(&x25519_path)?;
        (
            Some(
                Arc::new(HybridKemKey::new(algorithm, secret_key, x25519_sk))
                    as Arc<dyn rustls::sign::KemKey>,
            ),
            Some(x25519_pk),
        )
    } else {
        (
            Some(Arc::new(PureKemKey::new(algorithm, secret_key)) as Arc<dyn rustls::sign::KemKey>),
            None,
        )
    };

    let mut cert_bytes = public_key;
    if let Some(x25519_pk) = x25519_pk {
        cert_bytes.extend_from_slice(&x25519_pk);
    }

    Ok(Arc::new(CertifiedKey {
        cert: vec![CertificateDer::from(cert_bytes)],
        key: signing_key,
        ocsp: None,
        kem_key,
    }))
}
