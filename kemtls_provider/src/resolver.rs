use log::debug;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::SignatureScheme;
use std::sync::Arc;

#[derive(Debug)]
pub struct ServerCertResolver {
    key_pair: KeyPair,
}

impl ServerCertResolver {
    pub fn new(key_pair: KeyPair) -> Self {
        Self { key_pair }
    }
}

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        debug!("ServerCertResolver::resolve called");
        debug!(
            "PQ key size: {} bytes, X25519 key size: {} bytes",
            self.key_pair.pq_public_key.as_ref().len(),
            self.key_pair.x25519_public_key.as_ref().map_or(0, |k| k.len()),
        );

        let mut cert_bytes = self.key_pair.pq_public_key.as_ref().to_vec();

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

    fn only_raw_public_keys(&self) -> bool {
        true
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
            self.key_pair.pq_public_key.as_ref().len(),
            self.key_pair.x25519_public_key.as_ref().map_or(0, |k| k.len()),
        );

        let mut cert_bytes = self.key_pair.pq_public_key.as_ref().to_vec();

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
            kem_key
        }
    }
}
