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
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        debug!("ServerCertResolver::resolve called");
        debug!(
            "Key size: {} bytes",
            self.key_pair.public_key.as_ref().len()
        );

        let raw_key = self
            .key_pair
            .public_key
            .as_ref()
            .to_vec();

        let cert = CertificateDer::from(raw_key.clone());

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
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        debug!("ClientCertResolver::resolve called");
        debug!(
            "Key size: {} bytes",
            self.key_pair.public_key.as_ref().len()
        );

        let raw_key = self
            .key_pair
            .public_key
            .as_ref()
            .to_vec();

        let cert = CertificateDer::from(raw_key.clone());

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
    public_key: oqs::kem::PublicKey,
    private_key: Arc<dyn rustls::sign::SigningKey>,
    kem_key: Option<Arc<dyn rustls::sign::KemKey>>,
}

impl KeyPair {
    pub fn new(
        public_key: oqs::kem::PublicKey,
        signing_key: Arc<dyn rustls::sign::SigningKey>,
        kem_key: Option<Arc<dyn rustls::sign::KemKey>>,
    ) -> Self {
        Self {
            public_key,
            private_key: signing_key,
            kem_key,
        }
    }
}
