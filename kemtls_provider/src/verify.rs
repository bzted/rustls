use log::debug;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::Error;

#[derive(Debug)]
pub struct ClientVerifier {
    algorithm: oqs::kem::Algorithm,
    x25519_sk: Option<[u8; 32]>,
    x25519_pk: Option<[u8; 32]>,
}

impl ClientVerifier {
    pub fn new(algorithm: oqs::kem::Algorithm, x25519_sk: Option<[u8; 32]>, x25519_pk: Option<[u8; 32]>) -> Self {
        ClientVerifier { algorithm, x25519_sk, x25519_pk }
    }

    fn pq_public_key_len(&self) -> usize {
        match self.algorithm {
            oqs::kem::Algorithm::MlKem512 => 800,
            oqs::kem::Algorithm::MlKem768 => 1184,
            oqs::kem::Algorithm::MlKem1024 => 1568,
            oqs::kem::Algorithm::BikeL1 => 1541,
            oqs::kem::Algorithm::BikeL3 => 3083,
            oqs::kem::Algorithm::BikeL5 => 5122,
            oqs::kem::Algorithm::Hqc128 => 2249,
            oqs::kem::Algorithm::Hqc192 => 4522,
            oqs::kem::Algorithm::Hqc256 => 7245,
            oqs::kem::Algorithm::NtruPrimeSntrup761 => 1158,
            _ => todo!(),
        }
    }
}

impl ServerCertVerifier for ClientVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now_time: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls12_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls13_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        debug!("supported_verify_schemes called");
        Vec::new()
    }

    fn requires_raw_public_keys(&self) -> bool {
        debug!("requires_raw_public_keys called - returning true");
        true
    }

    fn authkem(&self) -> bool {
        debug!("Trying authkem flow");
        true
    }

    fn encapsulate(&self, server_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        debug!("About to encapsulate to servers public key");

        if let (Some(sk), Some(pk)) = (self.x25519_sk, self.x25519_pk) {
            debug!("Using hybrid encapsulation flow");
            let (pq_pk_bytes, x25519_share) = server_pk.split_at(self.pq_public_key_len());

            let kem = oqs::kem::Kem::new(self.algorithm)
                .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pq_pk = kem
                .public_key_from_bytes(pq_pk_bytes)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (pq_ct, pq_ss) = kem
                .encapsulate(pq_pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            let peer_pub = x25519_share.try_into().map_err(|_| Error::General("Invalid X25519 public key".into()))?;
            let x25519_ss = x25519_dalek::x25519(sk, peer_pub); 


            let ciphertext = [pq_ct.as_ref(), &pk].concat();
            let shared_secret = [pq_ss.into_vec(), x25519_ss.as_slice().to_vec()].concat();

            return Ok((ciphertext, shared_secret))
        } else {
            let kem = oqs::kem::Kem::new(self.algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pk = kem
                .public_key_from_bytes(server_pk)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (ct, ss) = kem
                .encapsulate(pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            return Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
    }
}

#[derive(Debug)]
pub struct ServerVerifier {
    root_hints: Vec<rustls::DistinguishedName>, // Decoded using x509-parser. Not used in AuthKem
    algorithm: oqs::kem::Algorithm,
    x25519_sk: Option<[u8; 32]>,
    x25519_pk: Option<[u8; 32]>,
}

impl ServerVerifier {
    pub fn new(algorithm: oqs::kem::Algorithm, x25519_sk: Option<[u8; 32]>, x25519_pk: Option<[u8; 32]>) -> Self {
        ServerVerifier {
            root_hints: vec![rustls::DistinguishedName::from(Vec::new())],
            algorithm,
            x25519_sk,
            x25519_pk,
        }
    }

    fn pq_public_key_len(&self) -> usize {
        match self.algorithm {
            oqs::kem::Algorithm::MlKem512 => 800,
            oqs::kem::Algorithm::MlKem768 => 1184,
            oqs::kem::Algorithm::MlKem1024 => 1568,
            oqs::kem::Algorithm::BikeL1 => 1541,
            oqs::kem::Algorithm::BikeL3 => 3083,
            oqs::kem::Algorithm::BikeL5 => 5122,
            oqs::kem::Algorithm::Hqc128 => 2249,
            oqs::kem::Algorithm::Hqc192 => 4522,
            oqs::kem::Algorithm::Hqc256 => 7245,
            oqs::kem::Algorithm::NtruPrimeSntrup761 => 1158,
            _ => todo!(),
        }
    }
}
impl ClientCertVerifier for ServerVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        debug!("root_hint_subjects called");
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls12_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls13_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        debug!("supported_verify_schemes called");
        vec![rustls::SignatureScheme::ED25519]
    }

    fn authkem(&self) -> bool {
        true
    }

    fn encapsulate(&self, client_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        debug!("About to encapsulate to clients public key");

        if let (Some(sk), Some(pk)) = (self.x25519_sk, self.x25519_pk) {
            debug!("Using hybrid encapsulation flow");
            let (pq_pk_bytes, x25519_share) = client_pk.split_at(self.pq_public_key_len());
            debug!("Extracted pq_pk_bytes of length {} and x25519_share of length {}", pq_pk_bytes.len(), x25519_share.len());

            let kem = oqs::kem::Kem::new(self.algorithm)
                .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pq_pk = kem
                .public_key_from_bytes(pq_pk_bytes)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (pq_ct, pq_ss) = kem
                .encapsulate(pq_pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            let peer_pub = x25519_share.try_into().map_err(|_| Error::General("Invalid X25519 public key".into()))?;
            let x25519_ss = x25519_dalek::x25519(sk, peer_pub); 


            let ciphertext = [pq_ct.as_ref(), &pk].concat();
            let shared_secret = [pq_ss.into_vec(), x25519_ss.as_slice().to_vec()].concat();

            return Ok((ciphertext, shared_secret))
        } else {
            let kem = oqs::kem::Kem::new(self.algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pk = kem
                .public_key_from_bytes(client_pk)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (ct, ss) = kem
                .encapsulate(pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            return Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }
}
