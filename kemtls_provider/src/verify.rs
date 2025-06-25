use log::debug;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::Error;

#[derive(Debug)]
pub struct ClientVerifier {
    algorithm: oqs::kem::Algorithm,
}

impl ClientVerifier {
    pub fn new(algorithm: oqs::kem::Algorithm) -> Self {
        ClientVerifier { algorithm }
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

        let kem = oqs::kem::Kem::new(self.algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let pk = kem
            .public_key_from_bytes(server_pk)
            .ok_or_else(|| Error::General("Invalid public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(pk)
            .map_err(|_| Error::General("Encapsulation failed".into()))?;

        Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
    }
}

#[derive(Debug)]
pub struct ServerVerifier {
    root_hints: Vec<rustls::DistinguishedName>, // Decoded using x509-parser. Not used in AuthKem
    algorithm: oqs::kem::Algorithm,
}

impl ServerVerifier {
    pub fn new(algorithm: oqs::kem::Algorithm) -> Self {
        ServerVerifier {
            root_hints: vec![rustls::DistinguishedName::from(Vec::new())],
            algorithm,
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

        let kem = oqs::kem::Kem::new(self.algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let pk = kem
            .public_key_from_bytes(client_pk)
            .ok_or_else(|| Error::General("Invalid public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(pk)
            .map_err(|_| Error::General("Encapsulation failed".into()))?;

        Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }
}
