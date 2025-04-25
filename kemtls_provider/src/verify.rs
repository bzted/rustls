use log::debug;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::Error;

#[derive(Debug)]
pub struct Verifier;

impl ServerCertVerifier for Verifier {
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
        debug!("About to encapsulate to peers public key");

        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
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
