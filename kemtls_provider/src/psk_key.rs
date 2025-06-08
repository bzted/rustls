use log::debug;
use rustls::client::danger::AuthKemPskKey;
use rustls::Error;

#[derive(Debug)]
pub struct PskKey {
    server_pk: Vec<u8>,
}

impl PskKey {
    pub fn new(server_pk: Vec<u8>) -> Self {
        Self { server_pk }
    }
}

impl AuthKemPskKey for PskKey {
    fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        debug!("About to encapsulate to servers public key");

        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let pk = kem
            .public_key_from_bytes(&self.server_pk)
            .ok_or_else(|| Error::General("Invalid public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(pk)
            .map_err(|_| Error::General("Encapsulation failed".into()))?;

        Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
    }
}
