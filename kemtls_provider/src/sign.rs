use log::debug;
use rustls;

/// Not used for authkem, but required by rustls
#[derive(Debug)]
pub struct DummySigningKey;

impl rustls::sign::SigningKey for DummySigningKey {
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }

    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = offered
            .first()
            .copied()
            .unwrap_or(rustls::SignatureScheme::ED25519);
        Some(Box::new(DummySigner { scheme }))
    }
}

#[derive(Debug)]
struct DummySigner {
    scheme: rustls::SignatureScheme,
}

impl rustls::sign::Signer for DummySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        debug!(
            "WARNING: DummySigner.sign() called with {} bytes - returning dummy signature",
            message.len()
        );
        Ok(vec![0u8; 64])
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.scheme
    }
}
