extern crate alloc;
use log::debug;
use rustls::sign::KemKey;
use rustls::Error;
use rustls::NamedGroup;
#[derive(Debug)]
pub struct MlKemKey {
    algorithm: NamedGroup,
    sk: Vec<u8>,
}
impl MlKemKey {
    pub fn new(algorithm: NamedGroup, sk: Vec<u8>) -> Self {
        Self { algorithm, sk }
    }
}
impl KemKey for MlKemKey {
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let kem = match self.algorithm {
            NamedGroup::MLKEM512 => oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem512),
            NamedGroup::MLKEM768 => oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768),
            NamedGroup::MLKEM1024 => oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024),
            _ => return Err(Error::General("Unsupported KEM algorithm".into())),
        }
        .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let sk = oqs::kem::Kem::secret_key_from_bytes(&kem, &self.sk)
            .ok_or_else(|| Error::General("Invalid private key".into()))?;

        debug!("Ciphertext size: {} bytes", ciphertext.len());
        let ct = oqs::kem::Kem::ciphertext_from_bytes(&kem, ciphertext)
            .ok_or_else(|| Error::General("Invalid ciphertext".into()))?;

        let ss = kem.decapsulate(sk, ct).map_err(|e| {
            debug!("Decapsulation failed: {}", e);
            Error::General("Decapsulation failed".into())
        })?;
        debug!("Decapsulation successful!");
        debug!("Shared secret size: {} bytes", ss.as_ref().len());

        Ok(ss.as_ref().to_vec())
    }

    fn algorithm(&self) -> NamedGroup {
        self.algorithm
    }
}
