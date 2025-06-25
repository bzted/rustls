extern crate alloc;
use log::debug;
use rustls::sign::KemKey;
use rustls::Error;
use rustls::NamedGroup;

use crate::algorithms;
#[derive(Debug)]
pub struct MlKemKey {
    algorithm: oqs::kem::Algorithm,
    sk: Vec<u8>,
}
impl MlKemKey {
    pub fn new(algorithm: oqs::kem::Algorithm, sk: Vec<u8>) -> Self {
        Self { algorithm, sk }
    }
}
impl KemKey for MlKemKey {
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let kem = oqs::kem::Kem::new(self.algorithm)
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
        match self.algorithm {
            oqs::kem::Algorithm::MlKem512 => NamedGroup::MLKEM512,
            oqs::kem::Algorithm::MlKem768 => NamedGroup::MLKEM768,
            oqs::kem::Algorithm::MlKem1024 => NamedGroup::MLKEM1024,
            oqs::kem::Algorithm::BikeL1 => NamedGroup::BikeL1,
            oqs::kem::Algorithm::BikeL3 => NamedGroup::BikeL3,
            oqs::kem::Algorithm::BikeL5 => NamedGroup::BikeL5,
            oqs::kem::Algorithm::Hqc128 => NamedGroup::Hqc128,
            oqs::kem::Algorithm::Hqc192 => NamedGroup::Hqc192,
            oqs::kem::Algorithm::Hqc256 => NamedGroup::Hqc256,
            oqs::kem::Algorithm::NtruPrimeSntrup761 => NamedGroup::NtruPrimeStrup761,
            _ => todo!(),
        }
    }
}
