extern crate alloc;
use log::debug;
use rustls::sign::KemKey;
use rustls::Error;
use rustls::NamedGroup;
use x25519_dalek;

#[derive(Debug)]
pub struct PureKemKey {
    algorithm: oqs::kem::Algorithm,
    sk: Vec<u8>,
}
impl PureKemKey {
    pub fn new(algorithm: oqs::kem::Algorithm, sk: Vec<u8>) -> Self {
        Self { algorithm, sk }
    }
}
impl KemKey for PureKemKey {
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let kem = oqs::kem::Kem::new(self.algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let sk = oqs::kem::Kem::secret_key_from_bytes(&kem, &self.sk)
            .ok_or_else(|| Error::General("Invalid private key".into()))?;

        let ct = oqs::kem::Kem::ciphertext_from_bytes(&kem, ciphertext)
            .ok_or_else(|| Error::General("Invalid ciphertext".into()))?;

        let ss = kem.decapsulate(sk, ct).map_err(|e| {
            debug!("Decapsulation failed: {}", e);
            Error::General("Decapsulation failed".into())
        })?;
        debug!("DECAPSULATION RESULT : ct: {} bytes, ss: {} bytes", ct.as_ref().len(), ss.as_ref().len());

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
            oqs::kem::Algorithm::NtruPrimeSntrup761 => NamedGroup::NtruPrimeSntrup761,
            _ => todo!(),
        }
    }
}

const X25519_PUBLIC_LEN: usize = 32;

#[derive(Debug)]
pub struct HybridKemKey {
    algorithm: oqs::kem::Algorithm,
    pq_sk: Vec<u8>,
    x25519_sk: [u8; 32],
}
impl HybridKemKey {
    pub fn new(algorithm: oqs::kem::Algorithm, pq_sk: Vec<u8>, x25519_sk: [u8; 32]) -> Self {
        Self { algorithm, pq_sk, x25519_sk }
    }

    fn pq_ciphertext_len(&self) -> usize {
        match self.algorithm {
            oqs::kem::Algorithm::MlKem512 => 768,
            oqs::kem::Algorithm::MlKem768 => 1088,
            oqs::kem::Algorithm::MlKem1024 => 1568,
            oqs::kem::Algorithm::BikeL1 => 1573,
            oqs::kem::Algorithm::BikeL3 => 3115,
            oqs::kem::Algorithm::BikeL5 => 5154,
            oqs::kem::Algorithm::Hqc128 => 4433,
            oqs::kem::Algorithm::Hqc192 => 8978,
            oqs::kem::Algorithm::Hqc256 => 14421,
            oqs::kem::Algorithm::NtruPrimeSntrup761 => 1039,
            _ => todo!(),
        }
    }
}

impl KemKey for HybridKemKey {
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() != self.pq_ciphertext_len() + X25519_PUBLIC_LEN {
            return Err(Error::General("invalid hybrid ciphertext length".into()));
        }

        let (pq_ct_bytes, x25519_share) = ciphertext.split_at(self.pq_ciphertext_len());

        let kem = oqs::kem::Kem::new(self.algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let pq_sk = oqs::kem::Kem::secret_key_from_bytes(&kem, &self.pq_sk)
            .ok_or_else(|| Error::General("Invalid private key".into()))?;

        let pq_ct = oqs::kem::Kem::ciphertext_from_bytes(&kem, pq_ct_bytes)
            .ok_or_else(|| Error::General("Invalid ciphertext".into()))?;

        let pq_ss = kem.decapsulate(pq_sk, pq_ct).map_err(|e| {
            debug!("Decapsulation failed: {}", e);
            Error::General("Decapsulation failed".into())
        })?;

        let peer_pub = x25519_share.try_into().map_err(|_| Error::General("Invalid X25519 public key".into()))?;

        let x25519_ss = x25519_dalek::x25519(self.x25519_sk, peer_pub); 

        debug!("HYBRID DECAPSULATION RESULT : pq_ct: {} bytes, complete_ct: {} bytes, pq_ss: {} bytes, x25519_ss: {} bytes", pq_ct.as_ref().len(), ciphertext.len(), pq_ss.as_ref().len(), x25519_ss.as_slice().len());
        let out = [pq_ss.as_ref().to_vec(), x25519_ss.as_slice().to_vec()].concat();
        Ok(out)
    }

    fn algorithm(&self) -> NamedGroup {
        match self.algorithm {
            oqs::kem::Algorithm::MlKem512 => NamedGroup::X25519MLKEM512,
            oqs::kem::Algorithm::MlKem768 => NamedGroup::X25519MLKEM768,
            oqs::kem::Algorithm::MlKem1024 => NamedGroup::X25519MLKEM1024,
            oqs::kem::Algorithm::BikeL1 => NamedGroup::X25519BikeL1,
            oqs::kem::Algorithm::BikeL3 => NamedGroup::X25519BikeL3,
            oqs::kem::Algorithm::BikeL5 => NamedGroup::X25519BikeL5,
            oqs::kem::Algorithm::Hqc128 => NamedGroup::X25519Hqc128,
            oqs::kem::Algorithm::Hqc192 => NamedGroup::X25519Hqc192,
            oqs::kem::Algorithm::Hqc256 => NamedGroup::X25519Hqc256,
            oqs::kem::Algorithm::NtruPrimeSntrup761 => NamedGroup::X25519NtruPrimeSntrup761,
            _ => todo!(),
        }
    }
}