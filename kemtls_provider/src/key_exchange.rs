extern crate alloc;
use alloc::boxed::Box;
use oqs::kem::Kem;
use rustls::crypto;

pub struct KeyExchange {
    pk: oqs::kem::PublicKey,
    sk: oqs::kem::SecretKey,
    kem: Kem,
}
impl KeyExchange {
    pub fn new(pk: oqs::kem::PublicKey, sk: oqs::kem::SecretKey, kem: Kem) -> Self {
        Self { pk, sk, kem }
    }
}
impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer_pub_key: &[u8], //peer Public Key
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let ct = self
            .kem
            .ciphertext_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid Ciphertext".into()))?;
        let ss = self
            .kem
            .decapsulate(&self.sk, ct)
            .map_err(|_| rustls::Error::General("Kem decapsulation failed".into()))?;

        Ok(crypto::SharedSecret::from(ss.as_ref()))
    }
    fn pub_key(&self) -> &[u8] {
        self.pk.as_ref()
    }
    fn group(&self) -> rustls::NamedGroup {
        match self.kem.algorithm() {
            oqs::kem::Algorithm::MlKem512 => rustls::NamedGroup::MLKEM512,
            oqs::kem::Algorithm::MlKem768 => rustls::NamedGroup::MLKEM768,
            oqs::kem::Algorithm::MlKem1024 => rustls::NamedGroup::MLKEM1024,
            oqs::kem::Algorithm::BikeL1 => rustls::NamedGroup::BikeL1,
            oqs::kem::Algorithm::BikeL3 => rustls::NamedGroup::BikeL3,
            oqs::kem::Algorithm::BikeL5 => rustls::NamedGroup::BikeL5,
            oqs::kem::Algorithm::Hqc128 => rustls::NamedGroup::Hqc128,
            oqs::kem::Algorithm::Hqc192 => rustls::NamedGroup::Hqc192,
            oqs::kem::Algorithm::Hqc256 => rustls::NamedGroup::Hqc256,
            oqs::kem::Algorithm::NtruPrimeSntrup761 => rustls::NamedGroup::NtruPrimeStrup761,
            _ => rustls::NamedGroup::Unknown(0),
        }
    }
}
