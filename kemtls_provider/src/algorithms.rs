extern crate alloc;
use crate::key_exchange::KeyExchange;
use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use oqs::kem::Kem;
use rustls::crypto::{self, CompletedKeyExchange, SharedSecret};

pub const KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &MLKEM768 as &dyn SupportedKxGroup,
    &MLKEM512 as &dyn SupportedKxGroup,
    &MLKEM1024 as &dyn SupportedKxGroup,
    &BikeL1 as &dyn SupportedKxGroup,
    &BikeL3 as &dyn SupportedKxGroup,
    &BikeL5 as &dyn SupportedKxGroup,
    &Hqc128 as &dyn SupportedKxGroup,
    &Hqc192 as &dyn SupportedKxGroup,
    &Hqc256 as &dyn SupportedKxGroup,
    &NtruPrimeStrup761 as &dyn SupportedKxGroup,
];

#[derive(Debug)]
pub struct MLKEM512;
#[derive(Debug)]
pub struct MLKEM768;
#[derive(Debug)]
pub struct MLKEM1024;

#[derive(Debug)]
pub struct BikeL1;
#[derive(Debug)]
pub struct BikeL3;
#[derive(Debug)]
pub struct BikeL5;

#[derive(Debug)]
pub struct Hqc128;
#[derive(Debug)]
pub struct Hqc192;
#[derive(Debug)]
pub struct Hqc256;

#[derive(Debug)]
pub struct NtruPrimeStrup761;

impl crypto::SupportedKxGroup for MLKEM512 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem512)
            .map_err(|_| rustls::Error::General("ML-KEM512 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate ML-KEM512 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM512
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem512)
            .map_err(|_| rustls::Error::General("ML-KEM512 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}
impl crypto::SupportedKxGroup for MLKEM768 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem768)
            .map_err(|_| rustls::Error::General("ML-KEM768 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate ML-KEM768 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM768
    }
    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem768)
            .map_err(|_| rustls::Error::General("ML-KEM768 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}
impl crypto::SupportedKxGroup for MLKEM1024 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem1024)
            .map_err(|_| rustls::Error::General("ML-KEM1024 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate ML-KEM1024 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM1024
    }
    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem1024)
            .map_err(|_| rustls::Error::General("ML-KEM1024 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

impl crypto::SupportedKxGroup for BikeL1 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::BikeL1)
            .map_err(|_| rustls::Error::General("BikeL1 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate BikeL1 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::BikeL1
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::BikeL1)
            .map_err(|_| rustls::Error::General("BikeL1 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

impl crypto::SupportedKxGroup for BikeL3 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::BikeL3)
            .map_err(|_| rustls::Error::General("BikeL3 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate BikeL3 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::BikeL3
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::BikeL3)
            .map_err(|_| rustls::Error::General("BikeL3 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

impl crypto::SupportedKxGroup for BikeL5 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::BikeL5)
            .map_err(|_| rustls::Error::General("BikeL5 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate BikeL5 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::BikeL5
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::BikeL5)
            .map_err(|_| rustls::Error::General("BikeL5 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

impl crypto::SupportedKxGroup for Hqc128 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::Hqc128)
            .map_err(|_| rustls::Error::General("Hqc128 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate Hqc128 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::Hqc128
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::Hqc128)
            .map_err(|_| rustls::Error::General("Hqc128 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

impl crypto::SupportedKxGroup for Hqc192 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::Hqc192)
            .map_err(|_| rustls::Error::General("Hqc192 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate Hqc192 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::Hqc192
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::Hqc192)
            .map_err(|_| rustls::Error::General("Hqc192 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

impl crypto::SupportedKxGroup for Hqc256 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::Hqc256)
            .map_err(|_| rustls::Error::General("Hqc256 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate Hqc256 keypair".into()))?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::Hqc256
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::Hqc256)
            .map_err(|_| rustls::Error::General("Hqc256 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

impl crypto::SupportedKxGroup for NtruPrimeStrup761 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup761)
            .map_err(|_| rustls::Error::General("NtruPrimeSntrup761 Algorithm not found".into()))?;
        let (pk, sk) = kem.keypair().map_err(|_| {
            rustls::Error::General("Failed to generate NtruPrimeSntrup761 keypair".into())
        })?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::NtruPrimeStrup761
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup761)
            .map_err(|_| rustls::Error::General("NtruPrimeSntrup761 Algorithm not found".into()))?;
        let peer_pk = kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid peer public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("KEM Encapsulation failed".into()))?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ct.as_ref().to_vec(),
            secret: SharedSecret::from(ss.as_ref()),
        })
    }
}

pub fn get_kx_group_by_name(name: &str) -> Option<&'static dyn SupportedKxGroup> {
    match name.to_uppercase().as_str() {
        "MLKEM512" => Some(&MLKEM512),
        "MLKEM768" => Some(&MLKEM768),
        "MLKEM1024" => Some(&MLKEM1024),
        "BIKEL1" => Some(&BikeL1),
        "BIKEL3" => Some(&BikeL3),
        "BIKEL5" => Some(&BikeL5),
        "HQC128" => Some(&Hqc128),
        "HQC192" => Some(&Hqc192),
        "HQC256" => Some(&Hqc256),
        "NTRUPRIMESNTRUP761" => Some(&NtruPrimeStrup761),
        _ => None,
    }
}
