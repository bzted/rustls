extern crate alloc;
use crate::key_exchange::KeyExchange;
use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use oqs::kem::Kem;
use rustls::crypto::{self, CompletedKeyExchange, SharedSecret};
use crypto::aws_lc_rs::kx_group::X25519;
use crate::hybrid;

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
    &NtruPrimeSntrup761 as &dyn SupportedKxGroup,
    X25519MLKEM512,
    X25519MLKEM768,
    X25519MLKEM1024,
    X25519BIKEL1,
    X25519BIKEL3,
    X25519BIKEL5,
    X25519HQC128,
    X25519HQC192,
    X25519HQC256,
    X25519NTRUPRIMESNTRUP761,
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
pub struct NtruPrimeSntrup761;

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

impl crypto::SupportedKxGroup for NtruPrimeSntrup761 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup761)
            .map_err(|_| rustls::Error::General("NtruPrimeSntrup761 Algorithm not found".into()))?;
        let (pk, sk) = kem.keypair().map_err(|_| {
            rustls::Error::General("Failed to generate NtruPrimeSntrup761 keypair".into())
        })?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::NtruPrimeSntrup761
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

/// Hybrid groups implementation

const X25519_LEN: usize = 32;

const MLKEM512_CIPHERTEXT_LEN: usize = 768;
const MLKEM512_ENCAP_LEN: usize = 800;

pub static X25519MLKEM512: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &MLKEM512,
    name: rustls::NamedGroup::X25519MLKEM512,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM512_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM512_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;

pub static X25519MLKEM768: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &MLKEM768,
    name: rustls::NamedGroup::X25519MLKEM768,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
const MLKEM1024_ENCAP_LEN: usize = 1568;

pub static X25519MLKEM1024: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &MLKEM1024,
    name: rustls::NamedGroup::X25519MLKEM1024,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM1024_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM1024_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};
/// Parameters taken from:
/// https://openquantumsafe.org/liboqs/algorithms/kem/bike.html

const BIKEL1_CIPHERTEXT_LEN: usize = 1573;
const BIKEL1_ENCAP_LEN: usize = 1541;

pub static X25519BIKEL1: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &BikeL1,
    name: rustls::NamedGroup::X25519BikeL1,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: BIKEL1_ENCAP_LEN,
        post_quantum_server_share_len: BIKEL1_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

const BIKEL3_CIPHERTEXT_LEN: usize = 3115;
const BIKEL3_ENCAP_LEN: usize = 3083;

pub static X25519BIKEL3: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &BikeL3,
    name: rustls::NamedGroup::X25519BikeL3,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: BIKEL3_ENCAP_LEN,
        post_quantum_server_share_len: BIKEL3_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

const BIKEL5_CIPHERTEXT_LEN: usize = 5154;
const BIKEL5_ENCAP_LEN: usize = 5122;

pub static X25519BIKEL5: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &BikeL5,
    name: rustls::NamedGroup::X25519BikeL5,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: BIKEL5_ENCAP_LEN,
        post_quantum_server_share_len: BIKEL5_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// Parameters taken from:
/// https://openquantumsafe.org/liboqs/algorithms/kem/hqc.html

const HQC128_CIPHERTEXT_LEN: usize = 4433;
const HQC128_ENCAP_LEN: usize = 2249;

pub static X25519HQC128: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &Hqc128,
    name: rustls::NamedGroup::X25519Hqc128,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: HQC128_ENCAP_LEN,
        post_quantum_server_share_len: HQC128_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

const HQC192_CIPHERTEXT_LEN: usize = 8978;
const HQC192_ENCAP_LEN: usize = 4522;

pub static X25519HQC192: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &Hqc192,
    name: rustls::NamedGroup::X25519Hqc192,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: HQC192_ENCAP_LEN,
        post_quantum_server_share_len: HQC192_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

const HQC256_CIPHERTEXT_LEN: usize = 14421;
const HQC256_ENCAP_LEN: usize = 7245;

pub static X25519HQC256: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &Hqc256,
    name: rustls::NamedGroup::X25519Hqc256,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: HQC256_ENCAP_LEN,
        post_quantum_server_share_len: HQC256_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// Parameters taken from:
/// https://openquantumsafe.org/liboqs/algorithms/kem/ntruprime.html

const NTRUPRIMESNTRUP761_CIPHERTEXT_LEN: usize = 1039;
const NTRUPRIMESNTRUP761_ENCAP_LEN: usize = 1158;

pub static X25519NTRUPRIMESNTRUP761: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: X25519,
    post_quantum: &NtruPrimeSntrup761,
    name: rustls::NamedGroup::X25519NtruPrimeSntrup761,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: NTRUPRIMESNTRUP761_ENCAP_LEN,
        post_quantum_server_share_len: NTRUPRIMESNTRUP761_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

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
        "NTRUPRIMESNTRUP761" => Some(&NtruPrimeSntrup761),
        "X25519MLKEM512" => Some(X25519MLKEM512),
        "X25519MLKEM768" => Some(X25519MLKEM768),
        "X25519MLKEM1024" => Some(X25519MLKEM1024),
        "X25519BIKEL1" => Some(X25519BIKEL1),
        "X25519BIKEL3" => Some(X25519BIKEL3),
        "X25519BIKEL5" => Some(X25519BIKEL5),
        "X25519HQC128" => Some(X25519HQC128),
        "X25519HQC192" => Some(X25519HQC192),
        "X25519HQC256" => Some(X25519HQC256),
        "X25519NTRUPRIMESNTRUP761" => Some(X25519NTRUPRIMESNTRUP761),
        _ => None,
    }
}
