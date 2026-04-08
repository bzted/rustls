pub use kem_key::{PureKemKey, HybridKemKey};
use rustls::crypto::ring;

mod algorithms;
mod kem_key;
mod key_exchange;
pub mod hybrid;
pub mod psk_key;
pub mod resolver;
pub mod sign;
pub mod verify;
#[cfg(feature = "mldsa")]
pub mod pq_sign;
#[cfg(feature = "mldsa")]
use crate::pq_sign::{SUPPORTED_SIG_ALGS, KeyLoader};
pub use algorithms::{
    get_pq_kx_group_by_name, get_kx_group_by_name, BikeL1, BikeL3, BikeL5, Hqc128, Hqc192, Hqc256, NtruPrimeSntrup761,
    KX_GROUPS, MLKEM1024, MLKEM512, MLKEM768, DEFAULT_KX_GROUPS,
};
pub use key_exchange::KeyExchange;

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: KX_GROUPS.to_vec(),
        #[cfg(feature = "mldsa")]
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        #[cfg(feature = "mldsa")]
        key_provider: &KeyLoader,
        ..ring::default_provider()
    }
}
