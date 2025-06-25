pub use kem_key::MlKemKey;
use rustls::crypto::aws_lc_rs;

mod algorithms;
mod kem_key;
mod key_exchange;
pub mod psk_key;
pub mod resolver;
pub mod sign;
pub mod verify;
pub use algorithms::{
    get_kx_group_by_name, BikeL1, BikeL3, BikeL5, Hqc128, Hqc192, Hqc256, NtruPrimeStrup761,
    KX_GROUPS, MLKEM1024, MLKEM512, MLKEM768,
};
pub use key_exchange::KeyExchange;

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: KX_GROUPS.to_vec(),
        ..aws_lc_rs::default_provider()
    }
}
