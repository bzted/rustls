pub use kem_key::MlKemKey;
use rustls::crypto::aws_lc_rs;

mod algorithms;
mod kem_key;
mod key_exchange;
pub mod resolver;
pub mod sign;
pub mod verify;
pub use algorithms::{KX_GROUPS, MLKEM1024, MLKEM512, MLKEM768};
pub use key_exchange::KeyExchange;

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: KX_GROUPS.to_vec(),
        ..aws_lc_rs::default_provider()
    }
}
