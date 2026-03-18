use std::sync::Arc;

pub use kem_key::{PureKemKey, HybridKemKey};
use rustls::crypto::aws_lc_rs;
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;

mod algorithms;
mod kem_key;
mod key_exchange;
pub mod hybrid;
pub mod psk_key;
pub mod resolver;
pub mod sign;
pub mod verify;
pub use algorithms::{
    get_pq_kx_group_by_name, get_kx_group_by_name, BikeL1, BikeL3, BikeL5, Hqc128, Hqc192, Hqc256, NtruPrimeSntrup761,
    KX_GROUPS, MLKEM1024, MLKEM512, MLKEM768, DEFAULT_KX_GROUPS,
};
pub use key_exchange::KeyExchange;
use rustls::sign::SigningKey;
use rustls::Error;
use ::aws_lc_rs::unstable::signature::PqdsaKeyPair;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use crate::sign::PqdsaKeyKind;
use crate::sign::PqdsaSigningKey;
use crate::sign::SUPPORTED_SIG_ALGS;

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        key_provider: &KemtlsProvider,
        ..aws_lc_rs::default_provider()
    }
}

#[derive(Debug)]
pub struct KemtlsProvider;

impl KeyProvider for KemtlsProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        if let PrivateKeyDer::Pkcs8(pkcs8) = &key_der {
            for kind in PqdsaKeyKind::iter() {
                match PqdsaKeyPair::from_pkcs8(kind.to_alg(), pkcs8.secret_pkcs8_der()) {
                    Ok(key_pair) => {
                        return Ok(Arc::new(PqdsaSigningKey {
                            kind,
                            inner: Arc::new(key_pair),
                        }));
                    }
                    Err(_) => {
                        continue
                    },
                }
            }
        }

        match any_supported_type(&key_der) {
            Ok(key) => Ok(key),
            Err(_) => Err(Error::General(
                "failed to parse private key as ML-DSA, RSA, ECDSA, or EdDSA".into(),
            )),
        }
    }

    fn fips(&self) -> bool {
        false
    }
}