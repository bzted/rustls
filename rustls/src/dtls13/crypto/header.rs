use std::boxed::Box;

use aws_lc_rs::aead::quic::{Algorithm, HeaderProtectionKey, AES_128, AES_256, CHACHA20};
use aws_lc_rs::error::Unspecified;

use crate::CipherSuite;

pub trait HeaderEncrypter: Send + Sync {
    fn compute_mask(&self, sample: &[u8]) -> [u8; 5];
}

pub struct HeaderProtection {
    inner: HeaderProtectionKey,
}

impl HeaderProtection {
    pub fn new(alg: &'static Algorithm, sn_key: &[u8]) -> Result<Self, Unspecified> {
        let key = HeaderProtectionKey::new(alg, sn_key)?;
        Ok(Self { inner: key })
    }
}

impl HeaderEncrypter for HeaderProtection {
    fn compute_mask(&self, sample: &[u8]) -> [u8; 5] {
        match self.inner.new_mask(sample) {
            Ok(mask) => mask,
            Err(_) => {
                // return zeros if failed. 
                // AEAD authentication will fail after.
                [0u8; 5] 
            }
        }
    }
}

pub fn create_header_protection(
    suite: CipherSuite, 
    sn_key: &[u8]
) -> Box<dyn HeaderEncrypter> {
    
    let alg = match suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => &AES_128,
        CipherSuite::TLS13_AES_256_GCM_SHA384 => &AES_256,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => &CHACHA20,
        _ => panic!("Unsupported cipher suite for DTLS 1.3 header protection"),
    };

    let protector = HeaderProtection::new(alg, sn_key)
        .expect("Failed to create header protection key");

    Box::new(protector)
}