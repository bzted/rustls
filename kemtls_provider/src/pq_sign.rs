use aws_lc_rs::signature::KeyPair;
use rustls::{self, crypto::WebPkiSupportedAlgorithms};
use rustls::SignatureScheme;
use webpki::aws_lc_rs as webpki_algs;
use aws_lc_rs::unstable::signature::{
    ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair,
    PqdsaSigningAlgorithm,
};
use std::sync::Arc;
use rustls::sign::{SigningKey, Signer, public_key_to_spki};
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::pki_types::AlgorithmIdentifier;
use rustls::SignatureAlgorithm;
use core::fmt::{self, Debug, Formatter};
use rustls::Error;
use rustls::pki_types::alg_id;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;

#[derive(Debug)]
pub struct KeyLoader;

impl KeyProvider for KeyLoader {
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

pub(crate) struct PqdsaSigningKey {
    pub(crate) kind: PqdsaKeyKind,
    pub(crate) inner: Arc<PqdsaKeyPair>,
}

impl SigningKey for PqdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if !offered.contains(&self.kind.scheme()) {
            return None;
        }

        Some(Box::new(PqdsaSigner {
            key: self.inner.clone(),
            kind: self.kind,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(
            &self.kind.alg_id(),
            self.inner.public_key(),
        ))
    }

    // [`SignatureAlgorithm`] is for TLS 1.2, for which ML-DSA is not specified.
    // Pick a "Reserved for Private Use" value.
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(255)
    }
}

impl Debug for PqdsaSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqdsaSigningKey")
            .field("scheme", &self.kind.scheme())
            .finish_non_exhaustive()
    }
}

pub(crate) struct PqdsaSigner {
    pub(crate) key: Arc<PqdsaKeyPair>,
    pub(crate) kind: PqdsaKeyKind,
}

impl Signer for PqdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let expected_sig_len = self.key.algorithm().signature_len();
        let mut sig = vec![0; expected_sig_len];
        let actual_sig_len = self
            .key
            .sign(message, &mut sig)
            .map_err(|_| Error::General("signing failed".into()))?;

        if actual_sig_len != expected_sig_len {
            return Err(Error::General("unexpected signature length".into()));
        }

        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.kind.scheme()
    }
}

impl Debug for PqdsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqdsaSigner")
            .field("scheme", &self.kind.scheme())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PqdsaKeyKind {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}


impl PqdsaKeyKind {
    pub(crate) fn iter() -> impl Iterator<Item = Self> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87].into_iter()
    }

    pub(crate) fn to_alg(self) -> &'static PqdsaSigningAlgorithm {
        match self {
            Self::MlDsa44 => &ML_DSA_44_SIGNING,
            Self::MlDsa65 => &ML_DSA_65_SIGNING,
            Self::MlDsa87 => &ML_DSA_87_SIGNING,
        }
    }

    fn scheme(&self) -> SignatureScheme {
        match self {
            Self::MlDsa44 => SignatureScheme::ML_DSA_44,
            Self::MlDsa65 => SignatureScheme::ML_DSA_65,
            Self::MlDsa87 => SignatureScheme::ML_DSA_87,
        }
    }

    fn alg_id(&self) -> AlgorithmIdentifier {
        match self {
            Self::MlDsa44 => alg_id::ML_DSA_44,
            Self::MlDsa65 => alg_id::ML_DSA_65,
            Self::MlDsa87 => alg_id::ML_DSA_87,
        }
    }
}
pub(crate) static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ECDSA_P521_SHA256,
        webpki_algs::ECDSA_P521_SHA384,
        webpki_algs::ECDSA_P521_SHA512,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
        webpki_algs::ML_DSA_44,
        webpki_algs::ML_DSA_65,
        webpki_algs::ML_DSA_87,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
                webpki_algs::ECDSA_P521_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
                webpki_algs::ECDSA_P521_SHA256,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[
                webpki_algs::ECDSA_P521_SHA512,
                webpki_algs::ECDSA_P384_SHA512,
                webpki_algs::ECDSA_P256_SHA512,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),

        (SignatureScheme::ML_DSA_44, &[webpki_algs::ML_DSA_44]),

        (SignatureScheme::ML_DSA_65, &[webpki_algs::ML_DSA_65]),

        (SignatureScheme::ML_DSA_87, &[webpki_algs::ML_DSA_87]),
    ],
};