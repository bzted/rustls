use log::debug;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::Error;
use rustls::NamedGroup;
use std::sync::Arc;

fn algorithm_for_group(group: NamedGroup) -> Result<(oqs::kem::Algorithm, bool), Error> {
    match group {
        NamedGroup::MLKEM512 => Ok((oqs::kem::Algorithm::MlKem512, false)),
        NamedGroup::MLKEM768 => Ok((oqs::kem::Algorithm::MlKem768, false)),
        NamedGroup::MLKEM1024 => Ok((oqs::kem::Algorithm::MlKem1024, false)),
        NamedGroup::BikeL1 => Ok((oqs::kem::Algorithm::BikeL1, false)),
        NamedGroup::BikeL3 => Ok((oqs::kem::Algorithm::BikeL3, false)),
        NamedGroup::BikeL5 => Ok((oqs::kem::Algorithm::BikeL5, false)),
        NamedGroup::Hqc128 => Ok((oqs::kem::Algorithm::Hqc128, false)),
        NamedGroup::Hqc192 => Ok((oqs::kem::Algorithm::Hqc192, false)),
        NamedGroup::Hqc256 => Ok((oqs::kem::Algorithm::Hqc256, false)),
        NamedGroup::NtruPrimeSntrup761 => Ok((oqs::kem::Algorithm::NtruPrimeSntrup761, false)),
        NamedGroup::X25519MLKEM512 => Ok((oqs::kem::Algorithm::MlKem512, true)),
        NamedGroup::X25519MLKEM768 => Ok((oqs::kem::Algorithm::MlKem768, true)),
        NamedGroup::X25519MLKEM1024 => Ok((oqs::kem::Algorithm::MlKem1024, true)),
        NamedGroup::X25519BikeL1 => Ok((oqs::kem::Algorithm::BikeL1, true)),
        NamedGroup::X25519BikeL3 => Ok((oqs::kem::Algorithm::BikeL3, true)),
        NamedGroup::X25519BikeL5 => Ok((oqs::kem::Algorithm::BikeL5, true)),
        NamedGroup::X25519Hqc128 => Ok((oqs::kem::Algorithm::Hqc128, true)),
        NamedGroup::X25519Hqc192 => Ok((oqs::kem::Algorithm::Hqc192, true)),
        NamedGroup::X25519Hqc256 => Ok((oqs::kem::Algorithm::Hqc256, true)),
        NamedGroup::X25519NtruPrimeSntrup761 => Ok((oqs::kem::Algorithm::NtruPrimeSntrup761, true)),
        _ => Err(Error::General("Unsupported KEMTLS group".into())),
    }
}

fn pq_public_key_len(algorithm: oqs::kem::Algorithm) -> usize {
    match algorithm {
        oqs::kem::Algorithm::MlKem512 => 800,
        oqs::kem::Algorithm::MlKem768 => 1184,
        oqs::kem::Algorithm::MlKem1024 => 1568,
        oqs::kem::Algorithm::BikeL1 => 1541,
        oqs::kem::Algorithm::BikeL3 => 3083,
        oqs::kem::Algorithm::BikeL5 => 5122,
        oqs::kem::Algorithm::Hqc128 => 2249,
        oqs::kem::Algorithm::Hqc192 => 4522,
        oqs::kem::Algorithm::Hqc256 => 7245,
        oqs::kem::Algorithm::NtruPrimeSntrup761 => 1158,
        _ => todo!(),
    }
}

#[derive(Debug)]
pub struct ClientVerifier {
    x25519_sk: Option<[u8; 32]>,
    x25519_pk: Option<[u8; 32]>,
}

impl ClientVerifier {
    pub fn new(x25519_sk: Option<[u8; 32]>, x25519_pk: Option<[u8; 32]>) -> Self {
        ClientVerifier { x25519_sk, x25519_pk }
    }

    fn encapsulation_params(
        &self,
        selected_group: Option<NamedGroup>,
    ) -> Result<(oqs::kem::Algorithm, bool), Error> {
        match selected_group {
            Some(group) => {
                let (algorithm, hybrid) = algorithm_for_group(group)?;
                Ok((algorithm, hybrid))
            }
            None => Err(Error::General("No selected KEMTLS group".into())),
        }
    }
}

impl ServerCertVerifier for ClientVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now_time: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls12_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls13_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        debug!("supported_verify_schemes called");
        Vec::new()
    }

    fn requires_raw_public_keys(&self) -> bool {
        debug!("requires_raw_public_keys called - returning true");
        true
    }

    fn encapsulate(
        &self,
        selected_group: Option<NamedGroup>,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        debug!("About to encapsulate to servers public key");
        let (algorithm, is_hybrid) = self.encapsulation_params(selected_group)?;

        if is_hybrid {
            let (sk, pk) = match (self.x25519_sk, self.x25519_pk) {
                (Some(sk), Some(pk)) => (sk, pk),
                _ => {
                    return Err(Error::General(
                        "Negotiated hybrid KEMTLS group requires X25519 material".into(),
                    ))
                }
            };
            debug!("Using hybrid encapsulation flow");
            let (pq_pk_bytes, x25519_share) = server_pk.split_at(pq_public_key_len(algorithm));

            let kem = oqs::kem::Kem::new(algorithm)
                .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pq_pk = kem
                .public_key_from_bytes(pq_pk_bytes)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (pq_ct, pq_ss) = kem
                .encapsulate(pq_pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            let peer_pub = x25519_share.try_into().map_err(|_| Error::General("Invalid hybrid public key".into()))?;
            let x25519_ss = x25519_dalek::x25519(sk, peer_pub); 


            let ciphertext = [pq_ct.as_ref(), &pk].concat();
            let shared_secret = [pq_ss.into_vec(), x25519_ss.as_slice().to_vec()].concat();

            return Ok((ciphertext, shared_secret))
        } else {
            let kem = oqs::kem::Kem::new(algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pk = kem
                .public_key_from_bytes(server_pk)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (ct, ss) = kem
                .encapsulate(pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            return Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
    }
}

#[derive(Debug)]
pub struct ServerVerifier {
    root_hints: Vec<rustls::DistinguishedName>, // Decoded using x509-parser. Not used in AuthKem
    traditional_verifier: Option<Arc<dyn ClientCertVerifier>>,
    x25519_sk: Option<[u8; 32]>,
    x25519_pk: Option<[u8; 32]>,
}

impl ServerVerifier {
    pub fn new(
        traditional_verifier: Option<Arc<dyn ClientCertVerifier>>,
        x25519_sk: Option<[u8; 32]>,
        x25519_pk: Option<[u8; 32]>,
    ) -> Self {
        let root_hints = traditional_verifier
            .as_ref()
            .map(|verifier| verifier.root_hint_subjects().to_vec())
            .unwrap_or_else(|| vec![rustls::DistinguishedName::from(Vec::new())]);
        ServerVerifier {
            root_hints,
            traditional_verifier,
            x25519_sk,
            x25519_pk,
        }
    }

    fn encapsulation_params(
        &self,
        selected_group: Option<NamedGroup>,
    ) -> Result<(oqs::kem::Algorithm, bool), Error> {
        match selected_group {
            Some(group) => {
                let (algorithm, hybrid) = algorithm_for_group(group)?;
                Ok((algorithm, hybrid))
            }
            None => Err(Error::General("No selected KEMTLS group".into())),
        }
    }
}

impl ClientCertVerifier for ServerVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        debug!("root_hint_subjects called");
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, Error> {
        if x509_parser::parse_x509_certificate(end_entity.as_ref()).is_ok() {
            if let Some(verifier) = &self.traditional_verifier {
                return verifier.verify_client_cert(end_entity, intermediates, now);
            }

            return Err(Error::General(
                "received X.509 client certificate but no CA verifier is configured".into(),
            ));
        }

        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        if x509_parser::parse_x509_certificate(cert.as_ref()).is_ok() {
            if let Some(verifier) = &self.traditional_verifier {
                return verifier.verify_tls12_signature(message, cert, dss);
            }

            return Err(Error::General(
                "received X.509 client signature but no CA verifier is configured".into(),
            ));
        }

        debug!(
            "verify_tls12_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        if x509_parser::parse_x509_certificate(cert.as_ref()).is_ok() {
            if let Some(verifier) = &self.traditional_verifier {
                return verifier.verify_tls13_signature(message, cert, dss);
            }

            return Err(Error::General(
                "received X.509 client signature but no CA verifier is configured".into(),
            ));
        }

        debug!(
            "verify_tls13_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        debug!("supported_verify_schemes called");
        if let Some(verifier) = &self.traditional_verifier {
            verifier.supported_verify_schemes()
        } else {
            vec![rustls::SignatureScheme::ED25519]
        }
    }

    fn encapsulate(
        &self,
        selected_group: Option<NamedGroup>,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        debug!("About to encapsulate to clients public key");
        let (algorithm, is_hybrid) = self.encapsulation_params(selected_group)?;

        if is_hybrid {
            let (sk, pk) = match (self.x25519_sk, self.x25519_pk) {
                (Some(sk), Some(pk)) => (sk, pk),
                _ => {
                    return Err(Error::General(
                        "Negotiated hybrid KEMTLS group requires X25519 material".into(),
                    ))
                }
            };
            debug!("Using hybrid encapsulation flow");
            let (pq_pk_bytes, x25519_share) = client_pk.split_at(pq_public_key_len(algorithm));
            debug!("Extracted pq_pk_bytes of length {} and x25519_share of length {}", pq_pk_bytes.len(), x25519_share.len());

            let kem = oqs::kem::Kem::new(algorithm)
                .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pq_pk = kem
                .public_key_from_bytes(pq_pk_bytes)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (pq_ct, pq_ss) = kem
                .encapsulate(pq_pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            let peer_pub = x25519_share.try_into().map_err(|_| Error::General("Invalid hybrid public key".into()))?;
            let x25519_ss = x25519_dalek::x25519(sk, peer_pub); 


            let ciphertext = [pq_ct.as_ref(), &pk].concat();
            let shared_secret = [pq_ss.into_vec(), x25519_ss.as_slice().to_vec()].concat();

            return Ok((ciphertext, shared_secret))
        } else {
            let kem = oqs::kem::Kem::new(algorithm)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

            let pk = kem
                .public_key_from_bytes(client_pk)
                .ok_or_else(|| Error::General("Invalid public key".into()))?;
            let (ct, ss) = kem
                .encapsulate(pk)
                .map_err(|_| Error::General("Encapsulation failed".into()))?;

            return Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
    }
}
