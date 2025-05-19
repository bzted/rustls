use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use kemtls_provider::resolver::{ClientCertResolver, KeyPair};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ClientVerifier;
use kemtls_provider::{provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::{ClientConfig, ClientConnection};

fn main() {
    env_logger::init();

    let server_verifier = Arc::new(ClientVerifier);

    let crypto_provider = provider();

    debug!("Trying client authentication");

    let kem =
        Kem::new(oqs::kem::Algorithm::MlKem768).expect("Failed to create ML-KEM-768 instance");

    let (public_key, secret_key) = kem
        .keypair()
        .expect("Failed to generate KEM keypair");

    let signing_key = Arc::new(DummySigningKey);

    let kem_key = Arc::new(MlKemKey::new(
        rustls::NamedGroup::MLKEM768,
        secret_key.as_ref().to_vec(),
    ));

    // Create our key pair structure
    let key_pair = KeyPair::new(public_key, signing_key, Some(kem_key));

    // Create our custom resolver
    let resolver = Arc::new(ClientCertResolver::new(key_pair));

    let client_config = ClientConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_cert_resolver(resolver);

    let server_name = "servername".try_into().unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    debug!("Connecting to server at 127.0.0.1:8443...");
    let mut stream = TcpStream::connect("127.0.0.1:8443").unwrap();

    stream.set_nodelay(true).unwrap();

    let mut tls_stream = rustls::Stream::new(&mut client, &mut stream);

    tls_stream
        .write_all(
            concat!(
                "GET / HTTP/1.1\n",
                "Host: www.rust-lang-org\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();

    let cs = tls_stream
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        cs.suite()
    )
    .unwrap();

    let mut plaintext = Vec::new();
    tls_stream
        .read_to_end(&mut plaintext)
        .unwrap();
    stdout().write_all(&plaintext).unwrap();
}
