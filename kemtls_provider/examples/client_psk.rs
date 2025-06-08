use kemtls_provider::psk_key::{self, PskKey};
use kemtls_provider::resolver::{ClientCertResolver, KeyPair};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ClientVerifier;
use kemtls_provider::{provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::{ClientConfig, ClientConnection};
use std::convert::TryInto;
use std::fs;
use std::io::{stdout, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

fn main() {
    env_logger::init();

    let server_verifier = Arc::new(ClientVerifier);

    let crypto_provider = provider();

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

    // get servers pk from file
    let public_key = fs::read("keys/spk.bin").expect("failed to read servers public key");

    let psk = Arc::new(PskKey::new(public_key));

    let mut client_config = ClientConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_custom_authkem_psk_key(psk)
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_cert_resolver(resolver);
    //.with_no_client_auth();

    debug!("TRYING PSK");
    client_config.enable_early_data = true;

    let server_name = "servername".try_into().unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    debug!("Connecting to server at 127.0.0.1:8443...");
    let mut stream = TcpStream::connect("127.0.0.1:8443").unwrap();

    stream.set_nodelay(true).unwrap();

    let request = concat!(
        "GET / HTTP/1.1\n",
        "Host: www.rust-lang-org\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "\r\n"
    );

    // Send early data

    if let Some(mut early_data) = client.early_data() {
        early_data
            .write_all(request.as_bytes())
            .unwrap();
        println!(" * 0-RTT request sent * ");
    }

    let mut tls_stream = rustls::Stream::new(&mut client, &mut stream);

    tls_stream.flush().unwrap();

    // If the server didn't accept early data,
    // or we didn't send it as such, send the request as normal

    if !tls_stream.conn.is_early_data_accepted() {
        tls_stream
            .write_all(request.as_bytes())
            .unwrap();
        println!(" * Normal request sent * ");
    } else {
        println!(" * 0-RTT data accepted * ");
    }

    let mut response = String::new();
    BufReader::new(tls_stream)
        .read_line(&mut response)
        .unwrap();
    println!(" * Server response: {:?}", response);
}
