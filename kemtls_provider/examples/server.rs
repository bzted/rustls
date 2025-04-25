use kemtls_provider::resolver::{KeyPair, Resolver};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::{provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::server::Acceptor;
use rustls::{NamedGroup, ServerConfig};
use std::io::Write;
use std::sync::Arc;

fn main() {
    env_logger::init();

    debug!("Starting AuthKEM server...");
    // Generate a server KEM key pair
    let kem =
        Kem::new(oqs::kem::Algorithm::MlKem768).expect("Failed to create ML-KEM-768 instance");

    let (public_key, secret_key) = kem
        .keypair()
        .expect("Failed to generate KEM key pair");

    let signing_key = Arc::new(DummySigningKey);

    let kem_key = Arc::new(MlKemKey::new(
        NamedGroup::MLKEM768,
        secret_key.as_ref().to_vec(),
    ));
    // Create our key pair structure
    let key_pair = KeyPair::new(public_key, signing_key, Some(kem_key));

    // Create our custom resolver
    let resolver = Arc::new(Resolver::new(key_pair));

    // Set up TLS server with AuthKEM provider
    let crypto_provider = provider();

    debug!("Provider has {} kx_groups", crypto_provider.kx_groups.len());
    for kx in &crypto_provider.kx_groups {
        debug!("  KX group: {:?}", kx.name());
    }

    let mut server_config = ServerConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    debug!("Server config created successfully");

    let listener = std::net::TcpListener::bind(format!("[::]:{}", 8443)).unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone().into()) {
            Ok(mut conn) => {
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }
}
