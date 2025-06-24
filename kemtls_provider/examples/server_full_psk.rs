use kemtls_provider::resolver::{KeyPair, ServerCertResolver};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ServerVerifier;
use kemtls_provider::{provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::{NamedGroup, ServerConfig};
use std::io::{Read, Write};
use std::sync::Arc;
use std::{fs, io};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    debug!("Starting AuthKEM server...");
    // Generate a server KEM key pair
    let kem =
        Kem::new(oqs::kem::Algorithm::MlKem768).expect("Failed to create ML-KEM-768 instance");

    let (public_key, secret_key) = kem
        .keypair()
        .expect("Failed to generate KEM key pair");

    fs::create_dir_all("keys").expect("Couldn't create keys directory");
    // Write servers pk to a file
    fs::write("keys/spk.bin", &public_key).expect("failed to write servers public key");

    let signing_key = Arc::new(DummySigningKey);

    let kem_key = Arc::new(MlKemKey::new(
        NamedGroup::MLKEM768,
        secret_key.as_ref().to_vec(),
    ));
    // Create our key pair structure
    let key_pair = KeyPair::new(public_key, signing_key, Some(kem_key));

    // Create our custom resolver
    let resolver = Arc::new(ServerCertResolver::new(key_pair));

    // Create our custom verifier
    let client_verifier = Arc::new(ServerVerifier::new());

    // Set up TLS server with AuthKEM provider
    let crypto_provider = provider();

    debug!("Provider has {} kx_groups", crypto_provider.kx_groups.len());
    for kx in &crypto_provider.kx_groups {
        debug!("  KX group: {:?}", kx.name());
    }

    let mut server_config = ServerConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        //.with_no_client_auth()
        .with_cert_resolver(resolver);

    server_config.max_early_data_size = 1000;
    debug!("Server config created successfully");

    let listener = std::net::TcpListener::bind(format!("[::]:{}", 8443)).unwrap();

    loop {
        let (mut stream, _) = listener.accept()?;

        println!("Accepting connection");

        let mut conn = rustls::ServerConnection::new(Arc::new(server_config.clone()))?;

        let mut buf = Vec::new();
        let mut did_early_data = false;
        'handshake: while conn.is_handshaking() {
            while conn.wants_write() {
                if conn.write_tls(&mut stream)? == 0 {
                    // EOF
                    stream.flush()?;
                    break 'handshake;
                }
            }
            stream.flush()?;

            while conn.wants_read() {
                match conn.read_tls(&mut stream) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                    Ok(_) => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => return Err(err.into()),
                };
            }

            if let Err(e) = conn.process_new_packets() {
                let _ignored = conn.write_tls(&mut stream);
                stream.flush()?;

                return Err(io::Error::new(io::ErrorKind::InvalidData, e).into());
            };

            if let Some(mut early_data) = conn.early_data() {
                if !did_early_data {
                    println!("Receiving early data from client");
                    did_early_data = true;
                }

                let bytes_read = early_data
                    .read_to_end(&mut buf)
                    .unwrap();

                if bytes_read != 0 {
                    println!("Early data from client: {:?}", buf);
                }
            }
        }

        if !did_early_data {
            println!("Did not receive early data from client");
        }

        println!("Handshake complete\n");

        conn.writer()
            .write_all(b"Hello from server\n")?;
        conn.send_close_notify();
        conn.complete_io(&mut stream)?;
    }
}
