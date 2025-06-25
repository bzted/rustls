use kemtls_provider::resolver::{KeyPair, ServerCertResolver};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ServerVerifier;
use kemtls_provider::{get_kx_group_by_name, provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::crypto::CryptoProvider;
use rustls::server::Acceptor;
use rustls::ServerConfig;
use std::io::Write;
use std::sync::Arc;

fn get_kem_algorithm(algorithm: &str) -> Result<oqs::kem::Algorithm, String> {
    match algorithm.to_uppercase().as_str() {
        "MLKEM512" => Ok(oqs::kem::Algorithm::MlKem512),
        "MLKEM768" => Ok(oqs::kem::Algorithm::MlKem768),
        "MLKEM1024" => Ok(oqs::kem::Algorithm::MlKem1024),
        "BIKEL1" => Ok(oqs::kem::Algorithm::BikeL1),
        "BIKEL3" => Ok(oqs::kem::Algorithm::BikeL3),
        "BIKEL5" => Ok(oqs::kem::Algorithm::BikeL5),
        "HQC128" => Ok(oqs::kem::Algorithm::Hqc128),
        "HQC192" => Ok(oqs::kem::Algorithm::Hqc192),
        "HQC256" => Ok(oqs::kem::Algorithm::Hqc256),
        "NTRUPRIMESNTRUP761" => Ok(oqs::kem::Algorithm::NtruPrimeSntrup761),
        _ => Err(format!("Unknown group: {}", algorithm)),
    }
}

fn select_kx_group(crypto_provider: &mut CryptoProvider, group: &str) {
    if let Some(selected_group) = get_kx_group_by_name(group) {
        crypto_provider.kx_groups = vec![selected_group];
    } else {
        println!("Unknown group, using default groups");
        println!("Available groups: MLKEM512, MLKEM768, MLKEM1024, BikeL1, BikeL3, BikeL5, Hqc128, Hqc192, Hqc256, NtruPrimeSntrup761");
    }
}

fn main() {
    env_logger::init();

    let mut args = std::env::args();
    args.next();

    let mut group = None;
    let mut authkem = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-group" => {
                group = args.next();
                if group.is_none() {
                    eprintln!("Error: -group requires a group name");
                    std::process::exit(1);
                }
            }
            "-authkem" => {
                authkem = args.next();
                if authkem.is_none() {
                    eprintln!("Error: -auth requires an algorithm name");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("Error: Unknown argument '{}'", arg);
                std::process::exit(1);
            }
        }
    }

    // If authkem algorithm not provided, we use MLKEM768 as default
    let authkem = authkem.unwrap_or_else(|| "MLKEM768".to_string());

    debug!("Starting AuthKEM server...");
    // Generate a server KEM key pair
    let kemalg = match get_kem_algorithm(&authkem) {
        Ok(alg) => {
            println!("Selected KEM for authentication: {}", alg);
            alg
        }
        Err(e) => {
            eprintln!("Error with authkem algorithm: {}", e);
            std::process::exit(1);
        }
    };

    let kem = Kem::new(kemalg).expect("Failed to create kem instance");

    let (public_key, secret_key) = kem
        .keypair()
        .expect("Failed to generate KEM key pair");

    let signing_key = Arc::new(DummySigningKey);

    let kem_key = Arc::new(MlKemKey::new(kemalg, secret_key.as_ref().to_vec()));
    // Create our key pair structure
    let key_pair = KeyPair::new(public_key, signing_key, Some(kem_key));

    // Create our custom resolver
    let resolver = Arc::new(ServerCertResolver::new(key_pair));

    // Create our custom verifier
    let client_verifier = Arc::new(ServerVerifier::new(kemalg));

    // Set up TLS server with AuthKEM provider
    let mut crypto_provider = provider();

    if let Some(ref group_name) = group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name);
    } else {
        debug!("Using all available KX groups");
    }

    debug!("Provider has {} kx_groups", crypto_provider.kx_groups.len());
    for kx in &crypto_provider.kx_groups {
        debug!("  KX group: {:?}", kx.name());
    }

    let mut server_config = ServerConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(client_verifier)
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
                    "<h1>Hello Authenticated World!</h1>\r\n"
                )
                .as_bytes();

                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
            }
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }
}
