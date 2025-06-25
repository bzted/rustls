use kemtls_provider::psk_key::PskKey;
use kemtls_provider::resolver::{ClientCertResolver, KeyPair};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ClientVerifier;
use kemtls_provider::{get_kx_group_by_name, provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ClientConnection};
use std::convert::TryInto;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
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
    let mut early_auth = false;

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
            "-early_auth" => {
                early_auth = true;
                debug!("Early authentication enabled");
            }
            _ => {
                eprintln!("Error: Unknown argument '{}'", arg);
                std::process::exit(1);
            }
        }
    }

    // If authkem algorithm not provided, we use MLKEM768 as default
    let authkem = authkem.unwrap_or_else(|| "MLKEM768".to_string());

    let mut crypto_provider = provider();

    if let Some(ref group_name) = group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name);
    } else {
        debug!("Using all available KX groups");
    }

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

    let server_verifier = Arc::new(ClientVerifier::new(kemalg));

    let kem = Kem::new(kemalg).expect("Failed to create kem instance");

    let (public_key, secret_key) = kem
        .keypair()
        .expect("Failed to generate KEM keypair");

    let signing_key = Arc::new(DummySigningKey);

    let kem_key = Arc::new(MlKemKey::new(kemalg, secret_key.as_ref().to_vec()));

    // Create our key pair structure
    let key_pair = KeyPair::new(public_key, signing_key, Some(kem_key));

    // Create our custom resolver
    let resolver = Arc::new(ClientCertResolver::new(key_pair));

    // get servers pk from file
    let public_key = fs::read("keys/spk.bin").expect("failed to read servers public key");

    let psk = Arc::new(PskKey::new(public_key, kemalg));

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

    if early_auth {
        client_config.early_auth = true;
        println!("Early authentication activated");
    } else {
        println!("Early authentication disabled");
    }

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
