use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use kemtls_provider::resolver::{ClientCertResolver, KeyPair};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ClientVerifier;
use kemtls_provider::{get_kx_group_by_name, provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ClientConnection};

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 1;
const SERVER_ADDR: &str = "127.0.0.1:8443";

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

// DTLS Helper Functions

fn setup_udp_socket() -> Result<UdpSocket, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(SERVER_ADDR)?;
    socket.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;
    socket.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;
    Ok(socket)
}

fn send_dtls_datagram(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
) -> Result<(), std::io::Error> {
    while conn.wants_write() {
        let mut out = Vec::new();
        conn.write_tls(&mut out)?;
        if !out.is_empty() {
            debug!("Sending DTLS datagram of {} bytes", out.len());
            socket.send(&out)?;
        } else {
            break;
        }
    }
    Ok(())
}

fn receive_dtls_datagram(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
    buffer: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    /*let n = socket.recv(buffer)?;
    conn.read_tls(&mut &buffer[..n])?;
    conn.process_new_packets()?;
    Ok(())*/
    match socket.recv(buffer){
        Ok(n) =>{
            conn.read_tls(&mut &buffer[..n])?;
            conn.process_new_packets()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock =>{
            conn.process_new_packets()?;
        }    
        Err(e) =>{
            return Err(Box::new(e))
        } 
    }


    Ok(()) 
}

fn perform_dtls_handshake(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut in_buf = [0u8; BUFFER_SIZE];

    loop {
        send_dtls_datagram(socket, conn)?;

        if !conn.is_handshaking() {
            debug!("DTLS handshake completed");
            break;
        }

        receive_dtls_datagram(socket, conn, &mut in_buf)?;
    }

    Ok(())
}

fn send_http_request(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
    request: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    conn.writer().write_all(request)?;
    send_dtls_datagram(socket, conn)?;
    debug!("HTTP request sent");
    Ok(())
}

fn receive_http_response(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut in_buf = [0u8; BUFFER_SIZE];
    let mut plaintext = Vec::new();
    let mut tmp = [0u8; BUFFER_SIZE];

    loop {
        // Try to read already decrypted data
        {
            let mut reader = conn.reader();
            match reader.read(&mut tmp) {
                Ok(0) => {
                    // No data available yet
                }
                Ok(n) => {
                    plaintext.extend_from_slice(&tmp[..n]);
                    debug!("Read {} bytes of plaintext", n);
                    // Continue reading if there might be more data
                    if plaintext.len() > 0 && n < BUFFER_SIZE {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data ready, need to receive more datagrams
                }
                Err(e) => return Err(Box::new(e)),
            }
        }

        // Receive more datagrams if needed
        if plaintext.is_empty() {
            receive_dtls_datagram(socket, conn, &mut in_buf)?;
        } else {
            break;
        }
    }

    Ok(plaintext)
}

fn run_dtls_client(
    client_config: ClientConfig,
    server_name: rustls::pki_types::ServerName<'static>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = setup_udp_socket()?;
    let mut conn = ClientConnection::new_dtls(Arc::new(client_config), server_name)?;

    // Perform DTLS handshake
    perform_dtls_handshake(&socket, &mut conn)?;

    // Send HTTP request
    let request = b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n";
    send_http_request(&socket, &mut conn, request)?;

    // Receive and display response
    println!("Waiting for response...");
    let response = receive_http_response(&socket, &mut conn)?;

    println!("Response received:");
    println!("{}", String::from_utf8_lossy(&response));

    Ok(())
}

fn run_tls_client(
    client_config: ClientConfig,
    server_name: rustls::pki_types::ServerName<'static>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ClientConnection::new(Arc::new(client_config), server_name)?;
    debug!("Connecting to server at {}...", SERVER_ADDR);
    let mut stream = TcpStream::connect(SERVER_ADDR)?;
    stream.set_nodelay(true)?;

    let mut tls_stream = rustls::Stream::new(&mut client, &mut stream);

    tls_stream.write_all(
        concat!(
            "GET / HTTP/1.1\n",
            "Host: www.rust-lang-org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )?;

    let cs = tls_stream
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        cs.suite()
    )?;

    let mut plaintext = Vec::new();
    tls_stream.read_to_end(&mut plaintext)?;
    stdout().write_all(&plaintext)?;

    Ok(())
}

fn main() {
    env_logger::init();

    let mut use_dtls = false;
    if cfg!(feature = "dtls13") {
        debug!("Using DTLS 1.3");
        use_dtls = true;
    }

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

    let mut crypto_provider = provider();

    if let Some(ref group_name) = group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name);
    } else {
        debug!("Using all available KX groups");
    }

    debug!("Trying client authentication");

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

    let client_config = ClientConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_cert_resolver(resolver);

    let server_name = "servername".try_into().unwrap();

    let result = if use_dtls {
        run_dtls_client(client_config, server_name)
    } else {
        run_tls_client(client_config, server_name)
    };

    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}
