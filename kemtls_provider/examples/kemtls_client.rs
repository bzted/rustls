use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
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

#[derive(Parser, Debug)]
#[command(about = "Cliente KEMTLS/DTLS 1.3")]
struct ClientArgs {
    /// KX group to use (e.g. MLKEM768, BikeL3, Hqc192, NtruPrimeSntrup761)
    #[arg(short, long)]
    group: Option<String>,

    /// KEM algorithm to use for client authentication
    #[arg(short, long, default_value = "MLKEM768")]
    authkem: String,

    /// Optional CID value to offer in DTLS (0-255)
    #[arg(short, long)]
    cid: Option<u8>,

    /// Maximum fragment length for DTLS
    #[arg(short = 'L', long, default_value_t = 1400)]
    max_fragment_length: usize,

    /// Disables client authentication
    #[arg(short = 'd', long = "client_auth", default_value_t = true, action = clap::ArgAction::SetFalse)]
    client_auth: bool,

    /// Port to connect to
    #[arg(short, long, default_value_t = 8443)]
    port: u16,

    /// Address to connect to
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
}

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

fn setup_udp_socket(server_addr: &str) -> Result<UdpSocket, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    socket.connect(server_addr)?;
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

    while conn.is_handshaking() {
        send_dtls_datagram(socket, conn)?;

        match socket.recv(&mut in_buf) {
            Ok(n) => {
                conn.read_tls(&mut &in_buf[..n])?;
                conn.process_new_packets()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                conn.process_new_packets()?;
            }
            Err(e) => return Err(Box::new(e)),
        }
    }
    println!("DTLS handshake completed");
    Ok(())
}

fn send_http_request(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
    request: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    conn.writer().write_all(request)?;
    send_dtls_datagram(socket, conn)?;
    Ok(())
}

fn receive_http_response(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut in_buf = [0u8; BUFFER_SIZE];
    let mut plaintext = Vec::new();
    
    loop {
        let mut tmp = [0u8; BUFFER_SIZE];
        // Try to read already decrypted data
        {
            let mut reader = conn.reader();
            match reader.read(&mut tmp) {
                Ok(0) => {
                    // No data available yet
                }
                Ok(n) => {
                    plaintext.extend_from_slice(&tmp[..n]);
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
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = setup_udp_socket(server_addr)?;
    let mut conn = ClientConnection::new_dtls(Arc::new(client_config), server_name)?;

    // Perform DTLS handshake
    perform_dtls_handshake(&socket, &mut conn)?;

    // Send HTTP request
    let request = b"Hello from DTLS client\n";
    send_http_request(&socket, &mut conn, request)?;

    // Receive and display response
    let response = receive_http_response(&socket, &mut conn)?;

    println!("Response received:");
    println!("{}", String::from_utf8_lossy(&response));

    Ok(())
}

fn run_tls_client(
    client_config: ClientConfig,
    server_name: rustls::pki_types::ServerName<'static>,
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ClientConnection::new(Arc::new(client_config), server_name)?;
    println!("Connecting to server at {}", server_addr);
    let mut stream = TcpStream::connect(server_addr)?;
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
        println!("Using DTLS 1.3");
        use_dtls = true;
    }

    let args = ClientArgs::parse();

    let mut crypto_provider = provider();

    if let Some(ref group_name) = args.group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name);
    } else {
        debug!("Using all available KX groups");
    }

    let kemalg = match get_kem_algorithm(&args.authkem) {
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

    let mut client_config = match args.client_auth {
        true => ClientConfig::builder_with_provider(crypto_provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_cert_resolver(resolver),
        false => ClientConfig::builder_with_provider(crypto_provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_no_client_auth()
    };
    
    let server_addr = format!("{}:{}", args.addr, args.port);
    let server_name = "servername".try_into().unwrap();

    let result = if use_dtls {
        println!("Max fragment size set to: {}", args.max_fragment_length);
        client_config.max_fragment_size = Some(args.max_fragment_length);

        if let Some(cid_val) = args.cid {
            println!("Offering CID: {}", cid_val);
            client_config.set_cid(&[cid_val]);
        }
        run_dtls_client(client_config, server_name, &server_addr)
    } else {
        run_tls_client(client_config, server_name, &server_addr)
    };

    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}
