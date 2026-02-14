use kemtls_provider::resolver::{KeyPair, ServerCertResolver};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ServerVerifier;
use kemtls_provider::{get_kx_group_by_name, provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::crypto::CryptoProvider;
use rustls::server::Acceptor;
use rustls::{ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

const BUFFER_SIZE: usize = 4096;
const SERVER_PORT: u16 = 8443;
const TIMEOUT_SECS: u64 = 1;
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
                                Connection: closed\r\n\
                                Content-Type: text/html\r\n\
                                \r\n\
                                <h1>Hello Authenticated World!</h1>\r\n";
const DTLS_HTTP_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World, I'm using DTLS 1.3!";

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

fn create_server_config(
    kemalg: oqs::kem::Algorithm,
    crypto_provider: CryptoProvider,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let kem = Kem::new(kemalg)?;
    let (public_key, secret_key) = kem.keypair()?;

    let signing_key = Arc::new(DummySigningKey);
    let kem_key = Arc::new(MlKemKey::new(kemalg, secret_key.as_ref().to_vec()));
    let key_pair = KeyPair::new(public_key, signing_key, Some(kem_key));

    let resolver = Arc::new(ServerCertResolver::new(key_pair));
    let client_verifier = Arc::new(ServerVerifier::new(kemalg));

    let mut server_config = ServerConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(resolver);

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    debug!("Server config created successfully");
    Ok(server_config)
}

// TLS Helper Functions

fn handle_tls_client(
    mut stream: TcpStream,
    server_config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut acceptor = Acceptor::default();

    let accepted = loop {
        acceptor.read_tls(&mut stream)?;
        match acceptor.accept() {
            Ok(Some(accepted)) => break accepted,
            Ok(None) => continue,
            Err((err, mut alert)) => {
                debug!("Error in handshake: {:?}", err);
                let mut out = Vec::new();
                if let Err(write_err) = alert.write(&mut out) {
                    debug!("Error writing alert: {:?}", write_err);
                } else {
                    let _ = stream.write_all(&out);
                }
                return Err(format!("Handshake error: {:?}", err).into());
            }
        }
    };

    let mut conn = match accepted.into_connection(server_config.into()) {
        Ok(conn) => conn,
        Err((err, mut alert)) => {
            debug!("Error creating connection: {:?}", err);
            let mut out = Vec::new();
            if let Err(write_err) = alert.write(&mut out) {
                debug!("Error writing alert: {:?}", write_err);
            } else {
                let _ = stream.write_all(&out);
            }
            return Err(format!("Connection error: {:?}", err).into());
        }
    };

    // Send HTTP response
    conn.writer().write_all(HTTP_RESPONSE)?;
    conn.write_tls(&mut stream)?;
    conn.complete_io(&mut stream)?;

    // Close connection gracefully
    conn.send_close_notify();
    conn.write_tls(&mut stream)?;

    Ok(())
}

fn run_tls_server(server_config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("[::]:{}", SERVER_PORT))?;
    println!("TLS server listening on port {}", SERVER_PORT);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_tls_client(stream, server_config.clone()) {
                    debug!("Error handling TLS client: {:?}", e);
                }
            }
            Err(e) => {
                debug!("Error accepting connection: {:?}", e);
            }
        }
    }

    Ok(())
}

// DTLS Helper Functions

fn send_dtls_response(
    socket: &UdpSocket,
    conn: &mut ServerConnection,
    client_addr: SocketAddr,
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    conn.writer().write_all(response)?;

    let mut out_buf = Vec::new();
    conn.write_tls(&mut out_buf)?;

    socket.send_to(&out_buf, client_addr)?;

    Ok(())
}

fn handle_dtls_connection(
    socket: &UdpSocket,
    mut acceptor: Acceptor,
    server_config: ServerConfig,
    buffer: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let (accepted, client_addr) = loop {
        let (len, client_addr) = match socket.recv_from(buffer) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(());
            }
            Err(e) => return Err(Box::new(e))
        }; 

        acceptor.read_tls(&mut &buffer[..len])?;

        match acceptor.accept() {
            Ok(Some(accepted)) => break (accepted, client_addr),
            Ok(None) => continue,
            Err((err, mut alert)) => {
                debug!("Error in handshake: {:?}", err);
                let mut out = Vec::new();
                if let Err(write_err) = alert.write(&mut out) {
                    debug!("Error writing alert: {:?}", write_err);
                } else {
                    let _ = socket.send_to(&out, client_addr);
                }
                return Err(format!("Handshake error: {:?}", err).into());
            }
        }
    };

    let mut conn = match accepted.into_connection(server_config.into()) {
        Ok(conn) => conn,
        Err((err, mut alert)) => {
            debug!("Error creating connection: {:?}", err);
            let mut out = Vec::new();
            if let Err(write_err) = alert.write(&mut out) {
                debug!("Error writing alert: {:?}", write_err);
            } else {
                let _ = socket.send_to(&out, client_addr);
            }
            return Err(format!("Connection error: {:?}", err).into());
        }
    };

    while conn.is_handshaking() {
        while conn.wants_write() {
            let mut out_buf = Vec::new();
            conn.write_tls(&mut out_buf)?;
            if !out_buf.is_empty() {
                socket.send_to(&out_buf, client_addr)?;
            }
        }

        match socket.recv_from(buffer){
            Ok((len, addr)) =>{
                if addr != client_addr {
                    debug!("Addres missmatch");
                    continue;
                } 
            conn.read_tls(&mut &buffer[..len])?;
            conn.process_new_packets()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock =>{
            conn.process_new_packets()?;
        }    
        Err(e) =>{
            return Err(Box::new(e))
        } 
        } 
    }

    debug!("Handshake completed!");

    send_dtls_response(socket, &mut conn, client_addr, DTLS_HTTP_RESPONSE)?;

    Ok(())
}

fn run_dtls_server(server_config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(format!("[::]:{}", SERVER_PORT))?;
    socket.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;
    socket.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;

    socket.set_nonblocking(false)?;
    println!("DTLS server listening on port {}", SERVER_PORT);

    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let acceptor = Acceptor::default();

        if let Err(e) =
            handle_dtls_connection(&socket, acceptor, server_config.clone(), &mut buffer)
        {
            debug!("Error handling DTLS connection: {:?}", e);
            continue;
        }
    }
}

fn main() {
    env_logger::init();

    let use_dtls = cfg!(feature = "dtls13");
    if use_dtls {
        debug!("Using DTLS 1.3");
    }

    let mut args = std::env::args();
    args.next();

    let mut group = None;
    let mut authkem = None;
    let mut cid = None;
    let mut max_fragment_length = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-group" => {
                group = args.next();
                if group.is_none() {
                    debug!("Error: -group requires a group name");
                    std::process::exit(1);
                }
            }
            "-authkem" => {
                authkem = args.next();
                if authkem.is_none() {
                    debug!("Error: -authkem requires an algorithm name");
                    std::process::exit(1);
                }
            }
            "-cid" => {
                let cid_str = args.next();
                if cid_str.is_none() {
                    eprintln!("Error: -cid requires an integer value");
                    std::process::exit(1);
                }
                match cid_str.unwrap().parse::<u8>() {
                    Ok(val) => cid = Some(val),
                    Err(_) => {
                        eprintln!("Error: -cid must be a valid integer");
                        std::process::exit(1);
                    }
                }
            }
            "-L" => {
                let length_str = args.next();
                if length_str.is_none() {
                    eprintln!("Error: -L requires a length value");
                    std::process::exit(1);
                }
                match length_str.unwrap().parse::<usize>() {
                    Ok(val) => max_fragment_length = Some(val),
                    Err(_) => {
                        eprintln!("Error: -L must be a valid integer");
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                debug!("Error: Unknown argument '{}'", arg);
                std::process::exit(1);
            }
        }
    }

    let authkem = authkem.unwrap_or_else(|| "MLKEM768".to_string());

    debug!("Starting AuthKEM server...");

    let kemalg = match get_kem_algorithm(&authkem) {
        Ok(alg) => {
            println!("Selected KEM for authentication: {}", alg);
            alg
        }
        Err(e) => {
            debug!("Error with authkem algorithm: {}", e);
            std::process::exit(1);
        }
    };

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

    let mut server_config = match create_server_config(kemalg, crypto_provider) {
        Ok(config) => config,
        Err(e) => {
            debug!("Failed to create server config: {:?}", e);
            std::process::exit(1);
        }
    };

    let result = if use_dtls {
        if let Some(length) = max_fragment_length {
            println!("Setting max fragment size to: {}", length);
            server_config.max_fragment_size = Some(length);
        }

        if let Some(cid_val) = cid {
            println!("Offering CID: {}", cid_val);
            server_config.set_cid(&[cid_val]);
        }

        run_dtls_server(server_config)
    } else {
        run_tls_server(server_config)
    };

    if let Err(e) = result {
        debug!("Server error: {:?}", e);
        std::process::exit(1);
    }
}
