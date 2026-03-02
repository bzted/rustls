use kemtls_provider::provider;
use log::debug;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::Arc;
use rustls::ServerConnection;
use std::net::TcpStream;
use std::net::TcpListener;
use std::net::SocketAddr;
use std::time::Duration;
use clap::Parser;

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 1;
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
                                Connection: closed\r\n\
                                Content-Type: text/html\r\n\
                                \r\n\
                                <h1>Hello Authenticated World!</h1>\r\n";
const DTLS_HTTP_RESPONSE: &[u8] =
    b"Hello World, I'm using DTLS 1.3!";

#[derive(Parser, Debug)]
#[command(author, version, about = "Server with TLS 1.3 and DTLS 1.3 support", long_about = None)]
struct Args {
    /// KX group to use (e.g. MLKEM768, BikeL3, Hqc192, NtruPrimeSntrup761)
    #[arg(long)]
    group: Option<String>,

    /// Optional CID value to offer in DTLS (0-255)
    #[arg(long)]
    cid: Option<u8>,

    /// Maximum fragment length for DTLS
    #[arg(short = 'L', default_value_t = 1400)]
    max_fragment_length: usize,

    /// Disables client authentication
    #[arg(short = 'd', default_value_t = true, action = clap::ArgAction::SetFalse)]
    client_auth: bool,

    /// Certificate File
    #[arg(short = 'c', default_value = "../test-ca/rsa-2048/end.fullchain")]
    cert_file: String,

    /// Key file
    #[arg(short = 'k', default_value = "../test-ca/rsa-2048/end.key")]
    pk_file: String,

    /// Certificate Authority file
    #[arg(short = 'A', default_value = "../test-ca/rsa-2048/ca.cert")]
    ca_file: String,

    /// Port to listen on 
    #[arg(short, long, default_value_t = 8443)]
    port: u16,

    /// Activates PQC provider
    #[arg(short = 'q' ,long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pqc_provider: bool,
}

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

fn run_tls_server(server_config: ServerConfig, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("[::]:{}", port))?;
    println!("TLS server listening on port {}", port);

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
    debug!("Response sent to client {}", client_addr);

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
        debug!("Received {} bytes from {}", len, client_addr);

        let mut slice = &buffer[..len];
        while !slice.is_empty() {
            acceptor.read_tls(&mut slice)?;
        }

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
                debug!("Sent {} bytes to {}", out_buf.len(), client_addr);
            }
        }

        match socket.recv_from(buffer){
            Ok((len, addr)) =>{
                if addr != client_addr {
                    debug!("Addres missmatch");
                    continue;
                } 
                let mut slice = &buffer[..len];
                while !slice.is_empty() {
                    conn.read_tls(&mut slice)?;
                }
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

    while conn.wants_write() {
        let mut out_buf = Vec::new();
        conn.write_tls(&mut out_buf)?;
        if !out_buf.is_empty() {
            socket.send_to(&out_buf, client_addr)?;
        }
    }

    let (len, addr) = socket.recv_from(buffer)?;
    if addr == client_addr {
        let mut slice = &buffer[..len];
        while !slice.is_empty() {
            conn.read_tls(&mut slice)?;
        }
        let io_state = conn.process_new_packets()?;
        
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut reader = conn.reader();
            let mut msg = vec![0u8; io_state.plaintext_bytes_to_read()];
            let n = reader.read(&mut msg)?;
            println!("Client says: {:?}", String::from_utf8_lossy(&msg[..n]));
        }
    }

    send_dtls_response(socket, &mut conn, client_addr, DTLS_HTTP_RESPONSE)?;

    while let Ok((len, addr)) = socket.recv_from(buffer) {
        if addr == client_addr {
            let mut slice = &buffer[..len];
            while !slice.is_empty() {
                conn.read_tls(&mut slice)?;
            }
            let io_state = conn.process_new_packets()?;
            
            if io_state.plaintext_bytes_to_read() > 0 {
                let mut reader = conn.reader();
                let mut msg = vec![0u8; io_state.plaintext_bytes_to_read()];
                let n = reader.read(&mut msg)?;
                println!("Client says: {:?}", String::from_utf8_lossy(&msg[..n]));
            }
        }
    }
    
    Ok(())
}

fn run_dtls_server(server_config: ServerConfig, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(format!("[::]:{}", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;
    socket.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;

    socket.set_nonblocking(false)?;
    println!("DTLS server listening on port {}", port);

    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let acceptor = Acceptor::default();

        if let Err(e) =
            handle_dtls_connection(&socket, acceptor, server_config.clone(), &mut buffer)
        {
            debug!("Error handling DTLS connection: {:?}", e);
            return Err(e);
        }
    }
}
fn main() {
    env_logger::init();

    let use_dtls = cfg!(feature = "dtls13");
    if use_dtls {
        println!("Using DTLS 1.3");
    }

    println!("Starting traditional server...");
    let mut args = Args::parse();

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(args.ca_file)
            .expect("cannot open ca file")
            .map(|result| result.unwrap()),
    );

    let cert = rustls::pki_types::CertificateDer::pem_file_iter(&args.cert_file)
        .expect("Could not read certificate file")
        .map(|cert| cert.expect("Error reading certificate"))
        .collect();

    let pk = rustls::pki_types::PrivateKeyDer::from_pem_file(&args.pk_file).expect("Could not read private key file");

    let verifier = WebPkiClientVerifier::builder(root_store.into()).build().unwrap();
    // Set up TLS server with AuthKEM provider
    let crypto_provider = provider();

    let mut server_config = match (args.pqc_provider, args.client_auth) {
        (true, true) => {
            ServerConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert, pk).unwrap()
        }

        (true, false) => {
            ServerConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
                .with_no_client_auth()
                .with_single_cert(cert, pk).unwrap()
        }

        (false, true) => {
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert, pk).unwrap()
        }

        (false, false) => {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert, pk).unwrap()
        }
    };

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    // Disable session resumption for testing purposes
    server_config.send_tls13_tickets = 0;
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    println!("Server config created successfully");
    println!("Provider has {} kx_groups", server_config.crypto_provider().kx_groups.len());
    for kx in &server_config.crypto_provider().kx_groups {
        println!("  KX group: {:?}", kx.name());
    }

    let result = if use_dtls {
        println!("Setting max fragment size to: {}", args.max_fragment_length);
        server_config.max_fragment_size = Some(args.max_fragment_length);

        if let Some(cid_val) = args.cid {
            println!("Offering CID: {}", cid_val);
            server_config.set_cid(&[cid_val]);
        }
        run_dtls_server(server_config, args.port)
    } else {
            run_tls_server(server_config, args.port)
    };

    if let Err(e) = result {
        debug!("Server error: {:?}", e);
        std::process::exit(1);
    }
}
