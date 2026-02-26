use kemtls_provider::provider;
use log::debug;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use std::io::Write;
use std::net::UdpSocket;
use std::sync::Arc;
use rustls::ServerConnection;
use std::net::TcpStream;
use std::net::TcpListener;
use std::net::SocketAddr;
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
                debug!("Sent {} bytes to {}", out_buf.len(), client_addr);
            }
        }

        /*let (len, addr) = socket.recv_from(buffer)?;
        if addr != client_addr {
            debug!("Ignoring datagram from different address");
            continue;
        }

        debug!("Received {} bytes during handshake", len);
        conn.read_tls(&mut &buffer[..len])?;
        conn.process_new_packets()?;*/
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

fn main() /*-> Result<(), Box<dyn std::error::Error>>*/ {
    env_logger::init();

    let use_dtls = cfg!(feature = "dtls13");
    if use_dtls {
        debug!("Using DTLS 1.3");
    }

    debug!("Starting traditional server...");
    let mut args = std::env::args();
    args.next();

    let ca_file = args.next().expect("no cert file");

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(ca_file)
            .expect("cannot open ca file")
            .map(|result| result.unwrap()),
    );
    let cert_file = args.next().expect("no cert file");

    let pk_file = args.next().expect("no pk file");

    let cert = rustls::pki_types::CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();

    let pk = rustls::pki_types::PrivateKeyDer::from_pem_file(pk_file).unwrap();

    let verifier = WebPkiClientVerifier::builder(root_store.into()).build().unwrap();

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert, pk).unwrap();

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    debug!("Server config created successfully");

    let result = if use_dtls {
        run_dtls_server(server_config)
    } else {
        run_tls_server(server_config)
    };

    if let Err(e) = result {
        debug!("Server error: {:?}", e);
        std::process::exit(1);
    }
}
