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
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use clap::Parser;

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 30; 
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nConnection: closed\r\nContent-Type: text/html\r\n\r\n<h1>Hello KEMTLS World!</h1>\r\n";

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    cid: Option<u8>,
    #[arg(short = 'L', default_value_t = 1400)]
    max_fragment_length: usize,
    #[arg(short = 'd', default_value_t = true, action = clap::ArgAction::SetFalse)]
    client_auth: bool,
    #[arg(short = 'c', default_value = "../test-ca/rsa-2048/end.fullchain")]
    cert_file: String,
    #[arg(short = 'k', default_value = "../test-ca/rsa-2048/end.key")]
    pk_file: String,
    #[arg(short = 'A', default_value = "../test-ca/rsa-2048/ca.cert")]
    ca_file: String,
    #[arg(short, long, default_value_t = 8443)]
    port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
    #[arg(short = 'q' ,long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pqc_provider: bool,
    #[arg(short = 'B', long, default_value_t = 1000)]
    payload_size: usize,
}

enum ClientState {
    Handshaking {
        acceptor: Acceptor,
        last_seen: Instant,
    },
    Connected {
        conn: ServerConnection,
        response_sent: bool,
        last_seen: Instant,
    },
}

impl ClientState {
    fn handle_datagram(
        &mut self,
        packet: &[u8],
        socket: &UdpSocket,
        addr: SocketAddr,
        server_config: ServerConfig,
        payload_size: usize,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match self {
            ClientState::Handshaking { acceptor, last_seen } => {
                *last_seen = Instant::now();
                let mut slice = packet;
                acceptor.read_tls(&mut slice)?;

                match acceptor.accept() {
                    Ok(Some(accepted)) => {
                        let mut conn = match accepted.into_connection(server_config.into()) {
                            Ok(conn) => conn,
                            Err((err, mut alert)) => {
                                debug!("Error creating connection: {:?}", err);
                                let mut out = Vec::new();
                                if let Err(write_err) = alert.write(&mut out) {
                                    debug!("Error writing alert: {:?}", write_err);
                                } else {
                                    let _ = socket.send_to(&out, addr);
                                }
                                return Err(format!("Connection error: {:?}", err).into());
                            }
                        };
                        println!("Handshake exitoso con {}", addr);
                        
                        Self::flush_output(&mut conn, socket, addr)?;

                        *self = ClientState::Connected {
                            conn,
                            response_sent: false,
                            last_seen: Instant::now(),
                        };
                    }
                    Ok(None) => {}
                    Err((err, mut alert)) => {
                        let mut out = Vec::new();
                        alert.write(&mut out).ok();
                        let _ = socket.send_to(&out, addr);
                        return Err(Box::new(err));
                    }
                }
            }
            ClientState::Connected { conn, response_sent, last_seen } => {
                *last_seen = Instant::now();
                let mut slice = packet;
                conn.read_tls(&mut slice)?;
                let io_state = conn.process_new_packets()?;

                if io_state.plaintext_bytes_to_read() > 0 {
                    let mut reader = conn.reader();
                    let mut buf = vec![0u8; io_state.plaintext_bytes_to_read()];
                    reader.read_exact(&mut buf).ok();

                    if !*response_sent {
                        send_zero_payload(conn, payload_size)?;
                        *response_sent = true;
                    }
                }

                Self::flush_output(conn, socket, addr)?;

                if *response_sent && !conn.wants_write() {
                    return Ok(true); 
                }
            }
        }
        Ok(false)
    }

    fn flush_output(conn: &mut ServerConnection, socket: &UdpSocket, addr: SocketAddr) -> Result<(), std::io::Error> {
        while conn.wants_write() {
            let mut out_buf = Vec::new();
            if conn.write_dtls(&mut out_buf)? > 0 {
                socket.send_to(&out_buf, addr)?;
            }
        }
        Ok(())
    }
}

fn send_zero_payload(conn: &mut ServerConnection, size: usize) -> Result<(), std::io::Error> {
    let mut buffer = vec![0u8; size];
    if let Ok(mut file) = std::fs::File::open("/dev/zero") {
        file.read_exact(&mut buffer).ok();
    }
    conn.writer().write_all(&buffer)?;
    Ok(())
}

fn run_dtls_server(server_config: ServerConfig, addr: String, port: u16, payload_size: usize) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(format!("{}:{}", addr, port))?;
    socket.set_nonblocking(true)?;
    println!("DTLS Multi-Client Server listening on {}:{} (Single-Threaded)", addr, port);

    let mut clients: HashMap<SocketAddr, ClientState> = HashMap::new();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, addr)) => {
                    let packet = &buffer[..len];
                    let state = clients.entry(addr).or_insert_with(|| {
                        println!("Nuevo cliente: {}", addr);
                        ClientState::Handshaking {
                            acceptor: Acceptor::default(),
                            last_seen: Instant::now(),
                        }
                    });

                    if let Ok(finished) = state.handle_datagram(packet, &socket, addr, server_config.clone(), payload_size) {
                        if finished { clients.remove(&addr); }
                    } else {
                        clients.remove(&addr);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(Box::new(e)),
            }
        }

        let now = Instant::now();
        clients.retain(|addr, state| {
            match state {
                ClientState::Connected { conn, last_seen, .. } => {
                    conn.process_new_packets().ok();
                    let _ = ClientState::flush_output(conn, &socket, *addr);
                    now.duration_since(*last_seen) < Duration::from_secs(TIMEOUT_SECS)
                }
                ClientState::Handshaking { last_seen, .. } => {
                    now.duration_since(*last_seen) < Duration::from_secs(TIMEOUT_SECS)
                }
            }
        });

        std::thread::sleep(Duration::from_millis(1));
    }
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

fn run_tls_server(server_config: ServerConfig, addr: String, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("{}:{}", addr, port))?;
    println!("TLS server listening on {}:{}", addr, port);

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
        run_dtls_server(server_config, args.addr, args.port, args.payload_size)
    } else {
        run_tls_server(server_config, args.addr, args.port)
    };

    if let Err(e) = result {
        debug!("Server error: {:?}", e);
        std::process::exit(1);
    }
}
