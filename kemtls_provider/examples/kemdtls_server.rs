use kemtls_provider::resolver::{KeyPair, ServerCertResolver};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ServerVerifier;
use kemtls_provider::{PureKemKey, get_kx_group_by_name, provider, HybridKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::crypto::CryptoProvider;
use rustls::server::Acceptor;
use rustls::{Error, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use clap::Parser;
use std::collections::HashMap;
use rustls::sign::KemKey;
use openssl::pkey::{Id, PKey};
use std::fs;

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 1;
const HTTP_RESPONSE: &[u8] = b"Hello from TLS Server!";

#[derive(Parser, Debug)]
#[command(about = "KEMTLS Server with TLS 1.3 and DTLS 1.3 support")]
struct ServerArgs {
    /// KEM algorithm to use for authentication
    #[arg(short, long, default_value = "MLKEM768")]
    authkem: String,

    /// KX group to offer
    #[arg(short, long)]
    group: Option<String>,

    /// Optional CID value to offer in DTLS (0-255)
    #[arg(short, long)]
    cid: Option<u8>,

    /// Max fragment length for DTLS 
    #[arg(short = 'L', long, default_value_t = 1400)]
    max_fragment_length: usize,

    /// Disable client authentication 
    #[arg(short = 'd', long = "disable-client-auth", default_value_t = true, action = clap::ArgAction::SetFalse)]
    client_auth: bool,
    
    /// Port to listen on 
    #[arg(short, long, default_value_t = 8443)]
    port: u16,

    /// Address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,

    /// Payload bytes to send after handshake
    #[arg(short = 'B', long, default_value = "1000")]
    payload_size: usize,

    /// Enables hybrid KEMs
    #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    hybrid: bool,

    #[arg(short = 'k', long)]
    x25519_key: Option<String>,
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

fn create_server_config(
    kemalg: oqs::kem::Algorithm,
    crypto_provider: CryptoProvider,
    client_auth: bool,
    hybrid: bool,
    x25519_key_path: Option<String>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let kem = Kem::new(kemalg)?;
    let (public_key, secret_key) = kem.keypair()?;

    let signing_key = Arc::new(DummySigningKey);
    
    let (kem_key, x25519_sk, x25519_pk) = match hybrid {
        true => {
            let path = x25519_key_path.ok_or("Invalid x25519 key path")?;
            let (x25519_sk, x25519_pk) = load_x25519_keypair_from_pem(&path)?;

            let kem_key: Arc<dyn KemKey> = Arc::new(HybridKemKey::new(kemalg,secret_key.as_ref().to_vec(), x25519_sk));
            (kem_key, Some(x25519_sk), Some(x25519_pk))
        },
        false => {
            let kem_key: Arc<dyn KemKey> = Arc::new(PureKemKey::new(kemalg, secret_key.as_ref().to_vec()));
            (kem_key, None, None)
        }
    };

    // Create our key pair structure
    let key_pair = KeyPair::new(public_key, x25519_pk, signing_key, Some(kem_key));

    let resolver = Arc::new(ServerCertResolver::new(key_pair));
    let client_verifier = Arc::new(ServerVerifier::new(kemalg, x25519_sk, x25519_pk));

    let mut server_config = match client_auth {
        true => ServerConfig::builder_with_provider(crypto_provider.into())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(resolver),
        false => ServerConfig::builder_with_provider(crypto_provider.into()).with_safe_default_protocol_versions()?.with_no_client_auth().with_cert_resolver(resolver)
    };

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    // Disable session resumption for testing purposes
    server_config.send_tls13_tickets = 0;
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    println!("Server config created successfully");
    Ok(server_config)
}

fn load_x25519_keypair_from_pem(path: &str) -> Result<([u8; 32], [u8; 32]), Error> {
    let pem = fs::read(path)
        .map_err(|e| Error::General(format!("failed to read x25519 key file: {e}")))?;

    let pkey = PKey::private_key_from_pem(&pem)
        .map_err(|e| Error::General(format!("failed to parse x25519 private key PEM: {e}")))?;

    if pkey.id() != Id::X25519 {
        return Err(Error::General("provided key is not X25519".into()));
    }

    let raw_sk = pkey
        .raw_private_key()
        .map_err(|e| Error::General(format!("failed to extract raw x25519 private key: {e}")))?;

    let raw_pk = pkey
        .raw_public_key()
        .map_err(|e| Error::General(format!("failed to extract raw x25519 public key: {e}")))?;

    let sk: [u8; 32] = raw_sk
        .as_slice()
        .try_into()
        .map_err(|_| Error::General("invalid raw x25519 private key length".into()))?;

    let pk: [u8; 32] = raw_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::General("invalid raw x25519 public key length".into()))?;

    Ok((sk, pk))
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
    debug!("Response sent to client");
    // Close connection gracefully
    conn.send_close_notify();
    conn.write_tls(&mut stream)?;

    Ok(())
}

fn run_tls_server(server_config: ServerConfig, addr: String, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("{}:{}", addr, port))?;
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

// DTLS Helper Functions
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
                        
                        Self::write_pending(&mut conn, socket, addr)?;

                        *self = ClientState::Connected {
                            conn,
                            response_sent: false,
                            last_seen: Instant::now(),
                        };
                    }
                    Ok(None) => {
                    }
                    Err((err, mut alert)) => {
                        let mut out = Vec::new();
                        alert.write(&mut out).ok();
                        socket.send_to(&out, addr).ok();
                        return Err(Box::new(err));
                    }
                }
            }
            ClientState::Connected { conn, response_sent, last_seen } => {
                *last_seen = Instant::now();
                let mut slice = packet;
                if let Err(e) = conn.read_tls(&mut slice) {
                    let _ = Self::write_pending(conn, socket, addr);
                    return Err(Box::new(e));
                }
                if let Err(e) = conn.process_new_packets() {
                    eprintln!("Error fatal procesando paquetes: {:?}", e);
                    let _ = Self::write_pending(conn, socket, addr);
                    return Err(Box::new(e));
                }

                let io_state = conn.process_new_packets()?;

                if io_state.plaintext_bytes_to_read() > 0 {
                    let mut reader = conn.reader();
                    let mut discard = vec![0u8; io_state.plaintext_bytes_to_read()];
                    reader.read_exact(&mut discard).ok();

                    if !*response_sent {
                        send_zero_payload(conn, payload_size)?;
                        *response_sent = true;
                    }
                }

                Self::write_pending(conn, socket, addr)?;

                if *response_sent && !conn.wants_write() {
                    return Ok(true); 
                }
            }
        }
        Ok(false)
    }

    fn handle_timeout(
        &mut self,
        socket: &UdpSocket,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            ClientState::Connected { conn, .. } => {
                if let Err(e) = conn.process_new_packets() {
                    let mut alert_buf = Vec::new();
                    if let Ok(len) = conn.write_dtls(&mut alert_buf) {
                        if len > 0 {
                            let _ = socket.send_to(&alert_buf, addr);
                        }
                    }
                    return Err(Box::new(e));
                }
                Self::write_pending(conn, socket, addr)?;
            }
            ClientState::Handshaking { .. } => {
            }
        }
        Ok(())
    }

    fn write_pending(conn: &mut ServerConnection, socket: &UdpSocket, addr: SocketAddr) -> Result<(), std::io::Error> {
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
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/zero")?;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer)?;
    
    conn.writer().write_all(&buffer)?;
    Ok(())
}

fn run_dtls_server(
    server_config: ServerConfig,
    addr: String,
    port: u16,
    payload_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(format!("{}:{}", addr, port))?;
    socket.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;
    socket.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))?;
    socket.set_nonblocking(true)?;

    println!("DTLS server listening on {}:{}", addr, port);

    let mut clients: HashMap<SocketAddr, ClientState> = HashMap::new();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, addr)) => {
                    let packet = &buffer[..len];

                    let state = clients.entry(addr).or_insert_with(|| {
                        println!("Nueva sesión: {}", addr);
                        ClientState::Handshaking {
                            acceptor: Acceptor::default(),
                            last_seen: Instant::now(),
                        }
                    });

                    match state.handle_datagram(packet, &socket, addr, server_config.clone(), payload_size) {
                        Ok(true) => {
                            println!("Sesión finalizada con éxito: {}", addr);
                            clients.remove(&addr);
                        }
                        Err(e) => {
                            eprintln!("Error en sesión {}: {:?}", addr, e);
                            clients.remove(&addr);
                        }
                        Ok(false) => {} 
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    clients.retain(|addr, state| {
                        let last = match state {
                            ClientState::Handshaking { last_seen, .. } => last_seen,
                            ClientState::Connected { last_seen, .. } => last_seen,
                        };
                        if now.duration_since(*last) > Duration::from_secs(10) {
                            println!("Sesión expirada: {}", addr);
                            return false;
                        }  
                        if let Err(err) = state.handle_timeout(&socket, *addr) {
                            eprintln!("Error en retransmisión para {}: {:?}", addr, err);
                            return false;
                        }
                        true
                    });
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => eprintln!("Error crítico de socket: {:?}", e),
            }
        }
    }
}

fn main() {
    env_logger::init();

    let use_dtls = cfg!(feature = "dtls13");
    if use_dtls {
        println!("Using DTLS 1.3");
    }

    let args = ServerArgs::parse();

    println!("Starting KEMTLS Server...");

    let kemalg = match get_kem_algorithm(&args.authkem) {
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

    if let Some(ref group_name) = args.group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name);
    } else {
        println!("Using all available KX groups");
    }

    println!("Provider has {} kx_groups", crypto_provider.kx_groups.len());
    for kx in &crypto_provider.kx_groups {
        println!("  KX group: {:?}", kx.name());
    }

    let mut server_config = match create_server_config(kemalg, crypto_provider, args.client_auth, args.hybrid, args.x25519_key) {
        Ok(config) => config,
        Err(e) => {
            debug!("Failed to create server config: {:?}", e);
            std::process::exit(1);
        }
    };

    let result = if use_dtls {
        println!("Max fragment size set to: {}", args.max_fragment_length);
        server_config.max_fragment_size = Some(args.max_fragment_length);

        if let Some(cid_val) = args.cid {
            println!("Offering CID: {}", cid_val);
            server_config.set_cid(&[cid_val]);
        }

        run_dtls_server(server_config, args.addr, args.port, args.payload_size)
    } else {
        run_tls_server(server_config, args.addr,args.port)
    };

    if let Err(e) = result {
        debug!("Server error: {:?}", e);
        std::process::exit(1);
    }
}
