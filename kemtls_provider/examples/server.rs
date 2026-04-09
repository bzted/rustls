use kemtls_provider::{provider, get_kx_group_by_name, get_pq_kx_group_by_name, DEFAULT_KX_GROUPS};
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
use rustls::crypto::CryptoProvider;


const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 10; 
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nConnection: closed\r\nContent-Type: text/html\r\n\r\n<h1>Hello KEMTLS World!</h1>\r\n";


#[derive(Debug, Clone)]
struct Args {
    group: Option<String>,
    cid: Option<u8>,
    max_fragment_length: usize,
    client_auth: bool,
    cert_file: String,
    pk_file: String,
    ca_file: String,
    port: u16,
    addr: String,
    pqc_provider: bool,
    payload_size: usize,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            group: None,
            cid: None,
            max_fragment_length: 1300,
            client_auth: true,
            cert_file: "../test-ca/rsa-2048/end.fullchain".to_string(),
            pk_file: "../test-ca/rsa-2048/end.key".to_string(),
            ca_file: "../test-ca/rsa-2048/ca.cert".to_string(),
            port: 8443,
            addr: "127.0.0.1".to_string(),
            pqc_provider: false,
            payload_size: 1000,
        }
    }
}

fn print_help_and_exit() -> ! {
    println!(
        concat!(
            "Traditional TLS/DTLS server\n\n",
            "Options:\n",
            "  -g, --group <NAME>               KX group to use\n",
            "      --cid <0-255>               Optional DTLS CID\n",
            "  -L <N>                          Max fragment length (default: 1300)\n",
            "  -d                              Disable client authentication\n",
            "  -c <FILE>                       Certificate file\n",
            "  -k <FILE>                       Private key file\n",
            "  -A <FILE>                       CA certificate file\n",
            "  -p, --port <PORT>               Port (default: 8443)\n",
            "      --addr <ADDR>               Bind address (default: 127.0.0.1)\n",
            "  -q, --pqc-provider              Enable PQC provider\n",
            "  -B, --payload-size <N>          Payload bytes after handshake (default: 1000)\n",
            "  -h, --help                      Show help\n",
        )
    );
    std::process::exit(0);
}

fn parse_value<T: std::str::FromStr>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<T, String> {
    let value = iter.next().ok_or_else(|| format!("missing value for {flag}"))?;
    value.parse::<T>().map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1).peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => print_help_and_exit(),
            "-g" | "--group" => args.group = Some(parse_value(&mut iter, "--group")?),
            "--cid" => args.cid = Some(parse_value(&mut iter, "--cid")?),
            "-L" => args.max_fragment_length = parse_value(&mut iter, "-L")?,
            "-d" => args.client_auth = false,
            "-c" => args.cert_file = parse_value(&mut iter, "-c")?,
            "-k" => args.pk_file = parse_value(&mut iter, "-k")?,
            "-A" => args.ca_file = parse_value(&mut iter, "-A")?,
            "-p" | "--port" => args.port = parse_value(&mut iter, "--port")?,
            "--addr" => args.addr = parse_value(&mut iter, "--addr")?,
            "-q" | "--pqc-provider" => args.pqc_provider = true,
            "-B" | "--payload-size" => args.payload_size = parse_value(&mut iter, "--payload-size")?,
            _ if arg.starts_with("--group=") => args.group = Some(arg["--group=".len()..].to_string()),
            _ if arg.starts_with("--cid=") => args.cid = Some(arg["--cid=".len()..].parse().map_err(|_| format!("invalid value for --cid: {}", &arg["--cid=".len()..]))?),
            _ if arg.starts_with("--port=") => args.port = arg["--port=".len()..].parse().map_err(|_| format!("invalid value for --port: {}", &arg["--port=".len()..]))?,
            _ if arg.starts_with("--addr=") => args.addr = arg["--addr=".len()..].to_string(),
            _ if arg.starts_with("--payload-size=") => args.payload_size = arg["--payload-size=".len()..].parse().map_err(|_| format!("invalid value for --payload-size: {}", &arg["--payload-size=".len()..]))?,
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(args)
}

fn select_kx_group(crypto_provider: &mut CryptoProvider, group: &str, pqc: bool) {
    match pqc {
        true => {
            if let Some(selected_group) = get_pq_kx_group_by_name(group) {
                crypto_provider.kx_groups = vec![selected_group];
            } else {
                println!("Unknown group, using default groups");
            }
        }

        false => {
            if let Some(selected_group) = get_kx_group_by_name(group) {
                crypto_provider.kx_groups = vec![selected_group];
            } else {
                println!("Unknown group, using default groups");
            }
        }
    }
}


enum ClientState {
    Handshaking {
        acceptor: Acceptor,
        last_seen: Instant,
    },
    Connected {
        conn: ServerConnection,
        response_sent: bool,
        received_app_data: usize,
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
                            received_app_data: 0,
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
            ClientState::Connected { conn, response_sent, received_app_data, last_seen } => {
                *last_seen = Instant::now();
                let mut slice = packet;
                if let Err(e) = conn.read_tls(&mut slice) {
                    let _ = Self::flush_output(conn, socket, addr);
                    return Err(Box::new(e));
                }
                if let Err(e) = conn.process_new_packets() {
                    let _ = Self::flush_output(conn, socket, addr);
                    return Err(Box::new(e));
                }

                let io_state = conn.process_new_packets()?;

                if io_state.plaintext_bytes_to_read() > 0 {
                    let mut reader = conn.reader();
                    let mut buf = vec![0u8; io_state.plaintext_bytes_to_read()];
                    if reader.read_exact(&mut buf).is_ok() {
                        *received_app_data += buf.len();
                    }

                    if !*response_sent && *received_app_data >= payload_size {
                        send_zero_payload(conn, payload_size)?;
                        *response_sent = true;
                    }
                }

                Self::flush_output(conn, socket, addr)?;

                if *response_sent && *received_app_data >= payload_size && !conn.wants_write() {
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
                Self::flush_output(conn, socket, addr)?;
            }
            ClientState::Handshaking { .. } => {
            }
        }
        Ok(())
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
    println!("DTLS Multi-Client Server listening on {}:{}", addr, port);

    let mut clients: HashMap<SocketAddr, ClientState> = HashMap::new();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        // Recibir todos los paquetes pendientes en el buffer del sistema
        while let Ok((len, addr)) = socket.recv_from(&mut buffer) {
            let packet = &buffer[..len];
            let state = clients.entry(addr).or_insert_with(|| {
                println!("Nuevo cliente: {}", addr);
                ClientState::Handshaking {
                    acceptor: Acceptor::default(),
                    last_seen: Instant::now(),
                }
            });

            // handle_datagram ya no devuelve un flag de finalización
            if let Err(e) = state.handle_datagram(packet, &socket, addr, server_config.clone(), payload_size) {
                debug!("Error en sesión {}: {:?}", addr, e);
                clients.remove(&addr);
            }
        }

        // Tick de mantenimiento
        let now = Instant::now();
        clients.retain(|addr, state| {
            let last = match state {
                ClientState::Connected { last_seen, .. } => last_seen,
                ClientState::Handshaking { last_seen, .. } => last_seen,
            };

            if now.duration_since(*last) > Duration::from_secs(TIMEOUT_SECS) {
                println!("Timeout de inactividad: {}", addr);
                return false;
            }

            if let Err(e) = state.handle_timeout(&socket, *addr) {
                println!("Error durante retransmisión {}: {:?}. Cerrando.", addr, e);
                return false;
            }

            true
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
    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("Argument error: {e}");
        std::process::exit(2);
    });

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
    
    // Set up TLS server with AuthKEM provider
    let mut crypto_provider = provider();

    if !args.pqc_provider {
        crypto_provider.kx_groups = DEFAULT_KX_GROUPS.to_vec();
    }
    
    if let Some(ref group_name) = args.group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name, args.pqc_provider);
    } else {
        println!("Using all available KX groups");
    }


    let verifier = WebPkiClientVerifier::builder_with_provider(root_store.into(), Arc::new(crypto_provider.clone())).build().unwrap();

    let mut server_config = match  args.client_auth {
        true => {
            ServerConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert, pk).unwrap()
        }
        false => {
            ServerConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
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
