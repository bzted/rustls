use kemtls_provider::resolver::{
    ServerCertResolver, default_keys_dir, load_x25519_keypair_from_pem, supported_kemtls_groups,
};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ServerVerifier;
use kemtls_provider::{DEFAULT_KX_GROUPS, KX_GROUPS, get_kx_group_by_name, get_pq_kx_group_by_name, provider};
use log::debug;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const BUFFER_SIZE: usize = 4096;
const APP_FRAME_HEADER_LEN: usize = 4;
const TIMEOUT_SECS: u64 = 1;
const HANDSHAKING_CLIENT_TIMEOUT_SECS: u64 = 70;
const CONNECTED_CLIENT_TIMEOUT_SECS: u64 = 10;
const HTTP_RESPONSE: &[u8] = b"Hello from TLS Server!";

#[derive(Debug, Clone)]
struct ServerArgs {
    authkems: Vec<String>,
    group: Option<String>,
    keys_dir: Option<String>,
    pqc_provider: bool,
    cid: Option<u8>,
    max_fragment_length: usize,
    client_auth: bool,
    cert_file: String,
    pk_file: String,
    ca_file: String,
    port: u16,
    addr: String,
    payload_size: usize,
    hybrid_key: Option<String>,
}

impl Default for ServerArgs {
    fn default() -> Self {
        Self {
            authkems: Vec::new(),
            group: None,
            keys_dir: None,
            pqc_provider: false,
            cid: None,
            max_fragment_length: 1300,
            client_auth: true,
            cert_file: "../test-ca/rsa-2048/end.fullchain".to_string(),
            pk_file: "../test-ca/rsa-2048/end.key".to_string(),
            ca_file: "../test-ca/rsa-2048/ca.cert".to_string(),
            port: 8443,
            addr: "127.0.0.1".to_string(),
            payload_size: 1000,
            hybrid_key: None,
        }
    }
}

fn print_help_and_exit() -> ! {
    println!(concat!(
        "KEMTLS Server with TLS 1.3 and DTLS 1.3 support\n\n",
        "Options:\n",
        "  -a, --authkem <ALG>[,<ALG>...]  Authentication KEM(s); repeatable, defaults to all\n",
        "  -g, --group <NAME>              KX group to offer\n",
        "      --keys-dir <DIR>            Directory containing KEMTLS keys [default: CARGO_MANIFEST_DIR/keys]\n",
        "  -q, --pqc-provider              Interpret -g as a PQ/PQ-hybrid KX group\n",
        "      --cid <0-255>               Optional DTLS CID\n",
        "  -L, --max-fragment-length <N>   Max fragment length (default: 1300)\n",
        "  -d, --disable-client-auth       Disable client authentication\n",
        "  -c <FILE>                       Certificate file\n",
        "  -k <FILE>                       Private key file\n",
        "  -A <FILE>                       CA certificate file\n",
        "  -p, --port <PORT>               Port (default: 8443)\n",
        "      --addr <ADDR>               Bind address (default: 127.0.0.1)\n",
        "  -B, --payload-size <N>          Payload bytes after handshake (default: 1000)\n",
        "      --hybrid <FILE>             Enable hybrid KEMs with X25519 private key PEM\n",
        "  -h, --help                      Show help\n",
    ));
    std::process::exit(0);
}

fn parse_value<T: std::str::FromStr>(
    iter: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<T, String> {
    let value = iter
        .next()
        .ok_or_else(|| format!("missing value for {flag}"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn parse_args() -> Result<ServerArgs, String> {
    let mut args = ServerArgs::default();
    let mut iter = std::env::args().skip(1).peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => print_help_and_exit(),
            "-a" | "--authkem" => {
                let value: String = parse_value(&mut iter, "--authkem")?;
                push_authkems(&mut args.authkems, &value);
            }
            "-g" | "--group" => args.group = Some(parse_value(&mut iter, "--group")?),
            "--keys-dir" => args.keys_dir = Some(parse_value(&mut iter, "--keys-dir")?),
            "-q" | "--pqc-provider" => args.pqc_provider = true,
            "--cid" => args.cid = Some(parse_value(&mut iter, "--cid")?),
            "-L" | "--max-fragment-length" => {
                args.max_fragment_length = parse_value(&mut iter, "--max-fragment-length")?
            }
            "-d" | "--disable-client-auth" => args.client_auth = false,
            "-c" => args.cert_file = parse_value(&mut iter, "-c")?,
            "-k" => args.pk_file = parse_value(&mut iter, "-k")?,
            "-A" => args.ca_file = parse_value(&mut iter, "-A")?,
            "-p" | "--port" => args.port = parse_value(&mut iter, "--port")?,
            "--addr" => args.addr = parse_value(&mut iter, "--addr")?,
            "-B" | "--payload-size" => {
                args.payload_size = parse_value(&mut iter, "--payload-size")?
            }
            "--hybrid" => args.hybrid_key = Some(parse_value(&mut iter, "--hybrid")?),
            _ if arg.starts_with("--authkem=") => {
                push_authkems(&mut args.authkems, &arg["--authkem=".len()..])
            }
            _ if arg.starts_with("--group=") => {
                args.group = Some(arg["--group=".len()..].to_string())
            }
            _ if arg.starts_with("--keys-dir=") => {
                args.keys_dir = Some(arg["--keys-dir=".len()..].to_string())
            }
            _ if arg.starts_with("--cid=") => {
                args.cid = Some(
                    arg["--cid=".len()..]
                        .parse()
                        .map_err(|_| {
                            format!("invalid value for --cid: {}", &arg["--cid=".len()..])
                        })?,
                )
            }
            _ if arg.starts_with("--max-fragment-length=") => {
                args.max_fragment_length = arg["--max-fragment-length=".len()..]
                    .parse()
                    .map_err(|_| {
                        format!(
                            "invalid value for --max-fragment-length: {}",
                            &arg["--max-fragment-length=".len()..]
                        )
                    })?
            }
            _ if arg.starts_with("--port=") => {
                args.port = arg["--port=".len()..]
                    .parse()
                    .map_err(|_| format!("invalid value for --port: {}", &arg["--port=".len()..]))?
            }
            _ if arg.starts_with("--addr=") => args.addr = arg["--addr=".len()..].to_string(),
            _ if arg.starts_with("--payload-size=") => {
                args.payload_size = arg["--payload-size=".len()..]
                    .parse()
                    .map_err(|_| {
                        format!(
                            "invalid value for --payload-size: {}",
                            &arg["--payload-size=".len()..]
                        )
                    })?
            }
            _ if arg.starts_with("--hybrid=") => {
                args.hybrid_key = Some(arg["--hybrid=".len()..].to_string())
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(args)
}

fn push_authkems(authkems: &mut Vec<String>, value: &str) {
    authkems.extend(
        value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(ToOwned::to_owned),
    );
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

fn select_kx_group(crypto_provider: &mut CryptoProvider, group: &str, pqc_provider: bool) {
    let selected_group = if pqc_provider {
        get_pq_kx_group_by_name(group)
    } else {
        get_kx_group_by_name(group)
    };

    if let Some(selected_group) = selected_group {
        crypto_provider.kx_groups = vec![selected_group];
    } else {
        println!("Unknown group, using default groups");
        if pqc_provider {
            println!(
                "Available PQ/PQ-hybrid groups: MLKEM512, MLKEM768, MLKEM1024, BikeL1, BikeL3, BikeL5, Hqc128, Hqc192, Hqc256, NtruPrimeSntrup761 and hybrid variants with X25519"
            );
        } else {
            println!("Available traditional groups: X25519, SECP256R1, SECP384R1");
        }
    }
}

fn combined_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    let mut groups = DEFAULT_KX_GROUPS.to_vec();
    groups.extend_from_slice(KX_GROUPS);
    groups
}

fn selected_auth_group(
    kemalg: oqs::kem::Algorithm,
    hybrid: bool,
) -> Result<rustls::NamedGroup, Box<dyn std::error::Error>> {
    let group = match (kemalg, hybrid) {
        (oqs::kem::Algorithm::MlKem512, false) => rustls::NamedGroup::MLKEM512,
        (oqs::kem::Algorithm::MlKem768, false) => rustls::NamedGroup::MLKEM768,
        (oqs::kem::Algorithm::MlKem1024, false) => rustls::NamedGroup::MLKEM1024,
        (oqs::kem::Algorithm::BikeL1, false) => rustls::NamedGroup::BikeL1,
        (oqs::kem::Algorithm::BikeL3, false) => rustls::NamedGroup::BikeL3,
        (oqs::kem::Algorithm::BikeL5, false) => rustls::NamedGroup::BikeL5,
        (oqs::kem::Algorithm::Hqc128, false) => rustls::NamedGroup::Hqc128,
        (oqs::kem::Algorithm::Hqc192, false) => rustls::NamedGroup::Hqc192,
        (oqs::kem::Algorithm::Hqc256, false) => rustls::NamedGroup::Hqc256,
        (oqs::kem::Algorithm::NtruPrimeSntrup761, false) => rustls::NamedGroup::NtruPrimeSntrup761,
        (oqs::kem::Algorithm::MlKem512, true) => rustls::NamedGroup::X25519MLKEM512,
        (oqs::kem::Algorithm::MlKem768, true) => rustls::NamedGroup::X25519MLKEM768,
        (oqs::kem::Algorithm::MlKem1024, true) => rustls::NamedGroup::X25519MLKEM1024,
        (oqs::kem::Algorithm::BikeL1, true) => rustls::NamedGroup::X25519BikeL1,
        (oqs::kem::Algorithm::BikeL3, true) => rustls::NamedGroup::X25519BikeL3,
        (oqs::kem::Algorithm::BikeL5, true) => rustls::NamedGroup::X25519BikeL5,
        (oqs::kem::Algorithm::Hqc128, true) => rustls::NamedGroup::X25519Hqc128,
        (oqs::kem::Algorithm::Hqc192, true) => rustls::NamedGroup::X25519Hqc192,
        (oqs::kem::Algorithm::Hqc256, true) => rustls::NamedGroup::X25519Hqc256,
        (oqs::kem::Algorithm::NtruPrimeSntrup761, true) => {
            rustls::NamedGroup::X25519NtruPrimeSntrup761
        }
        _ => {
            return Err("Unsupported auth KEM group".into());
        }
    };

    Ok(group)
}

fn auth_groups_from_args(
    authkems: &[String],
    hybrid: bool,
) -> Result<Vec<rustls::NamedGroup>, Box<dyn std::error::Error>> {
    if authkems.is_empty() {
        return Ok(supported_kemtls_groups(hybrid));
    }

    let groups: Vec<rustls::NamedGroup> = authkems
        .iter()
        .map(|authkem| {
            let kemalg = get_kem_algorithm(authkem)?;
            selected_auth_group(kemalg, hybrid)
        })
        .collect::<Result<_, _>>()?;

    let mut deduped = Vec::new();
    for group in groups {
        if !deduped.contains(&group) {
            deduped.push(group);
        }
    }
    Ok(deduped)
}

fn create_server_config(
    auth_groups: Vec<rustls::NamedGroup>,
    crypto_provider: CryptoProvider,
    client_auth: bool,
    cert_file: &str,
    pk_file: &str,
    ca_file: &str,
    keys_dir: Option<String>,
    hybrid_key_path: Option<String>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let keys_dir = keys_dir.map(PathBuf::from).unwrap_or_else(default_keys_dir);
    let signing_key = Arc::new(DummySigningKey);
    let cert = CertificateDer::pem_file_iter(cert_file)?
        .map(|cert| cert.map_err(|e| format!("error reading certificate: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let pk = rustls::pki_types::PrivateKeyDer::from_pem_file(pk_file)?;
    let traditional_certified_key = Arc::new(rustls::sign::CertifiedKey::from_der(
        cert,
        pk,
        &crypto_provider,
    )?);

    let x25519_key_path = hybrid_key_path.map(PathBuf::from);
    let (x25519_sk, x25519_pk) = match &x25519_key_path {
        Some(path) => {
            let (x25519_sk, x25519_pk) = load_x25519_keypair_from_pem(&path)?;
            (Some(x25519_sk), Some(x25519_pk))
        }
        None => (None, None),
    };

    let resolver = Arc::new(ServerCertResolver::load_kemtls_keys(
        Some(traditional_certified_key),
        keys_dir,
        &auth_groups,
        signing_key,
        x25519_key_path,
    )?);

    let mut server_config = match client_auth {
        true => {
            let mut root_store = RootCertStore::empty();
            root_store.add_parsable_certificates(
                CertificateDer::pem_file_iter(ca_file)?
                    .map(|cert| cert.map_err(|e| format!("error reading CA certificate: {e}")))
                    .collect::<Result<Vec<_>, _>>()?,
            );

            let traditional_verifier = WebPkiClientVerifier::builder_with_provider(
                root_store.into(),
                Arc::new(crypto_provider.clone()),
            )
            .build()?;
            let client_verifier = Arc::new(ServerVerifier::new(
                Some(traditional_verifier),
                x25519_sk,
                x25519_pk,
            ));

            ServerConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions()?
                .with_kemtls_groups(auth_groups.clone())
                .with_client_cert_verifier(client_verifier)
                .with_cert_resolver(resolver)
        }
        false => ServerConfig::builder_with_provider(crypto_provider.into())
            .with_safe_default_protocol_versions()?
            .with_kemtls_groups(auth_groups.clone())
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    };

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    // Disable session resumption for testing purposes
    server_config.send_tls13_tickets = 0;
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    println!("Server config created successfully");
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
    debug!("Response sent to client");
    // Close connection gracefully
    conn.send_close_notify();
    conn.write_tls(&mut stream)?;

    Ok(())
}

fn run_tls_server(
    server_config: ServerConfig,
    addr: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
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
        request_buffer: Vec<u8>,
        expected_request_len: Option<usize>,
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
            ClientState::Handshaking {
                acceptor,
                last_seen,
            } => {
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
                            request_buffer: Vec::new(),
                            expected_request_len: None,
                            last_seen: Instant::now(),
                        };
                    }
                    Ok(None) => {}
                    Err((err, mut alert)) => {
                        let mut out = Vec::new();
                        alert.write(&mut out).ok();
                        socket.send_to(&out, addr).ok();
                        return Err(Box::new(err));
                    }
                }
            }
            ClientState::Connected {
                conn,
                response_sent,
                request_buffer,
                expected_request_len,
                last_seen,
            } => {
                *last_seen = Instant::now();
                let mut slice = packet;
                if let Err(e) = conn.read_tls(&mut slice) {
                    let _ = Self::write_pending(conn, socket, addr);
                    return Err(Box::new(e));
                }
                let io_state = match conn.process_new_packets() {
                    Ok(io_state) => io_state,
                    Err(e) => {
                        eprintln!("Error fatal procesando paquetes: {:?}", e);
                        let _ = Self::write_pending(conn, socket, addr);
                        return Err(Box::new(e));
                    }
                };

                if io_state.plaintext_bytes_to_read() > 0 {
                    let mut tmp = [0u8; BUFFER_SIZE];
                    loop {
                        let mut reader = conn.reader();
                        match reader.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => request_buffer.extend_from_slice(&tmp[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(Box::new(e)),
                        }
                    }

                    while take_complete_request(request_buffer, expected_request_len) {
                        send_zero_payload(conn, payload_size)?;
                        *response_sent = true;
                    }
                }

                Self::write_pending(conn, socket, addr)?;
                return Ok(false);
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
            ClientState::Handshaking { .. } => {}
        }
        Ok(())
    }

    fn write_pending(
        conn: &mut ServerConnection,
        socket: &UdpSocket,
        addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        while conn.wants_write() {
            let mut out_buf = Vec::new();
            if conn.write_dtls(&mut out_buf)? > 0 {
                socket.send_to(&out_buf, addr)?;
            }
        }
        Ok(())
    }
}

fn take_complete_request(buffer: &mut Vec<u8>, expected_len: &mut Option<usize>) -> bool {
    if expected_len.is_none() && buffer.len() >= APP_FRAME_HEADER_LEN {
        let frame_len = u32::from_be_bytes(
            buffer[..APP_FRAME_HEADER_LEN]
                .try_into()
                .expect("frame header has fixed size"),
        ) as usize;
        *expected_len = Some(frame_len);
    }

    let frame_len = match *expected_len {
        Some(frame_len) => frame_len,
        None => return false,
    };
    let total_len = APP_FRAME_HEADER_LEN + frame_len;
    if buffer.len() < total_len {
        return false;
    }

    buffer.drain(..total_len);
    *expected_len = None;
    true
}

fn looks_like_dtls_client_hello(packet: &[u8]) -> bool {
    const DTLS_RECORD_HEADER_LEN: usize = 13;
    const CONTENT_TYPE_HANDSHAKE: u8 = 22;
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

    packet.len() > DTLS_RECORD_HEADER_LEN
        && packet[0] == CONTENT_TYPE_HANDSHAKE
        && packet[3] == 0
        && packet[4] == 0
        && packet[DTLS_RECORD_HEADER_LEN] == HANDSHAKE_TYPE_CLIENT_HELLO
}

fn build_zero_payload_frame(size: usize) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(APP_FRAME_HEADER_LEN + size);
    buffer.extend_from_slice(&(size as u32).to_be_bytes());
    buffer.resize(APP_FRAME_HEADER_LEN + size, 0);
    buffer
}

fn send_zero_payload(conn: &mut ServerConnection, size: usize) -> Result<(), std::io::Error> {
    let buffer = build_zero_payload_frame(size);
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

                    if matches!(
                        clients.get(&addr),
                        Some(ClientState::Connected {
                            response_sent: true,
                            ..
                        })
                    ) && looks_like_dtls_client_hello(packet)
                    {
                        clients.remove(&addr);
                    }

                    let state = clients.entry(addr).or_insert_with(|| {
                        println!("Nueva sesión: {}", addr);
                        ClientState::Handshaking {
                            acceptor: Acceptor::default(),
                            last_seen: Instant::now(),
                        }
                    });

                    match state.handle_datagram(
                        packet,
                        &socket,
                        addr,
                        server_config.clone(),
                        payload_size,
                    ) {
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
                        let (last, timeout) = match state {
                            ClientState::Handshaking { last_seen, .. } => (
                                last_seen,
                                Duration::from_secs(HANDSHAKING_CLIENT_TIMEOUT_SECS),
                            ),
                            ClientState::Connected { last_seen, .. } => (
                                last_seen,
                                Duration::from_secs(CONNECTED_CLIENT_TIMEOUT_SECS),
                            ),
                        };
                        if now.duration_since(*last) > timeout {
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

    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("Argument error: {e}");
        std::process::exit(2);
    });

    println!("Starting KEMTLS Server...");

    let hybrid = args.hybrid_key.is_some();
    let auth_groups = match auth_groups_from_args(&args.authkems, hybrid) {
        Ok(groups) => {
            println!("Loaded {} authentication KEM group(s)", groups.len());
            for group in &groups {
                println!("  Auth group: {:?}", group);
            }
            groups
        }
        Err(e) => {
            debug!("Error with authkem algorithm list: {}", e);
            std::process::exit(1);
        }
    };

    let mut crypto_provider = provider();
    crypto_provider.kx_groups = combined_kx_groups();

    if let Some(ref group_name) = args.group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name, args.pqc_provider);
    } else {
        println!("Using all available traditional and PQ KX groups");
    }

    println!("Provider has {} kx_groups", crypto_provider.kx_groups.len());
    for kx in &crypto_provider.kx_groups {
        println!("  KX group: {:?}", kx.name());
    }

    let mut server_config = match create_server_config(
        auth_groups,
        crypto_provider,
        args.client_auth,
        &args.cert_file,
        &args.pk_file,
        &args.ca_file,
        args.keys_dir,
        args.hybrid_key,
    ) {
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
            let _ = server_config.set_cid(&[cid_val]);
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
