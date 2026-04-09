use std::cmp::Ordering;
use std::convert::TryInto;
use std::fs;
use std::io::{stdout, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kemtls_provider::resolver::{ClientCertResolver, KeyPair};
use kemtls_provider::sign::DummySigningKey;
use kemtls_provider::verify::ClientVerifier;
use kemtls_provider::{get_pq_kx_group_by_name, provider, HybridKemKey, PureKemKey};
use log::debug;
use openssl::pkey::{Id, PKey};
use oqs::kem::Kem;
use rustls::crypto::CryptoProvider;
use rustls::sign::KemKey;
use rustls::{ClientConfig, ClientConnection, Error};

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 1;

#[derive(Debug, Clone)]
struct ClientArgs {
    group: Option<String>,
    authkem: String,
    cid: Option<u8>,
    max_fragment_length: usize,
    client_auth: bool,
    port: u16,
    addr: String,
    payload_size: usize,
    hybrid: bool,
    x25519_key: Option<String>,
    iterations: usize,
    warmup: usize,
    csv: Option<String>,
}

impl Default for ClientArgs {
    fn default() -> Self {
        Self {
            group: None,
            authkem: "MLKEM768".to_string(),
            cid: None,
            max_fragment_length: 1300,
            client_auth: true,
            port: 8443,
            addr: "127.0.0.1".to_string(),
            payload_size: 1000,
            hybrid: false,
            x25519_key: None,
            iterations: 1,
            warmup: 5,
            csv: None,
        }
    }
}

fn print_usage(program: &str) {
    eprintln!(
        r"Usage: {program} [options]
         Options:
           -g, --group <NAME>              KX group to use
           -a, --authkem <NAME>            KEM algorithm for client authentication [default: MLKEM768]
           -c, --cid <0-255>               Optional CID value to offer in DTLS
           -L, --max-fragment-length <N>   Maximum fragment length for DTLS [default: 1300]
           -d, --client_auth               Disable client authentication
           -p, --port <PORT>               Port to connect to [default: 8443]
           --addr <ADDR>               Address to connect to [default: 127.0.0.1]
           -B, --payload-size <BYTES>      Payload bytes to send after handshake [default: 1000]
               --hybrid                    Enable hybrid KEMs
           -k, --x25519-key <PATH>         X25519 private key PEM path
           -n, --iterations <N>            Iterations to bench [default: 1]
               --warmup <N>                Warmup iterations [default: 5]
               --csv <PATH>                CSV file for results
           -h, --help                      Show this help message"
    );
}

fn take_value<I>(it: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    it.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_u8(value: &str, flag: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn parse_u16(value: &str, flag: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn parse_args() -> Result<ClientArgs, String> {
    let mut args = ClientArgs::default();
    let mut it = std::env::args();
    let program = it.next().unwrap_or_else(|| "kem_c".to_string());

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage(&program);
                std::process::exit(0);
            }
            "-g" | "--group" => {
                args.group = Some(take_value(&mut it, &arg)?);
            }
            "-a" | "--authkem" => {
                args.authkem = take_value(&mut it, &arg)?;
            }
            "-c" | "--cid" => {
                let v = take_value(&mut it, &arg)?;
                args.cid = Some(parse_u8(&v, &arg)?);
            }
            "-L" | "--max-fragment-length" => {
                let v = take_value(&mut it, &arg)?;
                args.max_fragment_length = parse_usize(&v, &arg)?;
            }
            "-d" | "--client_auth" => {
                args.client_auth = false;
            }
            "-p" | "--port" => {
                let v = take_value(&mut it, &arg)?;
                args.port = parse_u16(&v, &arg)?;
            }
            "--addr" => {
                args.addr = take_value(&mut it, &arg)?;
            }
            "-B" | "--payload-size" => {
                let v = take_value(&mut it, &arg)?;
                args.payload_size = parse_usize(&v, &arg)?;
            }
            "--hybrid" => {
                args.hybrid = true;
            }
            "-k" | "--x25519-key" => {
                args.x25519_key = Some(take_value(&mut it, &arg)?);
            }
            "-n" | "--iterations" => {
                let v = take_value(&mut it, &arg)?;
                args.iterations = parse_usize(&v, &arg)?;
            }
            "--warmup" => {
                let v = take_value(&mut it, &arg)?;
                args.warmup = parse_usize(&v, &arg)?;
            }
            "--csv" => {
                args.csv = Some(take_value(&mut it, &arg)?);
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--group=") {
                    args.group = Some(value.to_string());
                } else if let Some(value) = arg.strip_prefix("--authkem=") {
                    args.authkem = value.to_string();
                } else if let Some(value) = arg.strip_prefix("--cid=") {
                    args.cid = Some(parse_u8(value, "--cid")?);
                } else if let Some(value) = arg.strip_prefix("--max-fragment-length=") {
                    args.max_fragment_length = parse_usize(value, "--max-fragment-length")?;
                } else if let Some(value) = arg.strip_prefix("--port=") {
                    args.port = parse_u16(value, "--port")?;
                } else if let Some(value) = arg.strip_prefix("--addr=") {
                    args.addr = value.to_string();
                } else if let Some(value) = arg.strip_prefix("--payload-size=") {
                    args.payload_size = parse_usize(value, "--payload-size")?;
                } else if let Some(value) = arg.strip_prefix("--x25519-key=") {
                    args.x25519_key = Some(value.to_string());
                } else if let Some(value) = arg.strip_prefix("--iterations=") {
                    args.iterations = parse_usize(value, "--iterations")?;
                } else if let Some(value) = arg.strip_prefix("--warmup=") {
                    args.warmup = parse_usize(value, "--warmup")?;
                } else if let Some(value) = arg.strip_prefix("--csv=") {
                    args.csv = Some(value.to_string());
                } else {
                    return Err(format!("unknown argument: {arg}"));
                }
            }
        }
    }

    if args.hybrid && args.x25519_key.is_none() {
        return Err("--hybrid requires --x25519-key <PATH>".to_string());
    }

    Ok(args)
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
    if let Some(selected_group) = get_pq_kx_group_by_name(group) {
        crypto_provider.kx_groups = vec![selected_group];
    } else {
        println!("Unknown group, using default groups");
        println!("Available groups: MLKEM512, MLKEM768, MLKEM1024, BikeL1, BikeL3, BikeL5, Hqc128, Hqc192, Hqc256, NtruPrimeSntrup761");
    }
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
        let mut out_buf = Vec::new();
        match conn.write_dtls(&mut out_buf) {
            Ok(0) => break,
            Ok(n) => {
                debug!("DTLS datagram len = {} bytes", n);
                socket.send(&out_buf)?;
            }
            Err(e) => return Err(e),
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
                let mut slice = &in_buf[..n];
                while !slice.is_empty() {
                    conn.read_tls(&mut slice)?;
                }
                conn.process_new_packets()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                conn.process_new_packets()?;
            }
            Err(e) => return Err(Box::new(e)),
        }
    }
    debug!("DTLS handshake completed");
    Ok(())
}

fn send_http_request(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
    payload_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open("/dev/zero")?;
    let mut buffer = vec![0u8; payload_size];
    file.read_exact(&mut buffer)?;

    conn.writer().write_all(&buffer)?;
    send_dtls_datagram(socket, conn)?;
    Ok(())
}

fn receive_http_response(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
    expected_size: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut in_buf = [0u8; BUFFER_SIZE];
    let mut plaintext = Vec::new();

    while plaintext.len() < expected_size {
        let mut tmp = [0u8; BUFFER_SIZE];
        loop {
            let mut reader = conn.reader();
            match reader.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    plaintext.extend_from_slice(&tmp[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(Box::new(e)),
            }
        }

        if plaintext.len() >= expected_size {
            break;
        }

        match socket.recv(&mut in_buf) {
            Ok(n) => {
                let mut slice = &in_buf[..n];
                while !slice.is_empty() {
                    conn.read_tls(&mut slice)?;
                }
                conn.process_new_packets()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                conn.process_new_packets()?;
            }
            Err(e) => return Err(Box::new(e)),
        }
    }

    Ok(plaintext)
}

fn run_dtls_client(
    client_config: ClientConfig,
    server_name: rustls::pki_types::ServerName<'static>,
    server_addr: &str,
    payload_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = setup_udp_socket(server_addr)?;
    let mut conn = ClientConnection::new_dtls(Arc::new(client_config), server_name)?;

    perform_dtls_handshake(&socket, &mut conn)?;
    send_http_request(&socket, &mut conn, payload_size)?;

    let response = receive_http_response(&socket, &mut conn, payload_size)?;

    println!("Response received:");
    println!("{:?}", String::from_utf8_lossy(&response));

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

    let cs = tls_stream.conn.negotiated_cipher_suite().unwrap();
    writeln!(&mut std::io::stderr(), "Current ciphersuite: {:?}", cs.suite())?;

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

    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Argument error: {e}");
            let program = std::env::args().next().unwrap_or_else(|| "kem_c".to_string());
            print_usage(&program);
            std::process::exit(2);
        }
    };

    let server_addr = format!("{}:{}", args.addr, args.port);
    let server_name = "servername".try_into().unwrap();

    let result = if use_dtls {
        println!("Max fragment size set to: {}", args.max_fragment_length);

        if args.iterations > 1 || args.csv.is_some() {
            run_dtls_kemtls_benchmark(&args, server_name, &server_addr)
        } else {
            let client_config = match build_kemtls_client_config(&args) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!("Error building client config: {:?}", e);
                    std::process::exit(1);
                }
            };

            run_dtls_client(client_config, server_name, &server_addr, args.payload_size)
        }
    } else {
        let client_config = match build_kemtls_client_config(&args) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error building client config: {:?}", e);
                std::process::exit(1);
            }
        };

        run_tls_client(client_config, server_name, &server_addr)
    };

    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

#[derive(Debug, Clone)]
struct BenchRow {
    iter: usize,
    status: String,
    setup_ms: Option<f64>,
    handshake_ms: Option<f64>,
    transaction_ms: Option<f64>,
    error: Option<String>,
}

#[derive(Debug)]
struct SummaryStats {
    iterations_total: usize,
    iterations_ok: usize,
    iterations_error: usize,
    iterations_timeout: usize,
    sum_ms: f64,
    mean_ms: f64,
    median_ms: f64,
    min_ms: f64,
    max_ms: f64,
    stddev_ms: f64,
}

fn compute_percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }

    let n = sorted.len() as f64;
    let rank = p * (n - 1.0);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        sorted[lower]
    } else {
        let weight = rank - lower as f64;
        sorted[lower] * (1.0 - weight) + sorted[upper] * weight
    }
}

fn compute_summary_stats(rows: &[BenchRow]) -> Option<SummaryStats> {
    let mut valid: Vec<f64> = rows
        .iter()
        .filter_map(|r| if r.status == "OK" { r.transaction_ms } else { None })
        .collect();

    let iterations_total = rows.len();
    let iterations_ok = valid.len();
    let iterations_error = rows.iter().filter(|r| r.status == "ERROR").count();
    let iterations_timeout = rows
        .iter()
        .filter(|r| {
            r.error
                .as_deref()
                .map(|e| e.to_ascii_lowercase().contains("timeout"))
                .unwrap_or(false)
        })
        .count();

    if valid.is_empty() {
        return None;
    }

    valid.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

    let sum_ms: f64 = valid.iter().sum();
    let mean_ms = sum_ms / valid.len() as f64;
    let median_ms = compute_percentile(&valid, 0.50);
    let min_ms = valid[0];
    let max_ms = valid[valid.len() - 1];

    let variance = if valid.len() > 1 {
        valid
            .iter()
            .map(|v| {
                let d = *v - mean_ms;
                d * d
            })
            .sum::<f64>()
            / (valid.len() as f64 - 1.0)
    } else {
        0.0
    };

    let stddev_ms = variance.sqrt();

    Some(SummaryStats {
        iterations_total,
        iterations_ok,
        iterations_error,
        iterations_timeout,
        sum_ms,
        mean_ms,
        median_ms,
        min_ms,
        max_ms,
        stddev_ms,
    })
}

fn write_bench_csv(path: &str, rows: &[BenchRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record([
        "iter",
        "status",
        "setup_ms",
        "handshake_ms",
        "transaction_ms",
        "error",
    ])?;

    for row in rows {
        wtr.write_record([
            row.iter.to_string(),
            row.status.clone(),
            row.setup_ms.map(|v| format!("{:.4}", v)).unwrap_or_default(),
            row.handshake_ms
                .map(|v| format!("{:.4}", v))
                .unwrap_or_default(),
            row.transaction_ms
                .map(|v| format!("{:.4}", v))
                .unwrap_or_default(),
            row.error.clone().unwrap_or_default(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

fn write_summary_csv(
    path: &str,
    stats: &SummaryStats,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["metric", "value"])?;

    wtr.write_record(["iterations_total", &stats.iterations_total.to_string()])?;
    wtr.write_record(["iterations_ok", &stats.iterations_ok.to_string()])?;
    wtr.write_record(["iterations_error", &stats.iterations_error.to_string()])?;
    wtr.write_record(["iterations_timeout", &stats.iterations_timeout.to_string()])?;

    wtr.write_record(["sum_ms", &format!("{:.4}", stats.sum_ms)])?;
    wtr.write_record(["mean_ms", &format!("{:.4}", stats.mean_ms)])?;
    wtr.write_record(["median_ms", &format!("{:.4}", stats.median_ms)])?;
    wtr.write_record(["min_ms", &format!("{:.4}", stats.min_ms)])?;
    wtr.write_record(["max_ms", &format!("{:.4}", stats.max_ms)])?;
    wtr.write_record(["stddev_ms", &format!("{:.4}", stats.stddev_ms)])?;

    wtr.flush()?;
    Ok(())
}

fn build_kemtls_client_config(
    args: &ClientArgs,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut crypto_provider = provider();

    if let Some(ref group_name) = args.group {
        println!("Selecting KX group: {}", group_name);
        select_kx_group(&mut crypto_provider, group_name);
    } else {
        debug!("Using all available KX groups");
    }

    let kemalg = get_kem_algorithm(&args.authkem)
        .map_err(|e| format!("Error with authkem algorithm: {}", e))?;

    let kem = Kem::new(kemalg).map_err(|e| format!("Failed to create Kem instance: {e:?}"))?;
    let (public_key, secret_key) = kem.keypair().map_err(|e| format!("Failed to generate Kem keypair: {e:?}"))?;

    let signing_key = Arc::new(DummySigningKey);

    let (kem_key, x25519_sk, x25519_pk) = match args.hybrid {
        true => {
            let path = args.x25519_key.clone().ok_or("Invalid x25519 key path")?;
            let (x25519_sk, x25519_pk) = load_x25519_keypair_from_pem(&path)?;
            let kem_key: Arc<dyn KemKey> =
                Arc::new(HybridKemKey::new(kemalg, secret_key.as_ref().to_vec(), x25519_sk));
            (kem_key, Some(x25519_sk), Some(x25519_pk))
        }
        false => {
            let kem_key: Arc<dyn KemKey> =
                Arc::new(PureKemKey::new(kemalg, secret_key.as_ref().to_vec()));
            (kem_key, None, None)
        }
    };

    let key_pair = KeyPair::new(public_key, x25519_pk, signing_key, Some(kem_key));
    let resolver = Arc::new(ClientCertResolver::new(key_pair));
    let server_verifier = Arc::new(ClientVerifier::new(kemalg, x25519_sk, x25519_pk));

    let mut client_config = match args.client_auth {
        true => ClientConfig::builder_with_provider(crypto_provider.into())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_cert_resolver(resolver),

        false => ClientConfig::builder_with_provider(crypto_provider.into())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_no_client_auth(),
    };

    client_config.resumption = rustls::client::Resumption::disabled();
    client_config.max_fragment_size = Some(args.max_fragment_length);
    //client_config.kemtls_enabled = true;

    if let Some(cid_val) = args.cid {
        client_config.set_cid(&[cid_val]);
    }

    Ok(client_config)
}

fn run_one_dtls_connection(
    iter: usize,
    client_config: Arc<ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
    server_addr: &str,
    payload_size: usize,
    setup_ms: Option<f64>,
) -> BenchRow {
    let socket = match setup_udp_socket(server_addr) {
        Ok(s) => s,
        Err(e) => {
            return BenchRow {
                iter,
                status: "ERROR".to_string(),
                setup_ms,
                handshake_ms: None,
                transaction_ms: None,
                error: Some(format!("socket: {}", e)),
            };
        }
    };

    let mut conn = match ClientConnection::new_dtls(client_config, server_name) {
        Ok(c) => c,
        Err(e) => {
            return BenchRow {
                iter,
                status: "ERROR".to_string(),
                setup_ms,
                handshake_ms: None,
                transaction_ms: None,
                error: Some(format!("conn: {}", e)),
            };
        }
    };

    let t0 = Instant::now();

    if let Err(e) = perform_dtls_handshake(&socket, &mut conn) {
        return BenchRow {
            iter,
            status: "ERROR".to_string(),
            setup_ms,
            handshake_ms: None,
            transaction_ms: None,
            error: Some(format!("handshake: {}", e)),
        };
    }

    let t1 = Instant::now();
    let handshake_ms = t1.duration_since(t0).as_secs_f64() * 1000.0;

    if let Err(e) = send_http_request(&socket, &mut conn, payload_size) {
        return BenchRow {
            iter,
            status: "ERROR".to_string(),
            setup_ms,
            handshake_ms: Some(handshake_ms),
            transaction_ms: None,
            error: Some(format!("send_app: {}", e)),
        };
    }

    match receive_http_response(&socket, &mut conn, payload_size) {
        Ok(_response) => {
            let t2 = Instant::now();
            let transaction_ms = t2.duration_since(t0).as_secs_f64() * 1000.0;

            BenchRow {
                iter,
                status: "OK".to_string(),
                setup_ms,
                handshake_ms: Some(handshake_ms),
                transaction_ms: Some(transaction_ms),
                error: None,
            }
        }
        Err(e) => BenchRow {
            iter,
            status: "ERROR".to_string(),
            setup_ms,
            handshake_ms: Some(handshake_ms),
            transaction_ms: None,
            error: Some(format!("recv_app: {}", e)),
        },
    }
}

fn run_dtls_kemtls_benchmark(
    args: &ClientArgs,
    server_name: rustls::pki_types::ServerName<'static>,
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rows = Vec::with_capacity(args.iterations);

    let client_config = build_kemtls_client_config(args)?;
    let shared_config = Arc::new(client_config);

    for i in 0..args.warmup {
        let _ = run_one_dtls_connection(
            i,
            shared_config.clone(),
            server_name.clone(),
            server_addr,
            args.payload_size,
            None,
        );
    }

    for i in 1..=args.iterations {
        let row = run_one_dtls_connection(
            i,
            shared_config.clone(),
            server_name.clone(),
            server_addr,
            args.payload_size,
            None,
        );

        if i % 100 == 0 || i == args.iterations {
            println!("{} / {}", i, args.iterations);
        }

        rows.push(row);
    }

    if let Some(path) = args.csv.as_deref() {
        write_bench_csv(path, &rows)?;

        if let Some(stats) = compute_summary_stats(&rows) {
            let summary_path = if let Some(base) = path.strip_suffix(".csv") {
                format!("{}_summary.csv", base)
            } else {
                format!("{}_summary.csv", path)
            };

            write_summary_csv(&summary_path, &stats)?;

            println!("Resultados guardados en: {}", path);
            println!("Resumen guardado en: {}", summary_path);
            println!("OK: {} / {}", stats.iterations_ok, stats.iterations_total);
            println!("Mean transaction_ms: {:.4}", stats.mean_ms);
            println!("Median transaction_ms: {:.4}", stats.median_ms);
            println!("Min transaction_ms: {:.4} ms", stats.min_ms);
            println!("Max transaction_ms: {:.4} ms", stats.max_ms);
            println!(
                "Desviación estándar transaction_ms: {:.4} ms",
                stats.stddev_ms
            );
        } else {
            println!("No hay medidas válidas para calcular estadísticas.");
        }
    } else if let Some(stats) = compute_summary_stats(&rows) {
        println!("OK: {} / {}", stats.iterations_ok, stats.iterations_total);
        println!("Mean transaction_ms: {:.4}", stats.mean_ms);
        println!("Median transaction_ms: {:.4}", stats.median_ms);
        println!("Min transaction_ms: {:.4} ms", stats.min_ms);
        println!("Max transaction_ms: {:.4} ms", stats.max_ms);
        println!(
            "Desviación estándar transaction_ms: {:.4} ms",
            stats.stddev_ms
        );
    }

    Ok(())
}
