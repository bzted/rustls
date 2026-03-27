use kemtls_provider::{provider, get_pq_kx_group_by_name, get_kx_group_by_name, DEFAULT_KX_GROUPS};
use log::debug;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;
use rustls::crypto::CryptoProvider;
use std::cmp::Ordering;

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 1;

// DTLS Helper Functions

#[derive(Parser, Debug)]
#[command(author, version, about = "KEMTLS/DTLS 1.3 Client")]
struct Args {
    /// KX group to use (e.g. MLKEM768, BikeL3, Hqc192, NtruPrimeSntrup761)
    #[arg(short, long)]
    group: Option<String>,

    /// Optional CID value to offer in DTLS (0-255)
    #[arg(long)]
    cid: Option<u8>,

    /// Maximum fragment length for DTLS
    #[arg(short = 'L', default_value_t = 1300)]
    max_fragment_length: usize,

    /// Disables client authentication
    #[arg(short = 'd', default_value_t = true, action = clap::ArgAction::SetFalse)]
    client_auth: bool,

    /// Certificate File
    #[arg(short = 'c', default_value = "../test-ca/rsa-2048/client.fullchain")]
    cert_file: String,

    /// Key file
    #[arg(short = 'k', default_value = "../test-ca/rsa-2048/client.key")]
    pk_file: String,

    /// Certificate Authority file
    #[arg(short = 'A', default_value = "../test-ca/rsa-2048/ca.cert")]
    ca_file: String,

    /// Port to listen on 
    #[arg(short, long, default_value_t = 8443)]
    port: u16,

    /// Address to connect to
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,

    /// Activates PQC provider
    #[arg(short = 'q' ,long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    pqc_provider: bool,

    /// Payload bytes to send after handshake
    #[arg(short = 'B', long, default_value = "1000")]
    payload_size: usize,

    /// Iterations to bench
    #[arg(short = 'n', long, default_value_t = 1)]
    iterations: usize,

    /// Warmup iterations
    #[arg(long, default_value_t = 5)]
    warmup: usize,

    /// CSV file for results
    #[arg(long)]
    csv: Option<String>,

    /// Incrementar puertos de cliente (para medidas)
    #[arg(long, default_value_t = false, action = clap::ArgAction::SetTrue)]
    incremental_ports: bool,

    /// Puerto inicial
    #[arg(long, default_value_t = 50000)]
    base_local_port: u16,
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

fn setup_udp_socket(server_addr: &str, local_port: Option<u16>) -> Result<UdpSocket, std::io::Error> {
    let bind_addr = match local_port {
        Some(port) => format!("0.0.0.0:{port}"),
        None => "0.0.0.0:0".to_string(),
    };

    let socket = UdpSocket::bind(bind_addr)?;
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

fn receive_dtls_datagram(
    socket: &UdpSocket,
    conn: &mut ClientConnection,
    buffer: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    match socket.recv(buffer){
        Ok(n) =>{
            let mut slice = &buffer[..n];
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
    payload_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Read;

    let mut file = std::fs::File::open("/dev/zero")?;
    let mut buffer = vec![0u8; payload_size];
    file.read_exact(&mut buffer)?;

    conn.writer().write_all(&buffer)?;
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
        {
            let mut reader = conn.reader();
            match reader.read(&mut tmp) {
                Ok(0) => {}
                Ok(n) => {
                    plaintext.extend_from_slice(&tmp[..n]);
                    if plaintext.len() > 0 && n < BUFFER_SIZE {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(Box::new(e)),
            }
        }

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
    payload_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = setup_udp_socket(server_addr, Some(0 as u16))?;
    let mut conn = ClientConnection::new_dtls(Arc::new(client_config), server_name)?;

    perform_dtls_handshake(&socket, &mut conn)?;

    let request = b"Hello from DTLS client!\n";
    send_http_request(&socket, &mut conn, payload_size)?;

    println!("Waiting for response...");
    let response = receive_http_response(&socket, &mut conn)?;

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
    debug!("Connecting to server at {}...", server_addr);
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
        debug!("Using DTLS 1.3");
        use_dtls = true;
    }

    let args = Args::parse();

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

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(args.ca_file)
            .expect("cannot open ca file")
            .map(|result| result.unwrap()),
    );

    let cert: Vec<CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_file_iter(args.cert_file)
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect();

    let pk = rustls::pki_types::PrivateKeyDer::from_pem_file(args.pk_file).unwrap();

    let mut client_config = match args.client_auth {
        true => {
            ClientConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
                .with_root_certificates(root_store)
                .with_client_auth_cert(cert, pk).unwrap()
        }

        false => {
            ClientConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    // Disable session resumption for testing purposes
    client_config.resumption = rustls::client::Resumption::disabled();
    
    let server_name: rustls::pki_types::ServerName<'static> = args.addr.clone().try_into().unwrap();
    let server_addr = format!("{}:{}", args.addr, args.port);

    let result = if use_dtls {
        println!("Max fragment size set to: {}", args.max_fragment_length);
        client_config.max_fragment_size = Some(args.max_fragment_length);

        if let Some(cid_val) = args.cid {
            println!("Offering CID: {}", cid_val);
            client_config.set_cid(&[cid_val]);
        }
        
        if args.iterations > 1 || args.csv.is_some() {
            run_dtls_benchmark(
                client_config,
                server_name,
                &server_addr,
                args.payload_size,
                args.iterations,
                args.warmup,
                args.csv.as_deref(),
                args.incremental_ports,
                args.base_local_port,
            )
        } else {
            run_dtls_client(client_config, server_name, &server_addr, args.payload_size)
        }
    } else {
        run_tls_client(client_config, server_name, &server_addr)
    };

    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

/// Benchmarks

#[derive(Debug)]
struct BenchRow {
    iter: usize,
    status: String,
    handshake_ms: Option<f64>,
    transaction_ms: Option<f64>,
    error: Option<String>,
}

fn run_one_dtls_connection(
    iter: usize,
    client_config: Arc<ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
    server_addr: &str,
    payload_size: usize,
    local_port: Option<u16>,
) -> BenchRow {
    let socket = match setup_udp_socket(server_addr, local_port) {
        Ok(s) => s,
        Err(e) => {
            return BenchRow {
                iter,
                status: "ERROR".to_string(),
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
                handshake_ms: None,
                transaction_ms: None,
                error: Some(format!("conn: {}", e)),
            };
        }
    };

    let t0 = std::time::Instant::now();

    if let Err(e) = perform_dtls_handshake(&socket, &mut conn) {
        return BenchRow {
            iter,
            status: "ERROR".to_string(),
            handshake_ms: None,
            transaction_ms: None,
            error: Some(format!("handshake: {}", e)),
        };
    }

    let t1 = std::time::Instant::now();
    let handshake_ms = t1.duration_since(t0).as_secs_f64() * 1000.0;

    if let Err(e) = send_http_request(&socket, &mut conn, payload_size) {
        return BenchRow {
            iter,
            status: "ERROR".to_string(),
            handshake_ms: Some(handshake_ms),
            transaction_ms: None,
            error: Some(format!("send_app: {}", e)),
        };
    }

    match receive_http_response(&socket, &mut conn) {
        Ok(_response) => {
            let t2 = std::time::Instant::now();
            let transaction_ms = t2.duration_since(t0).as_secs_f64() * 1000.0;

            BenchRow {
                iter,
                status: "OK".to_string(),
                handshake_ms: Some(handshake_ms),
                transaction_ms: Some(transaction_ms),
                error: None,
            }
        }
        Err(e) => BenchRow {
            iter,
            status: "ERROR".to_string(),
            handshake_ms: Some(handshake_ms),
            transaction_ms: None,
            error: Some(format!("recv_app: {}", e)),
        },
    }
}

fn write_bench_csv(
    path: &str,
    rows: &[BenchRow],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record([
        "iter",
        "status",
        "handshake_ms",
        "transaction_ms",
        "error",
    ])?;

    for row in rows {
        wtr.write_record([
            row.iter.to_string(),
            row.status.clone(),
            row.handshake_ms.map(|v| format!("{:.4}", v)).unwrap_or_default(),
            row.transaction_ms.map(|v| format!("{:.4}", v)).unwrap_or_default(),
            row.error.clone().unwrap_or_default(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

fn run_dtls_benchmark(
    client_config: ClientConfig,
    server_name: rustls::pki_types::ServerName<'static>,
    server_addr: &str,
    payload_size: usize,
    iterations: usize,
    warmup: usize,
    csv_path: Option<&str>,
    incremental_ports: bool,
    base_local_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_config = Arc::new(client_config);

    for i in 0..warmup {
        let local_port = if incremental_ports {
            Some(base_local_port.saturating_add(i as u16))
        } else {
            None
        };

        let _ = run_one_dtls_connection(
            i,
            shared_config.clone(),
            server_name.clone(),
            server_addr,
            payload_size,
            local_port
        );
    }

    let mut rows = Vec::with_capacity(iterations);

    for i in 1..=iterations {
        let local_port = if incremental_ports {
            Some(base_local_port.saturating_add((warmup + i) as u16))
        } else {
            None
        };

        let row = run_one_dtls_connection(
            i,
            shared_config.clone(),
            server_name.clone(),
            server_addr,
            payload_size,
            local_port,
        );

        if i % 100 == 0 || i == iterations {
            println!("{} / {}", i, iterations);
        }

        rows.push(row);
    }

    if let Some(path) = csv_path {
        write_bench_csv(path, &rows)?;

        if let Some(stats) = compute_summary_stats(&rows) {
            let summary_path = if let Some(base) = path.strip_suffix(".csv") {
                format!("{}_summary.csv", base)
            } else {
                format!("{}_summary.csv", path)
            };

            write_summary_csv(&summary_path, &stats)?;

            println!("Resumen guardado en: {}", summary_path);
            println!("OK: {} / {}", stats.iterations_ok, stats.iterations_total);
            println!("Media transaction_ms: {:.4} ms", stats.mean_ms);
            println!("Mediana transaction_ms: {:.4} ms", stats.median_ms);
            println!("Min transaction_ms: {:.4} ms", stats.min_ms);
            println!("Max transaction_ms: {:.4} ms", stats.max_ms);
            println!("Desviación estándar transaction_ms: {:.4} ms", stats.stddev_ms);
        } else {
            println!("No hay medidas válidas para calcular estadísticas.");
        }
    } else {
        if let Some(stats) = compute_summary_stats(&rows) {
            println!("OK: {} / {}", stats.iterations_ok, stats.iterations_total);
            println!("Media transaction_ms: {:.4} ms", stats.mean_ms);
            println!("Mediana transaction_ms: {:.4} ms", stats.median_ms);
            println!("Min transaction_ms: {:.4} ms", stats.min_ms);
            println!("Max transaction_ms: {:.4} ms", stats.max_ms);
            println!("Desviación estándar transaction_ms: {:.4} ms", stats.stddev_ms);
        } else {
            println!("No hay medidas válidas para calcular estadísticas.");
        }
    };

    Ok(())
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
        .filter_map(|r| {
            if r.status == "OK" {
                r.transaction_ms
            } else {
                None
            }
        })
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
        valid.iter()
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