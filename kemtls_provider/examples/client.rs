use kemtls_provider::provider;
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

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 1;

// DTLS Helper Functions

#[derive(Parser, Debug)]
#[command(author, version, about = "KEMTLS/DTLS 1.3 Client")]
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
}

fn setup_udp_socket(server_addr: &str) -> Result<UdpSocket, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
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
            debug!("Sending DTLS datagram of {} bytes", out.len());
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
    request: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    conn.writer().write_all(request)?;
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
        // Try to read already decrypted data
        {
            let mut reader = conn.reader();
            match reader.read(&mut tmp) {
                Ok(0) => {
                    // No data available yet
                }
                Ok(n) => {
                    plaintext.extend_from_slice(&tmp[..n]);
                    debug!("Read {} bytes of plaintext", n);
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
    let request = b"Hello from DTLS client!\n";
    send_http_request(&socket, &mut conn, request)?;

    // Receive and display response
    println!("Waiting for response...");
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

    let crypto_provider = provider();

    let args = Args::parse();

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

    let mut client_config = match (args.pqc_provider, args.client_auth) {
        (true, true) => {
            ClientConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
                .with_root_certificates(root_store)
                .with_client_auth_cert(cert, pk).unwrap()
        }

        (true, false) => {
            ClientConfig::builder_with_provider(crypto_provider.into())
                .with_safe_default_protocol_versions().unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }

        (false, true) => {
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(cert, pk).unwrap()
        }

        (false, false) => {
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    let server_addr = format!("{}:{}", args.addr, args.port);
    let server_name = "testserver.com".try_into().unwrap();

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
