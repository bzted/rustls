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

const BUFFER_SIZE: usize = 4096;
const TIMEOUT_SECS: u64 = 1;
const SERVER_ADDR: &str = "127.0.0.1:8443";

// DTLS Helper Functions

fn setup_udp_socket() -> Result<UdpSocket, std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(SERVER_ADDR)?;
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
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = setup_udp_socket()?;
    let mut conn = ClientConnection::new_dtls(Arc::new(client_config), server_name)?;

    // Perform DTLS handshake
    perform_dtls_handshake(&socket, &mut conn)?;

    // Send HTTP request
    let request = b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n";
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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ClientConnection::new(Arc::new(client_config), server_name)?;
    debug!("Connecting to server at {}...", SERVER_ADDR);
    let mut stream = TcpStream::connect(SERVER_ADDR)?;
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

    let mut max_fragment_length = None;
    let crypto_provider = provider();

    let mut args = std::env::args();
    args.next();
    let ca_file = args.next().expect("no cert file");

    let length_str = args.next();

    if length_str.is_some() {
        match length_str.unwrap().parse::<usize>() {
                        Ok(val) => max_fragment_length = Some(val),
                        Err(_) => {
                            eprintln!("Error: -L must be a valid integer");
                            std::process::exit(1);
                        }
        }
    }

    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(ca_file)
            .expect("cannot open ca file")
            .map(|result| result.unwrap()),
    );

    //let client_config = ClientConfig::builder_with_provider(crypto_provider.into())
    //    .with_safe_default_protocol_versions()
    //    .unwrap()
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "testserver.com".try_into().unwrap();
    let result = if use_dtls {
        if let Some(length) = max_fragment_length {
            println!("Setting max fragment size to: {}", length);
            client_config.max_fragment_size = Some(length);
        }
        run_dtls_client(client_config, server_name)
    } else {
        run_tls_client(client_config, server_name)
    };

    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}
