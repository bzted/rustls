use kemtls_provider::provider;
use log::debug;
use rustls::pki_types::pem::PemObject;
use rustls::server::Acceptor;
use rustls::ServerConfig;
use std::io::Write;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    debug!("Starting traditional server...");
    let mut args = std::env::args();
    args.next();
    let cert_file = args.next().expect("no cert file");

    let pk_file = args.next().expect("no pk file");

    let cert = rustls::pki_types::CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();

    let pk = rustls::pki_types::PrivateKeyDer::from_pem_file(pk_file).unwrap();
    // Set up TLS server with AuthKEM provider
    let crypto_provider = provider();

    debug!("Provider has {} kx_groups", crypto_provider.kx_groups.len());
    for kx in &crypto_provider.kx_groups {
        debug!("  KX group: {:?}", kx.name());
    }

    //let mut server_config = ServerConfig::builder_with_provider(crypto_provider.into())
    //    .with_safe_default_protocol_versions()
    //    .unwrap()
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, pk)?;

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    debug!("Server config created successfully");

    let listener = std::net::TcpListener::bind(format!("[::]:{}", 8443)).unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone().into()) {
            Ok(mut conn) => {
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }
    Ok(())
}
