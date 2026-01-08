use kemtls_provider::provider;
use log::debug;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use std::io::Write;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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

    let verifier = WebPkiClientVerifier::builder(root_store.into()).build()?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
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
