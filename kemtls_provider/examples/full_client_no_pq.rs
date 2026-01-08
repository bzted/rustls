use kemtls_provider::provider;
use log::debug;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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

    let cert: Vec<CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_file_iter(cert_file)
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect();

    let pk = rustls::pki_types::PrivateKeyDer::from_pem_file(pk_file).unwrap();

    //let client_config = ClientConfig::builder_with_provider(crypto_provider.into())
    //    .with_safe_default_protocol_versions()
    //    .unwrap()
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert, pk)?;

    let server_name = "testserver.com".try_into().unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    debug!("Connecting to server at 127.0.0.1:8443...");
    let mut stream = TcpStream::connect("127.0.0.1:8443").unwrap();

    stream.set_nodelay(true).unwrap();

    let mut tls_stream = rustls::Stream::new(&mut client, &mut stream);

    tls_stream
        .write_all(
            concat!(
                "GET / HTTP/1.1\n",
                "Host: www.rust-lang-org\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();

    let cs = tls_stream
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        cs.suite()
    )
    .unwrap();

    let mut plaintext = Vec::new();
    tls_stream
        .read_to_end(&mut plaintext)
        .unwrap();
    stdout().write_all(&plaintext).unwrap();

    Ok(())
}
