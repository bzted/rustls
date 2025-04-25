use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use kemtls_provider::provider;
use kemtls_provider::verify::Verifier;
use log::debug;
use rustls::{ClientConfig, ClientConnection};

fn main() {
    env_logger::init();

    let server_verifier = Arc::new(Verifier);

    let crypto_provider = provider();

    let client_config = ClientConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_no_client_auth();

    let server_name = "servername".try_into().unwrap();
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
        "Curernt ciphersuite: {:?}",
        cs.suite()
    )
    .unwrap();

    let mut plaintext = Vec::new();
    tls_stream
        .read_to_end(&mut plaintext)
        .unwrap();
    stdout().write_all(&plaintext).unwrap();
}
