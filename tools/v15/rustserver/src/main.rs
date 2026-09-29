// Minimal rustls server for the v1.5 negotiation-function comparison.
// Usage: v15-rustls-server <port> <pem-with-cert-and-key> <comma-separated kx groups in order>
use std::{env, fs::File, io::BufReader, net::TcpListener, sync::Arc};

use rustls::crypto::aws_lc_rs as provider;

fn main() {
    let args: Vec<String> = env::args().collect();
    let (port, pem, groups) = (&args[1], &args[2], &args[3]);
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(pem).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(pem).unwrap()))
        .unwrap()
        .expect("no private key in PEM");
    let kx_groups = groups
        .split(',')
        .map(|name| match name {
            "X25519MLKEM768" => provider::kx_group::X25519MLKEM768,
            "X25519" => provider::kx_group::X25519,
            other => panic!("unknown group {other}"),
        })
        .collect();
    let crypto = rustls::crypto::CryptoProvider { kx_groups, ..provider::default_provider() };
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(crypto))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap();
    eprintln!("listening {port} groups={groups}");
    for stream in listener.incoming() {
        let Ok(mut sock) = stream else { continue };
        let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
        while conn.is_handshaking() {
            if conn.complete_io(&mut sock).is_err() {
                break;
            }
        }
        eprintln!("negotiated={:?}", conn.negotiated_key_exchange_group().map(|g| g.name()));
    }
}
