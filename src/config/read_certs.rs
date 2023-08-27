use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

pub fn load_certificates_from_pem(path: &str) -> Vec<rustls::Certificate> {
    let file = File::open(path).expect("Failed to open certificate file");
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).expect("Failed to parse certificate file");

    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

pub fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

fn build_server_config(
    ca_file_path: &str,
    cert_file_path: &str,
    key_file_path: &str,
) -> Arc<ServerConfig> {
    let ca_file = File::open(&ca_file_path).expect("Cannot open CA file");
    let mut reader = BufReader::new(ca_file);
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());
    let allow_authenticated = Arc::new(AllowAnyAuthenticatedClient::new(root_store));

    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();
    let versions = rustls::DEFAULT_VERSIONS.to_vec();

    let certs = load_certificates_from_pem(cert_file_path);
    let key = load_private_key(key_file_path);

    let config = rustls::ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_client_cert_verifier(allow_authenticated)
        .with_single_cert(certs, key)
        .expect("invalid client auth certs/key");
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use crate::config::read_certs::build_server_config;

    #[test]
    fn test_read_file() {
        let file = build_server_config(
            r"certs\RootCA.pem",
            r"certs\cert_ddpwuxrmp.uk\ddpwuxrmp.uk.crt",
            r"certs\cert_ddpwuxrmp.uk\ddpwuxrmp.uk.key",
        );
    }
}
