use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::Item::{ECKey, PKCS8Key, RSAKey};
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::path::Path;
use std::sync::Arc;

/// Load certificates.
pub fn load_certificates<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<rustls::Certificate>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect())
}

/// Load private key from file.
///
/// This function also supports concatenated private key format
/// (i.e. the private key is appended to the certificate file).
pub fn load_private_key<P: AsRef<Path>>(path: P) -> std::io::Result<rustls::PrivateKey> {
    let mut reader = BufReader::new(File::open(&path)?);
    loop {
        // if read_one returns `None`, no suitable private key is found
        let item = rustls_pemfile::read_one(&mut reader)?.ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "no private key found in file (requires RSA, EC, or PKCS): {}",
                path.as_ref().display()
            ),
        ))?;
        if let RSAKey(key) | PKCS8Key(key) | ECKey(key) = item {
            break Ok(rustls::PrivateKey(key));
        }
    }
}

pub fn build_server_config(
    ca: Vec<rustls::Certificate>,
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> std::io::Result<Arc<ServerConfig>> {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(&ca);
    Ok(Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(root_store)))
            .with_single_cert(certs, key)
            .map_err(|e| {
                std::io::Error::new(
                    ErrorKind::Other,
                    format!("failed to build server config: {e}"),
                )
            })?,
    ))
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    const CA_PATH: &str = "./certs/RootCA.pem";
    const EMPTY_CRT: &str = "./certs/empty/empty.crt";
    const EMPTY_KEY: &str = "./certs/empty/empty.key";
    const TEST_CRT: &str = "./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.crt";
    const TEST_KEY: &str = "./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.key";
    const CONCAT_CRT_KEY: &str = "./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.pem";

    #[test]
    fn test_server_config() {
        let ca = load_certificates(CA_PATH).expect("failed to load ca");
        let certs = load_certificates(TEST_CRT).expect("failed to load certs");
        let key = load_private_key(TEST_KEY).expect("failed to key");
        build_server_config(ca, certs, key).expect("failed to build server config");
    }

    #[test]
    fn test_empty_cert() {
        if let Ok(v) = load_certificates(EMPTY_CRT) {
            assert!(v.is_empty())
        } else {
            panic!("load_certificates should be OK reading empty file")
        }
    }

    #[test]
    fn test_empty_key() {
        assert!(load_private_key(EMPTY_KEY).is_err())
    }

    #[test]
    fn test_concat() {
        assert!(load_private_key(CONCAT_CRT_KEY).is_ok())
    }
}
