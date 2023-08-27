use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{RootCertStore, ServerConfig};
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::path::Path;
use std::sync::Arc;

pub fn load_certificates<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<rustls::Certificate>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect())
}

pub fn load_private_key<P: AsRef<Path>>(path: P) -> std::io::Result<rustls::PrivateKey> {
    let mut reader = BufReader::new(File::open(&path)?);
    let key = match rustls_pemfile::read_one(&mut reader)?.ok_or(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("no private key found in file: {}", path.as_ref().display()),
    ))? {
        rustls_pemfile::Item::RSAKey(key) => key,
        rustls_pemfile::Item::PKCS8Key(key) => key,
        rustls_pemfile::Item::ECKey(key) => key,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "invalid private key format (requires RSA, EC, or PKCS): {}",
                    path.as_ref().display()
                ),
            ))
        }
    };
    Ok(rustls::PrivateKey(key))
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

    const CERTS_DIR: &str = "certs";
    const CA_PATH: &str = "./certs/RootCA.pem";
    const TEST_CRT: &str = "./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.crt";
    const TEST_KEY: &str = "./certs/ddpwuxrmp.uk/ddpwuxrmp.uk.key";

    #[test]
    fn test_server_config() {
        std::process::Command::new("/bin/sh")
            .args(&["./gen-certs.sh", "ddpwuxrmp.uk"])
            .output()
            .expect("failed to create certs");
        let ca = load_certificates(CA_PATH).expect("failed to load ca");
        let certs = load_certificates(TEST_CRT).expect("failed to load certs");
        let key = load_private_key(TEST_KEY).expect("failed to key");
        build_server_config(ca, certs, key).expect("failed to build server config");
        let _ = std::fs::remove_dir_all(CERTS_DIR);
    }
}
