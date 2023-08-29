use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, ClientConfig, RootCertStore, ServerConfig};
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
    let mut items = rustls_pemfile::read_all(&mut reader)?
        .into_iter()
        .filter_map(|item| {
            if let RSAKey(key) | PKCS8Key(key) | ECKey(key) = item {
                Some(rustls::PrivateKey(key))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    match items.len() {
        0 => Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "no private key found in file (requires RSA, EC, or PKCS): {}",
                path.as_ref().display()
            ),
        )),
        1 => Ok(rustls::PrivateKey(items.remove(0).0)),
        _ => Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "multiple private keys found in file: {}",
                path.as_ref().display()
            ),
        )),
    }
}

/// Build a `rustls::ServerConfig` struct with client Auth.
pub fn build_crypto(
    ca: Vec<rustls::Certificate>,
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> std::io::Result<(ServerConfig, ClientConfig)> {
    let root_store = build_root_store(&ca)?;
    let server_config = build_server_config(root_store.clone(), certs.clone(), key.clone())?;
    let client_config = build_client_config(root_store, certs, key)?;
    Ok((server_config, client_config))
}

/// Use WebPKI X.509 Certificate Validation to obtain domain name
/// from certificate.
pub fn try_parse_cert(cert: &Certificate) -> std::io::Result<webpki::EndEntityCert> {
    webpki::EndEntityCert::try_from(cert.0.as_slice()).map_err(|e| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse certificate: {e}"),
        )
    })
}

/// config for server
fn build_server_config(
    root_store: RootCertStore,
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> std::io::Result<rustls::ServerConfig> {
    rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(root_store)))
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("failed to build server config: {e}"),
            )
        })
}

/// config for client
fn build_client_config(
    root_store: RootCertStore,
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> std::io::Result<rustls::ClientConfig> {
    rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("failed to build cient config: {e}"),
            )
        })
}

fn build_root_store(ca: &[rustls::Certificate]) -> std::io::Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let (_, ignored) = root_store.add_parsable_certificates(&ca);
    if ignored > 0 {
        Err(std::io::Error::new(
            ErrorKind::Other,
            format!("{ignored} root certs ignored"),
        ))
    } else {
        Ok(root_store)
    }
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
        build_crypto(ca, certs, key).expect("failed to build server config");
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
