use super::{
    tls::{build_crypto, load_certificates, load_private_key},
    ServerConfig,
};
use std::{sync::Arc, time::Duration};

pub const KEEP_ALIVE_INTERVAL: Option<Duration> = Some(Duration::from_secs(15));

/// Create a default configuation for the QUIC server.
pub fn default_config(
    config: &ServerConfig,
    whitelist: Option<Vec<webpki::DnsName>>,
) -> std::io::Result<(quinn::ServerConfig, quinn::ClientConfig)> {
    let ca = load_certificates(&config.ca)?;
    let certs = load_certificates(&config.certs)?;
    let key = load_private_key(&config.key)?;
    let (server_crypto, client_crypto) = build_crypto(ca, whitelist, certs, key)?;
    let transport_config = default_transport_config();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    server_config.transport_config(transport_config.clone());
    client_config.transport_config(transport_config);
    Ok((server_config, client_config))
}

/// Default transport config.
///
/// - keep alive interval = 15 sec
/// - disable idle timeout
fn default_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(KEEP_ALIVE_INTERVAL);
    transport_config.max_idle_timeout(None);
    Arc::new(transport_config)
}
