pub mod client_auth;
pub mod quic;
pub mod tls;

use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Deserialize)]
pub struct ServerConfig {
    pub ca: PathBuf,
    pub certs: PathBuf,
    pub key: PathBuf,
    pub addr: SocketAddr,
}

impl ServerConfig {
    /// The load function supports `toml`, `json`, `yaml` and many more formats.
    /// See [config-rs](https://docs.rs/config/latest/config/).
    pub fn load<S: AsRef<str>>(name: S) -> std::io::Result<ServerConfig> {
        let config = config::Config::builder()
            .add_source(config::File::with_name(name.as_ref()))
            .build()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("error loading config {e}"),
                )
            })?;
        config.try_deserialize().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("error deserializing config {e}"),
            )
        })
    }
}

#[cfg(test)]
mod test_config {
    use super::*;
    use crate::config::tls::match_certs_domain;
    use quinn::Connection;
    use rustls::Certificate;
    use std::time::Duration;
    use webpki::DnsName;

    const NAME_A: &str = "ddpwuxrmp.uk";
    const NAME_B: &str = "rehdhssj.cn";
    const CONFIG_A: &str = "data/config-ddpwuxrmp.toml";
    const CONFIG_B: &str = "data/config-rehdhssj.toml";

    fn domain_list() -> Vec<DnsName> {
        vec![
            DnsName::from(webpki::DnsNameRef::try_from_ascii_str(NAME_A).unwrap()),
            DnsName::from(webpki::DnsNameRef::try_from_ascii_str(NAME_B).unwrap()),
        ]
    }

    fn make_server(config_file: &str) -> (ServerConfig, quinn::Endpoint) {
        let server_conf = ServerConfig::load(config_file).expect("failed to load server config");
        let (server_config, client_config) =
            quic::default_config(&server_conf, Some(domain_list()))
                .expect("failed to build server config");
        let mut server =
            quinn::Endpoint::server(server_config, server_conf.addr).expect("init server failed");
        server.set_default_client_config(client_config);
        (server_conf, server)
    }

    #[tokio::test]
    async fn test_config() {
        let (conf_a, server_a) = make_server(CONFIG_A);
        let (conf_b, server_b) = make_server(CONFIG_B);
        let accept = tokio::spawn(async move {
            let conn = server_b
                .accept()
                .await
                .expect("closed without connection")
                .await
                .expect("failed connecting");
            get_addr_name(&conn)
        });
        // wait 100 ms
        tokio::time::sleep(Duration::from_millis(100)).await;
        let connect = tokio::spawn(async move {
            let conn = server_a
                .connect(conf_b.addr, "rehdhssj.cn")
                .expect("failed to connect")
                .await
                .expect("failed connecting");
            get_addr_name(&conn)
        });
        let (addr_a, name_a) = accept.await.expect("accept paniced");
        let (addr_b, name_b) = connect.await.expect("connect paniced");
        assert_eq!(addr_a, conf_a.addr);
        assert_eq!(name_a, NAME_A);
        assert_eq!(addr_b, conf_b.addr);
        assert_eq!(name_b, NAME_B);
    }

    /// helper function
    fn get_addr_name(conn: &Connection) -> (SocketAddr, String) {
        let addr = conn.remote_address();
        let identity = conn.peer_identity().expect("failed to get certificate");
        println!("{:?}", identity);
        let cert = identity
            .downcast_ref::<Vec<Certificate>>()
            .expect("failed to cast to certificate");
        let domains = domain_list();
        let mut matched = match_certs_domain(&cert, &domains).expect("no matching domain");
        assert_eq!(matched.len(), 1);
        (
            addr,
            String::from_utf8(matched.remove(0).as_ref().to_owned()).unwrap(),
        )
    }
}
