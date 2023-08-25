use serde::Deserialize;
use std::net::IpAddr;

#[derive(Deserialize)]
struct Node {
    identifier: String,
    ip: IpAddr,
    port: u16,
    dns: String,
}
