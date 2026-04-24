//! GAP-C2-006: Tor Network Integration
//! Menyediakan dukungan routing via proxy SOCKS5 Tor / Arti Client.

pub struct TorConfig {
    pub socks5_proxy_addr: String,
    pub onion_v3_address: Option<String>,
}

impl TorConfig {
    /// Default proxy untuk daemon Tor lokal
    pub fn default_local() -> Self {
        Self {
            socks5_proxy_addr: "127.0.0.1:9050".to_string(),
            onion_v3_address: None,
        }
    }

    /// Format alamat libp2p multiaddr untuk koneksi Onion V3
    pub fn format_onion_multiaddr(onion_v3: &str, port: u16) -> String {
        format!("/onion3/{}:{}", onion_v3, port)
    }
}
