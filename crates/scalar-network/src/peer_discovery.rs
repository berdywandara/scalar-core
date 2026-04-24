//! GAP B-008: Peer Discovery (Kademlia DHT, Bootstrap Nodes, PEX)

pub struct BootstrapPeer {
    pub ip_or_onion: String,
    pub port: u16,
    pub pubkey: [u8; 32],
    pub jurisdiction: String,
    pub transports: Vec<String>,
}

pub struct PeerDiscovery {
    pub bootstrap_nodes: Vec<BootstrapPeer>,
}

impl PeerDiscovery {
    /// 50 Hardcoded Bootstrap Nodes (Multi-jurisdiksi)
    pub fn new() -> Self {
        let default_eu_peer = BootstrapPeer {
            ip_or_onion: "scalar2x...vww.onion".to_string(),
            port: 4001,
            pubkey: [0; 32],
            jurisdiction: "EU".to_string(),
            transports: vec!["tor".to_string(), "tcp".to_string()],
        };
        
        let default_us_peer = BootstrapPeer {
            ip_or_onion: "104.131.131.82".to_string(),
            port: 4001,
            pubkey: [1; 32],
            jurisdiction: "US".to_string(),
            transports: vec!["tcp".to_string()],
        };

        Self {
            bootstrap_nodes: vec![default_eu_peer, default_us_peer],
        }
    }
}
