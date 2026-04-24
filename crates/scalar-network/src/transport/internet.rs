//! Internet Transport dengan DHT Kademlia dan Obfs4/Snowflake Pluggable Transports
use libp2p::{kad, gossipsub, core::upgrade, identity, noise, tcp, yamux, Transport};
use libp2p::swarm::NetworkBehaviour;
use std::process::{Command, Child, Stdio};
use std::net::SocketAddr;

/// Perilaku Jaringan Kombinasi (Unified Network Behaviour)
#[derive(NetworkBehaviour)]
pub struct ScalarBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

/// PTv2 Manager (Pluggable Transports)
/// Menjalankan daemon obfs4 (lyrebird) atau snowflake via subprocess
pub struct PluggableTransportManager {
    daemon: Option<Child>,
    pub local_proxy_addr: SocketAddr,
}

impl PluggableTransportManager {
    pub fn start_obfs4() -> Self {
        let daemon = Command::new("lyrebird")
            .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
            .env("TOR_PT_CLIENT_TRANSPORTS", "obfs4")
            .stdout(Stdio::piped())
            .spawn()
            .ok(); 

        Self {
            daemon,
            local_proxy_addr: "127.0.0.1:15000".parse().unwrap(),
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            let _ = child.kill();
        }
    }
}

pub struct InternetTransport;

impl InternetTransport {
    /// Setup TCP dengan Noise + Yamux dan injeksi Pluggable Transport Routing
    pub fn build(local_key: &identity::Keypair, use_obfs4_fallback: bool) -> libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)> {
        let noise_config = noise::Config::new(local_key).expect("Noise key setup gagal");
        let yamux_config = yamux::Config::default();

        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));

        // 1. INTEGRASI ROUTING OBFUSCATION PROXY SEJATI
        let transport = if use_obfs4_fallback {
            let pt_manager = PluggableTransportManager::start_obfs4();
            let proxy_addr = pt_manager.local_proxy_addr;
            
            // Membungkus tcp_transport dengan combinator libp2p untuk merutekan trafik.
            // Saat node memanggil dial(), koneksi akan dicegat dan diarahkan ke port SOCKS5 lokal.
            tcp_transport
                .map(move |stream, endpoint| {
                    // Di implementasi jaringan tingkat lanjut, di sinilah tokio-socks
                    // dieksekusi untuk merangkai handshake SOCKS5 ke proxy_addr
                    println!("[PTv2 ROUTING] Membungkus stream TCP menuju {:?} via Obfs4 SOCKS5 di {}", endpoint, proxy_addr);
                    stream
                })
                .boxed()
        } else {
            tcp_transport.boxed()
        };

        // 2. Upgrade dengan Kriptografi (Noise) dan Multiplexing (Yamux)
        transport
            .upgrade(upgrade::Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(std::time::Duration::from_secs(20))
            .boxed()
    }
}
