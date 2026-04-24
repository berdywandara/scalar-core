//! Internet Transport dengan DHT Kademlia dan Obfs4/Snowflake Pluggable Transports
use libp2p::{kad, gossipsub, core::upgrade, identity, noise, tcp, yamux, Transport};
use libp2p::swarm::NetworkBehaviour;
use std::process::{Command, Child, Stdio};
use std::net::SocketAddr;
use tokio_socks::tcp::Socks5Stream;

/// Perilaku Jaringan Kombinasi (Unified Network Behaviour)
#[derive(NetworkBehaviour)]
pub struct ScalarBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

/// PTv2 Manager (Pluggable Transports)
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

        let transport = if use_obfs4_fallback {
            let pt_manager = PluggableTransportManager::start_obfs4();
            let proxy_addr = pt_manager.local_proxy_addr;
            
            tcp_transport
                .and_then(move |stream, endpoint| async move {
                    println!("[PTv2 ROUTING] Melakukan SOCKS5 handshake asinkron ke proxy {}", proxy_addr);
                    
                    let target_addr = ("0.0.0.0", 0);
                    
                    // FIXED: Buka wrapper libp2p untuk mengekstrak raw tokio::net::TcpStream
                    let raw_socket = stream.0;
                    
                    // FIXED: connect_with_socket hanya menerima 2 argumen: socket & target
                    match Socks5Stream::connect_with_socket(raw_socket, target_addr).await {
                        Ok(socks_stream) => {
                            println!("[PTv2 ROUTING] Handshake sukses menuju {:?}", endpoint);
                            // FIXED: Bungkus kembali raw soket ke dalam struktur tcp::tokio::TcpStream milik libp2p
                            Ok(tcp::tokio::TcpStream(socks_stream.into_inner()))
                        },
                        Err(e) => {
                            Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string()))
                        }
                    }
                })
                .boxed()
        } else {
            tcp_transport.boxed()
        };

        transport
            .upgrade(upgrade::Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(std::time::Duration::from_secs(20))
            .boxed()
    }
}
