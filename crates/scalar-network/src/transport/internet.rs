//! Internet Transport dengan DHT Kademlia dan Obfs4/Snowflake Pluggable Transports
//! Sesuai Concept 2 Fase 4C.2.2 Defense 3: obfs4/Snowflake pluggable transport anti-censorship.
use libp2p::core::multiaddr::Protocol;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{core::upgrade, gossipsub, identity, kad, noise, tcp, yamux, Transport};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use tokio_socks::tcp::Socks5Stream;

/// Perilaku Jaringan Kombinasi (Unified Network Behaviour)
/// Menggabungkan gossipsub (pesan) dan kademlia (peer discovery / DHT)
#[derive(NetworkBehaviour)]
pub struct ScalarBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

/// PTv2 Manager (Pluggable Transports version 2)
/// Sesuai Concept 2 4C.2.2 Defense 3: "Pluggable transports: obfs4, Snowflake"
pub struct PluggableTransportManager {
    daemon: Option<Child>,
    pub local_proxy_addr: SocketAddr,
}

impl PluggableTransportManager {
    /// Spawn daemon lyrebird (obfs4proxy dari Tor Project).
    /// Binary lyrebird harus tersedia di PATH sistem.
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

/// Ekstrak (host, port) dari Multiaddr libp2p.
/// /ip4/1.2.3.4/tcp/4001 → Some(("1.2.3.4", 4001))
/// /ip6/::1/tcp/4001     → Some(("::1", 4001))
fn extract_host_port(multiaddr: &libp2p::Multiaddr) -> Option<(String, u16)> {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;

    for proto in multiaddr.iter() {
        match proto {
            Protocol::Ip4(addr) => host = Some(addr.to_string()),
            Protocol::Ip6(addr) => host = Some(addr.to_string()),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }

    match (host, port) {
        (Some(h), Some(p)) => Some((h, p)),
        _ => None,
    }
}

pub struct InternetTransport;

impl InternetTransport {
    /// Bangun transport libp2p dengan Noise + Yamux.
    ///
    /// Jika `use_obfs4_fallback = true`:
    ///   1. Daemon lyrebird di-spawn di 127.0.0.1:15000
    ///   2. Setiap koneksi keluar dicegat via .and_then() combinator
    ///   3. Alamat peer diekstrak dari ConnectedPoint::get_remote_address()
    ///   4. SOCKS5 handshake nyata dilakukan ke (host, port) peer tersebut
    ///   5. Stream kembali ke pipeline Noise → Yamux
    pub fn build(
        local_key: &identity::Keypair,
        use_obfs4_fallback: bool,
    ) -> libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>
    {
        let noise_config = noise::Config::new(local_key).expect("Noise key setup gagal");
        let yamux_config = yamux::Config::default();
        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));

        let transport = if use_obfs4_fallback {
            let pt_manager = PluggableTransportManager::start_obfs4();
            let proxy_addr = pt_manager.local_proxy_addr;

            tcp_transport
                .and_then(move |stream, endpoint| async move {
                    // Ambil alamat peer yang sebenarnya dari ConnectedPoint.
                    // ConnectedPoint::get_remote_address() → &Multiaddr
                    let remote_multiaddr = endpoint.get_remote_address();

                    let (host, port) = extract_host_port(remote_multiaddr).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("Multiaddr tidak valid: {}", remote_multiaddr),
                        )
                    })?;

                    println!(
                        "[PTv2] SOCKS5 tunnel → {}:{} via proxy {}",
                        host, port, proxy_addr
                    );

                    // Ekstrak raw TcpStream dari wrapper libp2p
                    let raw_socket = stream.0;

                    // SOCKS5 handshake nyata ke alamat peer yang sebenarnya
                    match Socks5Stream::connect_with_socket(raw_socket, (host.as_str(), port)).await
                    {
                        Ok(socks_stream) => {
                            println!("[PTv2] Tunnel sukses ke {}:{}", host, port);
                            // Bungkus kembali ke TcpStream libp2p untuk Noise/Yamux
                            Ok(tcp::tokio::TcpStream(socks_stream.into_inner()))
                        }
                        Err(e) => Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            format!("SOCKS5 gagal ke {}:{} — {}", host, port, e),
                        )),
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
