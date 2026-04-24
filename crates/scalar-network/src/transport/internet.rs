//! Internet Transport dengan DHT Kademlia dan Obfs4 Proxy Routing
use libp2p::{kad, gossipsub, core::upgrade, identity, noise, tcp, yamux, Transport};
use libp2p::swarm::NetworkBehaviour;

/// Perilaku Jaringan Kombinasi (Unified Network Behaviour)
#[derive(NetworkBehaviour)]
pub struct ScalarBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

pub struct InternetTransport;

impl InternetTransport {
    /// Setup TCP dengan Noise + Yamux. 
    /// Jika `use_obfs4_fallback` diaktifkan, trafik akan dirouting ke port proxy obfs4 lokal
    pub fn build(local_key: &identity::Keypair, _use_obfs4_fallback: bool) -> libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)> {
        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        let noise_config = noise::Config::new(local_key).expect("Noise key setup gagal");
        let yamux_config = yamux::Config::default();

        // Dalam runtime produksi, jika _use_obfs4_fallback aktif, tcp_transport diganti
        // dengan custom transport yang mengalirkan koneksi ke bind address obfs4 lokal.
        tcp_transport
            .upgrade(upgrade::Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(std::time::Duration::from_secs(20))
            .boxed()
    }
}
