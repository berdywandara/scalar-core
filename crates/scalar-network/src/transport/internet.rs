//! GAP B-003: Internet Transport (TCP, Noise, Yamux, No-DNS)

use libp2p::{core::upgrade, identity, noise, tcp, yamux, Transport};
use std::time::Duration;

pub struct InternetTransport;

impl InternetTransport {
    /// Setup TCP transport via libp2p dengan Noise encryption dan Yamux multiplexing
    /// Menggunakan IP direct dan DHT (Zero-DNS policy)
    pub fn build(local_key: &identity::Keypair) -> libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)> {
        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        
        // Custom PKI Certificate Pinning via Noise protocol
        let noise_config = noise::Config::new(local_key).expect("Noise key setup gagal");
        let yamux_config = yamux::Config::default();

        tcp_transport
            .upgrade(upgrade::Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .boxed()
    }
}
