//! Scalar P2P Swarm — Spec §12.1, §12.2, §7.2
//!
//! Transport: TCP + Noise + Yamux (Tier 1 — CONSENSUS_TRANSPORT)
//! Behaviour: gossipsub + kademlia + identify
//!
//! Spec §12.2: peer discovery via Kademlia DHT.
//! Spec §7.2: NodeHeartbeat broadcast via gossipsub topic "scalar/heartbeat/1".

use libp2p::{
    gossipsub, identify, identity, kad,
    noise, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol,
};
use std::time::Duration;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use tokio::sync::mpsc;
use futures::StreamExt;

// ── Topic constants — spec §12 ────────────────────────────────────────────────

/// Gossipsub topic untuk NodeHeartbeat. Spec §7.2.
pub const TOPIC_HEARTBEAT: &str = "scalar/heartbeat/1";
/// Gossipsub topic untuk GossipMessage. Spec §12.
pub const TOPIC_GOSSIP: &str = "scalar/gossip/1";
/// Gossipsub topic untuk StateBeacon. Spec §12.1a.
pub const TOPIC_BEACON: &str = "scalar/beacon/1";

// ── ScalarNodeBehaviour ───────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
pub struct ScalarNodeBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
}

// ── SwarmEvent ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum NodeSwarmEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    HeartbeatReceived { from: PeerId, data: Vec<u8> },
    GossipReceived { from: PeerId, data: Vec<u8> },
    BeaconReceived { from: PeerId, data: Vec<u8> },
}

// ── build_swarm ───────────────────────────────────────────────────────────────

pub fn build_swarm() -> anyhow::Result<libp2p::Swarm<ScalarNodeBehaviour>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("[P2P] Local PeerID: {}", local_peer_id);

    // Message ID function untuk gossipsub — hash(source + sequence)
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    // Gossipsub config
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .max_transmit_size(256 * 1024)
        // Mesh parameters untuk 2-node testing
        .mesh_n(2)
        .mesh_n_low(1)
        .mesh_n_high(4)
        .mesh_outbound_min(1)
        .build()
        .map_err(|e| anyhow::anyhow!("Gossipsub config: {}", e))?;

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    ).map_err(|e| anyhow::anyhow!("Gossipsub: {}", e))?;

    // Subscribe topics
    for topic_str in [TOPIC_HEARTBEAT, TOPIC_GOSSIP, TOPIC_BEACON] {
        let topic = gossipsub::IdentTopic::new(topic_str);
        gossipsub.subscribe(&topic)?;
        println!("[P2P] Subscribed: {}", topic_str);
    }

    // Kademlia
    let mut kademlia_config = kad::Config::new(
        StreamProtocol::new("/scalar/kad/1.0.0")
    );
    kademlia_config.set_query_timeout(Duration::from_secs(60));
    let kademlia = kad::Behaviour::with_config(
        local_peer_id,
        kad::store::MemoryStore::new(local_peer_id),
        kademlia_config,
    );

    // Identify
    let identify = identify::Behaviour::new(
        identify::Config::new("/scalar/1.0.0".to_string(), local_key.public())
    );

    let behaviour = ScalarNodeBehaviour { gossipsub, kademlia, identify };

    // Build swarm dengan SwarmBuilder v0.54 API
    let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(Duration::from_secs(60))
        })
        .build();

    Ok(swarm)
}

// ── run_swarm ─────────────────────────────────────────────────────────────────

pub async fn run_swarm(
    mut swarm: libp2p::Swarm<ScalarNodeBehaviour>,
    listen_addr: Multiaddr,
    dial_peers: Vec<Multiaddr>,
    event_tx: mpsc::Sender<NodeSwarmEvent>,
    mut msg_rx: mpsc::Receiver<(String, Vec<u8>)>,
) -> anyhow::Result<()> {
    swarm.listen_on(listen_addr.clone())?;
    println!("[P2P] Listen: {}", listen_addr);

    for peer_addr in dial_peers {
        println!("[P2P] Dialing: {}", peer_addr);
        let _ = swarm.dial(peer_addr);
    }

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[P2P] ✅ Listening: {}", address);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[P2P] ✅ Connected: {}", peer_id);
                        let _ = event_tx.send(NodeSwarmEvent::PeerConnected(peer_id)).await;
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        println!("[P2P] ❌ Disconnected: {} ({:?})", peer_id, cause);
                        let _ = event_tx.send(NodeSwarmEvent::PeerDisconnected(peer_id)).await;
                    }
                    SwarmEvent::Behaviour(ScalarNodeBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { propagation_source, message, .. }
                    )) => {
                        let topic = message.topic.as_str().to_string();
                        let data = message.data.clone();
                        let from = propagation_source;
                        if topic == TOPIC_HEARTBEAT {
                            println!("[P2P] 💓 HB from: {}", from);
                            let _ = event_tx.send(NodeSwarmEvent::HeartbeatReceived { from, data }).await;
                        } else if topic == TOPIC_GOSSIP {
                            println!("[P2P] 📨 Gossip from: {}", from);
                            let _ = event_tx.send(NodeSwarmEvent::GossipReceived { from, data }).await;
                        } else if topic == TOPIC_BEACON {
                            println!("[P2P] 🔦 Beacon from: {}", from);
                            let _ = event_tx.send(NodeSwarmEvent::BeaconReceived { from, data }).await;
                        }
                    }
                    SwarmEvent::Behaviour(ScalarNodeBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. }
                    )) => {
                        println!("[P2P] 🆔 Identified: {} ({})", peer_id, info.protocol_version);
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    _ => {}
                }
            }

            Some((topic_str, data)) = msg_rx.recv() => {
                let topic = gossipsub::IdentTopic::new(&topic_str);
                match swarm.behaviour_mut().gossipsub.publish(topic, data) {
                    Ok(_) => println!("[P2P] 📤 Published: {}", topic_str),
                    Err(e) => println!("[P2P] ⚠️  Publish error: {:?}", e),
                }
            }
        }
    }
}
