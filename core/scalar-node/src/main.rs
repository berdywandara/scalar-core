//! Scalar Core Node — Boot Sequence
//!
//! Komponen:
//!   1. State Machine
//!   2. Consensus Engine  
//!   3. RPC Server (port 7777)
//!   4. P2P Swarm (libp2p gossipsub + kademlia) — spec §12.1
//!
//! Usage:
//!   ./scalar-node --port=7777
//!   ./scalar-node --port=7778 --dial=/ip4/127.0.0.1/tcp/PORT_SWARM_A

use scalar_consensus::ConsensusEngine;
use scalar_node::api::LocalRpcServer;
use scalar_node::heartbeat_service::HeartbeatService;
use scalar_node::state_machine::NodeStateMachine;
use scalar_node::swarm::{build_swarm, run_swarm, TOPIC_HEARTBEAT};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // RPC port — default 7777
    let port: u16 = args
        .iter()
        .find(|a| a.starts_with("--port="))
        .and_then(|a| a.trim_start_matches("--port=").parse().ok())
        .unwrap_or(7777);

    // P2P swarm port — default random (0 = OS assigns)
    let p2p_port: u16 = args
        .iter()
        .find(|a| a.starts_with("--p2p-port="))
        .and_then(|a| a.trim_start_matches("--p2p-port=").parse().ok())
        .unwrap_or(0);

    // Peer untuk di-dial saat startup (bootstrap)
    let dial_peers: Vec<libp2p::Multiaddr> = args
        .iter()
        .filter(|a| a.starts_with("--dial="))
        .filter_map(|a| a.trim_start_matches("--dial=").parse().ok())
        .collect();

    println!("==================================================");
    println!("  SCALAR NETWORK CORE NODE - BOOT SEQUENCE");
    println!("  RPC Port : {}", port);
    println!(
        "  P2P Port : {}",
        if p2p_port == 0 {
            "random".to_string()
        } else {
            p2p_port.to_string()
        }
    );
    println!("  Dial     : {} peers", dial_peers.len());
    println!("==================================================");

    // 1. State Machine
    let state_machine = Arc::new(Mutex::new(NodeStateMachine::default()));
    println!("[STATE] NodeStateMachine online.");

    // 2. Consensus Engine
    let _consensus_engine = Arc::new(Mutex::new(ConsensusEngine::default()));
    println!("[CONSENSUS] ZK Consensus Engine online.");

    // 3. HeartbeatService — HeartbeatUnit v9.0 (108 bytes, BLAKE3-MAC)
    // NodeKey dan NodeID: random untuk testing, production pakai Argon2id
    let full_node_id = {
        let mut id = [0u8; 32];
        id[0..2].copy_from_slice(&port.to_le_bytes());
        id
    };
    let node_key = [0x42u8; 32]; // placeholder — production: dari seed derivation §13.1
    let hb_service = Arc::new(Mutex::new(HeartbeatService::new(full_node_id, node_key)));
    println!("[HB] HeartbeatService v9.0 online (108 bytes, BLAKE3-MAC).");

    // 4. RPC Server
    let rpc_server = LocalRpcServer { port };
    println!("[RPC] LocalRpcServer port {}.", port);
    tokio::task::spawn_blocking(move || {
        rpc_server.start();
    });

    // 4. P2P Swarm — spec §12.1
    let swarm = build_swarm()?;
    let listen_addr: libp2p::Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse()?;

    // Channel: swarm → node logic (inbound events)
    let (event_tx, mut event_rx) = mpsc::channel(100);
    // Channel: node logic → swarm (outbound messages)
    let (msg_tx, msg_rx) = mpsc::channel::<(String, Vec<u8>)>(100);

    // Spawn swarm task
    tokio::spawn(async move {
        if let Err(e) = run_swarm(swarm, listen_addr, dial_peers, event_tx, msg_rx).await {
            eprintln!("[P2P] Swarm error: {}", e);
        }
    });

    println!("[P2P] Swarm started.");
    println!("[CORE] Event loop running.");
    println!("==================================================");

    // 5. Main event loop
    let mut hb_counter: u32 = 0;
    loop {
        tokio::select! {
            // Handle P2P events
            Some(event) = event_rx.recv() => {
                use scalar_node::swarm::NodeSwarmEvent;
                match event {
                    NodeSwarmEvent::PeerConnected(peer) => {
                        println!("[CORE] ✅ Peer connected: {}", peer);
                    }
                    NodeSwarmEvent::PeerDisconnected(peer) => {
                        println!("[CORE] ❌ Peer disconnected: {}", peer);
                    }
                    NodeSwarmEvent::HeartbeatReceived { from, data } => {
                        println!("[CORE] 💓 HB from {} ({} bytes)", from, data.len());
                        // Verifikasi HeartbeatUnit v9.0 — 5-step spec §7.2b
                        if data.len() == 108 {
                            let nmt = HeartbeatService::local_nmt();
                            // NodeKey_epoch peer: placeholder [0x42;32] untuk testing
                            // Production: ambil dari EpochAnchor peer — spec §7.2a
                            let peer_nke = scalar_emission::liveness::derive_node_key_epoch(
                                &[0x42u8; 32], 0
                            );
                            let mut svc = hb_service.lock().unwrap();
                            if svc.verify_peer_heartbeat(&data, nmt, &peer_nke) {
                                println!("[CORE] ✅ HB verified from {}", from);
                            } else {
                                println!("[CORE] ❌ HB rejected from {}", from);
                            }
                        } else {
                            println!("[CORE] ⚠️  HB wrong size: {} (expected 108)", data.len());
                        }
                    }
                    NodeSwarmEvent::GossipReceived { from, data } => {
                        println!("[CORE] 📨 Gossip from {} ({} bytes)", from, data.len());
                    }
                    NodeSwarmEvent::BeaconReceived { from, data } => {
                        println!("[CORE] 🔦 Beacon from {} ({} bytes)", from, data.len());
                    }
                }
            }

            // Broadcast HeartbeatUnit v9.0 setiap 10 detik — spec §7.2
            _ = sleep(Duration::from_secs(10)) => {
                hb_counter += 1;
                {
                    let mut sm = state_machine.lock().unwrap();
                    sm.update_network_sensor(true, true);
                }

                // Produce HeartbeatUnit v9.0 (108 bytes, BLAKE3-MAC) — spec §7.2
                let hb_bytes = {
                    let mut svc = hb_service.lock().unwrap();
                    let hb = svc.produce_heartbeat();
                    let bytes = hb.to_bytes().to_vec();
                    drop(svc);
                    bytes
                };

                let _ = msg_tx.send((TOPIC_HEARTBEAT.to_string(), hb_bytes)).await;
                println!("[CORE] 💓 HeartbeatUnit v9.0 #{} broadcast (108 bytes)", hb_counter);
            }
        }
    }
}
