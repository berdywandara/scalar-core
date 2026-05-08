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
use scalar_node::state_machine::NodeStateMachine;
use scalar_node::swarm::{build_swarm, run_swarm, TOPIC_HEARTBEAT};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // RPC port — default 7777
    let port: u16 = args.iter()
        .find(|a| a.starts_with("--port="))
        .and_then(|a| a.trim_start_matches("--port=").parse().ok())
        .unwrap_or(7777);

    // P2P swarm port — default random (0 = OS assigns)
    let p2p_port: u16 = args.iter()
        .find(|a| a.starts_with("--p2p-port="))
        .and_then(|a| a.trim_start_matches("--p2p-port=").parse().ok())
        .unwrap_or(0);

    // Peer untuk di-dial saat startup (bootstrap)
    let dial_peers: Vec<libp2p::Multiaddr> = args.iter()
        .filter(|a| a.starts_with("--dial="))
        .filter_map(|a| a.trim_start_matches("--dial=").parse().ok())
        .collect();

    println!("==================================================");
    println!("  SCALAR NETWORK CORE NODE - BOOT SEQUENCE");
    println!("  RPC Port : {}", port);
    println!("  P2P Port : {}", if p2p_port == 0 { "random".to_string() } else { p2p_port.to_string() });
    println!("  Dial     : {} peers", dial_peers.len());
    println!("==================================================");

    // 1. State Machine
    let state_machine = Arc::new(Mutex::new(NodeStateMachine::default()));
    println!("[STATE] NodeStateMachine online.");

    // 2. Consensus Engine
    let _consensus_engine = Arc::new(Mutex::new(ConsensusEngine::default()));
    println!("[CONSENSUS] ZK Consensus Engine online.");

    // 3. RPC Server
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
    let mut hb_counter: u64 = 0;
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
                        println!("[CORE] 💓 Heartbeat from {} ({} bytes)", from, data.len());
                    }
                    NodeSwarmEvent::GossipReceived { from, data } => {
                        println!("[CORE] 📨 Gossip from {} ({} bytes)", from, data.len());
                    }
                    NodeSwarmEvent::BeaconReceived { from, data } => {
                        println!("[CORE] 🔦 Beacon from {} ({} bytes)", from, data.len());
                    }
                }
            }

            // Broadcast heartbeat setiap 10 detik — spec §7.2
            _ = sleep(Duration::from_secs(10)) => {
                hb_counter += 1;
                let mut sm = state_machine.lock().unwrap();
                sm.update_network_sensor(true, true);
                drop(sm);

                // Broadcast dummy heartbeat ke network
                let hb_data = format!("HB:{}", hb_counter).into_bytes();
                let _ = msg_tx.send((TOPIC_HEARTBEAT.to_string(), hb_data)).await;
                println!("[CORE] 💓 Heartbeat #{} broadcast", hb_counter);
            }
        }
    }
}
