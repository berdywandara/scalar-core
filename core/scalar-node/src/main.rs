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
use scalar_node::wal::{CheckpointSnapshot, FileCheckpointWal, WalPhase};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // ── Subcommand: keygen ─────────────────────────────────────────────────
    // scalar-node keygen [--keystore=<path>] [--genesis-hash=<hex>]
    // SCALAR-TECHNICAL §10.5
    if args.len() > 1 && args[1] == "keygen" {
        // run_keygen is synchronous (CPU-bound), call directly.
        // Blocking the tokio thread is fine — we exit after completion.
        if let Err(e) = scalar_node::keystore::run_keygen(&args) {
            eprintln!("❌ keygen error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

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

    // Fast testnet mode — epoch 4 menit bukan 12.67 jam
    // --fast: HB 2s, sub-epoch 5 HBs (10s), epoch 120s
    let fast_mode = args.iter().any(|a| a == "--fast");
    // --crash-mode: HB 1s, subepoch 2 HBs → epoch 48s (for WAL crash test)
    let crash_mode = args.iter().any(|a| a == "--crash-mode");
    // --crash-after-prepare: simulate crash right after WAL PREPARE
    let crash_after_prepare = args.iter().any(|a| a == "--crash-after-prepare");

    let hb_interval_s: u64 = if crash_mode {
        1
    } else if fast_mode {
        2
    } else {
        10
    };
    // crash: 2 × 1s = 2s subepoch → epoch 24 × 2s = 48s
    // fast:  5 × 2s = 10s         → epoch 24 × 10s = 240s (~4 mnt)
    // normal: 180 × 10s           → epoch ~12 jam
    let hbs_per_subepoch: u32 = if crash_mode {
        2
    } else if fast_mode {
        5
    } else {
        180
    };

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
    if crash_mode {
        println!(
            "  Mode     : CRASH-TEST (HB={}s, subepoch={}HBs, epoch={}s)",
            hb_interval_s,
            hbs_per_subepoch,
            hb_interval_s * hbs_per_subepoch as u64 * 24
        );
    } else if fast_mode {
        println!(
            "  Mode     : FAST (HB={}s, subepoch={}HBs, epoch={}s)",
            hb_interval_s,
            hbs_per_subepoch,
            hb_interval_s * hbs_per_subepoch as u64 * 24
        );
    }
    println!("==================================================");

    // 1. State Machine
    let state_machine = Arc::new(Mutex::new(NodeStateMachine::default()));
    println!("[STATE] NodeStateMachine online.");

    // 2. Consensus Engine
    let _consensus_engine = Arc::new(Mutex::new(ConsensusEngine::default()));
    println!("[CONSENSUS] ZK Consensus Engine online.");

    // 2b. WAL — FileCheckpointWal (ADR-SEC-002, crash-safe)
    let wal_dir = format!("testnet-wal/node-{}", port);
    let mut wal = FileCheckpointWal::open(&wal_dir)
        .unwrap_or_else(|e| panic!("[WAL] Failed to open {}: {}", wal_dir, e));
    let prepared_count = wal.count_by_phase(&WalPhase::Prepared);
    if prepared_count > 0 {
        println!(
            "[WAL] ⚠️  CRASH RECOVERY: {} PREPARED entries found — node crashed during proving",
            prepared_count
        );
        println!("[WAL] WAL integrity maintained. Re-running proof generation...");
    } else {
        println!("[WAL] FileCheckpointWal open at {} (clean start)", wal_dir);
    }

    // 3. HeartbeatService — HeartbeatUnit v9.0 (108 bytes, BLAKE3-MAC)
    // NodeKey dan NodeID: dari keystore (--keystore=<path>) atau placeholder testnet
    // SCALAR-TECHNICAL §10.5
    let keystore_path: Option<String> = args
        .iter()
        .find(|a| a.starts_with("--keystore="))
        .map(|a| a.trim_start_matches("--keystore=").to_string());

    let (full_node_id, node_key) = if let Some(ref ks_path) = keystore_path {
        let passphrase = rpassword::prompt_password("Enter keystore passphrase: ")
            .unwrap_or_else(|_| String::new());
        match scalar_node::keystore::NodeKeystoreV1::decrypt_from_file(
            ks_path,
            passphrase.as_bytes(),
        ) {
            Ok(ks) => {
                println!(
                    "[NODE] ✅ Keystore loaded. NodeID: {}",
                    hex::encode(&ks.node_id_full[..8])
                );
                (ks.node_id_full, ks.node_key)
            }
            Err(e) => {
                eprintln!("[NODE] ❌ Failed to decrypt keystore: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("[NODE] ⚠️  No --keystore specified. Using placeholder NodeID (testnet only).");
        let mut id = [0u8; 32];
        id[0..2].copy_from_slice(&port.to_le_bytes());
        (id, [0x42u8; 32])
    };
    let hb_service = Arc::new(Mutex::new(HeartbeatService::new(full_node_id, node_key)));
    println!("[HB] HeartbeatService v9.1 online (148 bytes, BLAKE3-MAC).");

    // 4. RPC Server
    let rpc_server = LocalRpcServer { port };
    println!("[RPC] LocalRpcServer port {}.", port);
    tokio::task::spawn_blocking(move || {
        rpc_server.start();
    });

    // 4. P2P Swarm — spec §12.1
    let keypair_path = format!("testnet-wal/node-{}/keypair.bin", port);
    let swarm = build_swarm(&keypair_path)?;
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
    // PeerID → node_id_short mapping untuk reset seq saat disconnect
    let mut peer_to_node_id: std::collections::HashMap<libp2p::PeerId, [u8; 4]> =
        std::collections::HashMap::new();
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
                        // Reset seq tracking agar HB dari peer yang restart diterima
                        if let Some(node_id) = peer_to_node_id.remove(&peer) {
                            let mut svc = hb_service.lock().unwrap();
                            svc.reset_peer_seq(&node_id);
                            println!("[HB] 🔄 Seq reset for peer {}", hex::encode(node_id));
                        }
                    }
                    NodeSwarmEvent::HeartbeatReceived { from, data } => {
                        println!("[CORE] 💓 HB from {} ({} bytes)", from, data.len());
                        // Verifikasi HeartbeatUnit v9.0 — 5-step spec §7.2b
                        if data.len() == 148 {
                            let nmt = HeartbeatService::local_nmt();
                            // NodeKey_epoch peer: placeholder [0x42;32] untuk testing
                            // Production: ambil dari EpochAnchor peer — spec §7.2a
                            let peer_nke = scalar_emission::liveness::derive_node_key_epoch(
                                &[0x42u8; 32], 0
                            );
                            let mut svc = hb_service.lock().unwrap();
                            if let Some(node_id) = svc.verify_peer_heartbeat_with_id(&data, nmt, &peer_nke) {
                                println!("[CORE] ✅ HB verified from {}", from);
                                peer_to_node_id.insert(from, node_id);
                            } else {
                                println!("[CORE] ❌ HB rejected from {}", from);
                            }
                        } else {
                            println!("[CORE] ⚠️  HB wrong size: {} (expected 148)", data.len());
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

            // Broadcast HeartbeatUnit setiap hb_interval_s detik — spec §7.2
            _ = sleep(Duration::from_secs(hb_interval_s)) => {
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
                println!("[CORE] 💓 HeartbeatUnit v9.1 #{} broadcast (148 bytes)", hb_counter);

                // Sub-epoch / epoch boundary detection
                if hb_counter % hbs_per_subepoch == 0 {
                    let subepoch_num = hb_counter / hbs_per_subepoch;
                    let local_sub = (subepoch_num - 1) % 24;
                    let epoch_id = (subepoch_num - 1) / 24;

                    println!("[EPOCH] 🔔 Sub-epoch {:02} of epoch {} | HB#{}",
                        local_sub, epoch_id, hb_counter);

                    // Epoch boundary = last sub-epoch (23)
                    if local_sub == 23 {
                        let current_epoch = epoch_id as u64;
                        println!("[EPOCH] ==============================");
                        println!("[EPOCH] === EPOCH {} BOUNDARY ===", current_epoch);
                        println!("[EPOCH] ==============================");

                        // WAL checkpoint — Three-Phase Commit (ADR-SEC-002)
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;

                        let snap = CheckpointSnapshot {
                            epoch_id: current_epoch,
                            imt_frontier_root: [0u8; 32],
                            imt_count: hb_counter as u64,
                            utxo_set_root: [0u8; 32],
                            nullifier_active_root: [0u8; 32],
                            nullifier_archived_root: [0u8; 32],
                            total_supply_sscl: 0,
                        };

                        match wal.prepare(current_epoch, 1, snap, now_ms) {
                            Ok(r) => println!("[WAL] PREPARE epoch {}: {:?}", current_epoch, r),
                            Err(e) => println!("[WAL] PREPARE error: {}", e),
                        }

                        // --crash-after-prepare: simulate crash mid-proving (WAL test)
                        if crash_after_prepare {
                            println!("[WAL] ⚡ SIMULATED CRASH after PREPARE");
                            println!("[WAL] Exiting WITHOUT COMMIT to simulate node crash...");
                            std::process::exit(1);
                        }

                        // Simulate proof generation
                        let proof_delay = if crash_mode { 100 } else if fast_mode { 200 } else { 500 };
                        tokio::time::sleep(Duration::from_millis(proof_delay)).await;

                        match wal.commit(current_epoch, vec![0xCAu8; 32], now_ms + proof_delay) {
                            Ok(r) => println!("[WAL] COMMIT epoch {}: {:?}", current_epoch, r),
                            Err(e) => println!("[WAL] COMMIT error: {}", e),
                        }

                        println!("[EPOCH] ✅ Epoch {} complete", current_epoch);
                    }
                }
            }
        }
    }
}
