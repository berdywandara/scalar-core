//! Otak Eksekusi Scalar Core Node
//! Menggabungkan State Machine, RPC Server, dan P2P Network dalam satu runtime asinkron.

use scalar_node::state_machine::NodeStateMachine;
use scalar_node::api::LocalRpcServer;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==================================================");
    println!("  SCALAR NETWORK CORE NODE - BOOT SEQUENCE INITIATED");
    println!("==================================================");

    // 1. Inisiasi State Machine (Memori Inti Node)
    let state_machine = Arc::new(Mutex::new(NodeStateMachine::new()));
    println!("[STATE] NodeStateMachine berhasil diinisialisasi.");

    // 2. Inisiasi Command Center (Local RPC Server)
    let rpc_server = LocalRpcServer::new();
    println!("[RPC] LocalRpcServer siap mendengarkan instruksi dompet di port lokal.");

    // TODO: Tonggak 2 - Inisiasi Network Swarm (Libp2p) akan disuntikkan di sini

    // 3. Menjalankan RPC Server di thread latar belakang
    // Dalam skenario nyata, ini akan menggunakan tokio::net::TcpListener asinkron.
    // Untuk saat ini, kita menjalankan thread blocking di dalam task tokio.
    tokio::task::spawn_blocking(move || {
        rpc_server.start();
    });

    // 4. Siklus Hidup Abadi (The Event Loop)
    println!("[CORE] Memasuki siklus operasi utama...");
    loop {
        // Simulasi detak jantung node (Heartbeat) setiap 5 detik
        sleep(Duration::from_secs(5)).await;
        
        let mut sm = state_machine.lock().unwrap();
        // Simulasi update sensor jaringan (Internet OK, Sync OK)
        sm.update_network_sensor(true, true);
        
        // Membungkam compiler dari warning dead code dengan memanggil fungsi internal
        drop(sm); 
    }
}
