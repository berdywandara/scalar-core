//! GAP C-006: Node Local RPC API (Port 7777)
//! Hanya dibuka untuk localhost untuk komunikasi dengan Desktop/Mobile Wallet UI

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct RpcRequest {
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse {
    result: Option<String>,
    error: Option<String>,
}

pub struct LocalRpcServer {
    port: u16,
}

impl LocalRpcServer {
    pub fn new() -> Self {
        Self { port: 7777 } // Standar port Scalar RPC
    }

    pub fn start(&self) {
        let address = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&address).expect("Gagal bind ke port 7777");
        println!("🚀 Local RPC Server running at {}", address);

        // Di produksi, ini berjalan non-blocking (async tokio).
        // Untuk kompilasi rangka, thread dilepas.
        thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(stream) = stream {
                    Self::handle_client(stream);
                }
            }
        });
    }

    fn handle_client(mut stream: TcpStream) {
        let mut buffer = [0; 1024];
        if stream.read(&mut buffer).is_ok() {
            // Simulasi routing method (get_balance, send_transaction, get_smt_root)
            let response = RpcResponse {
                result: Some("{\"status\": \"synced\", \"smt_root\": \"0x...\"}".to_string()),
                error: None,
            };
            let response_str = serde_json::to_string(&response).unwrap();
            let _ = stream.write_all(response_str.as_bytes());
        }
    }
}
