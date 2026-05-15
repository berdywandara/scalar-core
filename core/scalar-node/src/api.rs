//! Local RPC API for komuniqueasi wallet ↔ node (port 7777)
//! Protokol: HTTP/1.1 simple so that bisa attest with curl and atuse wallet UI.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcRequest {
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcResponse {
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub struct LocalRpcServer {
    pub port: u16,
}

impl LocalRpcServer {
    pub fn new() -> Self {
        Self { port: 7777 }
    }

    /// run server secara blocking — call from spawn_blocking or thread separate.
    pub fn start(&self) {
        let address = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&address)
            .unwrap_or_else(|e| panic!("Gagal bind ke {}: {}", address, e));

        println!("🚀 Scalar RPC Server berjalan di http://{}", address);
        println!("   Test: curl http://localhost:{}", self.port);

        // Loop blocking — ini dijalankan dari spawn_blocking sehingga aman
        for stream in listener.incoming().flatten() {
            // Setiap koneksi ditangani di thread terpisah agar server tidak blocking
            std::thread::spawn(|| Self::handle_http(stream));
        }
    }

    /// Handle satu HTTP request and return JSON response.
    fn handle_http(mut stream: TcpStream) {
        let reader = BufReader::new(&stream);

        // Baca baris pertama HTTP request: "GET /method HTTP/1.1"
        let first_line = reader
            .lines()
            .next()
            .and_then(|l| l.ok())
            .unwrap_or_default();

        // Parse method dari path: GET /get_smt_root → "get_smt_root"
        let method = first_line
            .split_whitespace()
            .nth(1) // tato path
            .unwrap_or("/")
            .trim_start_matches('/')
            .to_string();

        let response_body = Self::route(&method);
        let body_str = serde_json::to_string_pretty(&response_body).unwrap_or_default();

        // Tulis HTTP response yang valid agar curl dan browser bisa membacanya
        let http_response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {}",
            body_str.len(),
            body_str
        );

        let _ = stream.write_all(http_response.as_bytes());
    }

    /// Route method to handler that sesuai.
    fn route(method: &str) -> RpcResponse {
        match method {
            "get_status" | "" => RpcResponse {
                result: Some(serde_json::json!({
                    "node": "Scalar Network Core",
                    "version": "0.1.0",
                    "status": "ACTIVE",
                    "principle": "Truth by Mathematics, Not by Majority"
                })),
                error: None,
            },
            "get_smt_root" => RpcResponse {
                result: Some(serde_json::json!({
                    "smt_root": "0x0000000000000000",
                    "nullifier_count": 0
                })),
                error: None,
            },
            "get_epoch" => RpcResponse {
                result: Some(serde_json::json!({
                    "epoch": 0,
                    "heartbeat_count": 0,
                    "epoch_progress_percent": 0,
                    "heartbeats_per_epoch": 4320
                })),
                error: None,
            },
            "get_peers" => RpcResponse {
                result: Some(serde_json::json!({
                    "peer_count": 0,
                    "peers": []
                })),
                error: None,
            },
            "get_node_state" => RpcResponse {
                result: Some(serde_json::json!({
                    "state": "ACTIVE",
                    "is_synced": true
                })),
                error: None,
            },
            _ => RpcResponse {
                result: None,
                error: Some(format!(
                    "Method '{}' tidak dikenal. Tersedia: get_status, get_smt_root, get_node_state, get_epoch, get_peers",
                    method
                )),
            },
        }
    }
}

impl Default for LocalRpcServer {
    fn default() -> Self {
        Self::new()
    }
}
