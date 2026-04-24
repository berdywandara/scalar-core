//! Local RPC API untuk komunikasi wallet ↔ node (port 7777)
//! Protokol: HTTP/1.1 sederhana agar bisa ditest dengan curl dan dipakai wallet UI.

use std::net::{TcpListener, TcpStream};
use std::io::{BufRead, BufReader, Write};
use serde::{Deserialize, Serialize};

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

    /// Jalankan server secara blocking — panggil dari spawn_blocking atau thread terpisah.
    pub fn start(&self) {
        let address = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&address)
            .unwrap_or_else(|e| panic!("Gagal bind ke {}: {}", address, e));

        println!("🚀 Scalar RPC Server berjalan di http://{}", address);
        println!("   Test: curl http://localhost:{}", self.port);

        // Loop blocking — ini dijalankan dari spawn_blocking sehingga aman
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                // Setiap koneksi ditangani di thread terpisah agar server tidak blocking
                std::thread::spawn(|| Self::handle_http(stream));
            }
        }
    }

    /// Handle satu HTTP request dan kembalikan JSON response.
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
            .nth(1) // ambil path
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

    /// Route method ke handler yang sesuai.
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
            "get_node_state" => RpcResponse {
                result: Some(serde_json::json!({
                    "state": "ACTIVE",
                    "is_synced": true
                })),
                error: None,
            },
            _ => RpcResponse {
                result: None,
                error: Some(format!("Method '{}' tidak dikenal. Tersedia: get_status, get_smt_root, get_node_state", method)),
            },
        }
    }
}

impl Default for LocalRpcServer {
    fn default() -> Self { Self::new() }
}