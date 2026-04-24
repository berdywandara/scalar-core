//! Real Tor SOCKS5 Integration
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

pub struct TorTransport {
    pub socks5_proxy: String,
}

impl TorTransport {
    pub fn new() -> Self {
        Self {
            socks5_proxy: "127.0.0.1:9050".to_string(), // Tor daemon standar
        }
    }

    /// Membuat koneksi SOCKS5 NYATA ke node .onion, bukan hanya println stub
    pub async fn connect_onion(&self, onion_address: &str, port: u16) -> Result<Socks5Stream<TcpStream>, &'static str> {
        let proxy_addr = self.socks5_proxy.as_str();
        
        // Membuka arus TCP sesungguhnya menuju layer Tor
        Socks5Stream::connect(proxy_addr, (onion_address, port))
            .await
            .map_err(|_| "Gagal membuka jalur SOCKS5 ke Tor daemon. Pastikan layanan Tor menyala.")
    }
}
