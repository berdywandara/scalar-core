pub mod api;
pub mod gossip;
pub mod state_machine;
pub mod sybil;

// Mengekspos struktur agar bisa dipanggil oleh binari utama
pub use gossip::ScalarGossipMessage;
pub use sybil::NodeIdentity;
