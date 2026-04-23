pub mod api;
pub mod state_machine;
pub mod sybil;
pub mod gossip;

// Mengekspos struktur agar bisa dipanggil oleh binari utama
pub use sybil::NodeIdentity;
pub use gossip::ScalarGossipMessage;
