pub mod api;
pub mod gossip;
pub mod state_machine;
pub mod sybil;

// Mengekspos struktur agar bisa dipanggil oleh binari utama
pub use gossip::ScalarGossipMessage;
pub use sybil::NodeIdentity;
pub mod swarm;
pub mod heartbeat_service;
pub mod epoch_anchor;
pub mod node_id;
