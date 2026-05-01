pub mod config;
pub mod message;
pub mod onion;
pub mod peer_discovery;
pub mod routing;
pub mod state_machine;
pub mod time;
pub mod tor;
pub mod tor_backup;
pub mod transport;

pub mod gossip;

// Export struct baru yang relevan dari gossip v5.0
pub use gossip::GossipNode;
pub use gossip::ScalarGossipMessage;
