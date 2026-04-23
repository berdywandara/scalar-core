pub mod gossip;
pub mod peer_discovery;
pub mod transport;

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Failed to establish connection")]
    ConnectionFailed,
    #[error("Message propagation failed")]
    PropagationError,
    #[error("Invalid transport selected")]
    TransportNotSupported,
}
