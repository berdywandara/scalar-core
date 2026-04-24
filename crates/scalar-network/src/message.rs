//! GAP B-009: ScalarMessage Unified Bus

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MsgType {
    NullifierAnnouncement, // 40 bytes
    SmtRootBroadcast,      // 48 bytes
    CompactProof,          // 30-50 KB
    PeerDiscovery,         // 64 bytes
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransportMeta {
    pub hops: u8,
    pub original_transport: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScalarMessage {
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub transport_metadata: Option<TransportMeta>,
}
