//! Real Libp2p Gossipsub Integration
use crate::message::ScalarMessage;
use libp2p::gossipsub;

pub struct GossipProtocol;

impl GossipProtocol {
    /// Relay ke peer menggunakan implementasi libp2p gossipsub sejati
    pub fn broadcast_delta(
        gossip_behaviour: &mut gossipsub::Behaviour,
        topic: &gossipsub::IdentTopic,
        msg: &ScalarMessage,
    ) -> Result<gossipsub::MessageId, &'static str> {
        if msg.signature.is_empty() {
            return Err("SPHINCS+ Signature missing");
        }

        let payload_bytes = serde_json::to_vec(msg).map_err(|_| "Gagal serialisasi message")?;
        gossip_behaviour
            .publish(topic.clone(), payload_bytes)
            .map_err(|_| "Gagal relay ke gossipsub peers")
    }
}
