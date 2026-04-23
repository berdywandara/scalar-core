use crate::NetworkError;

/// Mengatur logika penyebaran state delta (Delta Gossip) antar node
pub struct GossipManager {
    // libp2p gossipsub instance akan diletakkan di sini
}

impl GossipManager {
    pub fn broadcast_delta(&self, _data: &[u8]) -> Result<(), NetworkError> {
        // Todo: Implementasi penyebaran Nullifier + STARK proof
        unimplemented!("Gossip broadcast pending libp2p implementation");
    }
}
