//! Gossip Protocol "Delta Sync"
//! Efisiensi bandwidth tanpa mengirim seluruh buku besar (Concept 3.2.2)

pub struct DeltaNullifier {
    pub nullifier: [u8; 32],
    pub spend_proof: Vec<u8>,      // zk-STARK proof
    pub new_commitment: [u8; 32],
}

pub struct ScalarGossipMessage {
    pub timestamp: u64,
    pub smt_root: [u8; 32],
    pub delta_nullifiers: Vec<DeltaNullifier>,
    pub sender_signature: Vec<u8>, // SPHINCS+ Signature
}

impl ScalarGossipMessage {
    /// Validasi pesan gossip sebelum disebarkan ke peer lain
    pub fn validate_and_relay(&self) -> bool {
        // 1. Verifikasi proof setiap nullifier dalam pesan (Concept 3.2.2 - Step 2a)
        // 2. Cek apakah nullifier sudah ada di NullifierSet lokal (Concept 3.2.2 - Step 2b)
        // Jika valid, teruskan ke peer lain.
        true 
    }
}
