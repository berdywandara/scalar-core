pub mod formal;
// File: crates/scalar-consensus/src/lib.rs
//
// Consensus Engine — Spec §10
// Single Source of Truth: NullifierSet 2-layer (NS_ACTIVE + NS_CHECKPOINT).
// Spec §6.1: NullifierSet adalah abstraksi resmi untuk double-spend prevention.

use scalar_nullifier::NullifierSet;

pub struct ConsensusEngine {
    /// Single Source of Truth untuk state transaksi — spec §6.1.
    pub nullifier_set: NullifierSet,
    /// Epoch saat ini — digunakan untuk insert ke NS_ACTIVE.
    pub current_epoch: u64,
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusEngine {
    pub fn new() -> Self {
        Self {
            nullifier_set: NullifierSet::new(),
            current_epoch: 0,
        }
    }

    /// Verifikasi kebenaran matematis (Truth by Mathematics, not Majority).
    ///
    /// nullifier: N_network = BLAKE3(N_circuit) dalam format [u8; 32].
    /// Spec §6.3: is_spent() + insert() atomik.
    pub fn verify_mathematical_truth(&mut self, nullifier: &[u8; 32]) -> Result<(), &'static str> {
        // 1. Cek double spend via NullifierSet 2-layer — spec §6.3 is_spent()
        if self.nullifier_set.is_spent(nullifier) {
            return Err("REJECTED: Double Spend — nullifier sudah ada di NullifierSet");
        }

        // 2. Valid secara matematis — insert ke NS_ACTIVE — spec §6.3 insert()
        self.nullifier_set.insert(nullifier, self.current_epoch);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_nullifier_accepted() {
        let mut engine = ConsensusEngine::new();
        let nullifier = [1u8; 32];
        assert!(engine.verify_mathematical_truth(&nullifier).is_ok());
    }

    #[test]
    fn test_double_spend_rejected() {
        let mut engine = ConsensusEngine::new();
        let nullifier = [2u8; 32];
        engine.verify_mathematical_truth(&nullifier).unwrap();
        assert!(engine.verify_mathematical_truth(&nullifier).is_err());
    }

    #[test]
    fn test_different_nullifiers_accepted() {
        let mut engine = ConsensusEngine::new();
        assert!(engine.verify_mathematical_truth(&[1u8; 32]).is_ok());
        assert!(engine.verify_mathematical_truth(&[2u8; 32]).is_ok());
        assert!(engine.verify_mathematical_truth(&[3u8; 32]).is_ok());
    }
}
