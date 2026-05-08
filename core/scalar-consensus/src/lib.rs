// File: crates/scalar-consensus/src/lib.rs
//
// Consensus Engine — Spec §10
// Single Source of Truth: SparseMerkleTree sebagai NullifierSet.

use scalar_nullifier::smt::SparseMerkleTree;

pub struct ConsensusEngine {
    /// Single Source of Truth untuk state transaksi
    pub nullifier_set: SparseMerkleTree,
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusEngine {
    pub fn new() -> Self {
        Self {
            nullifier_set: SparseMerkleTree::new(),
        }
    }

    /// Verifikasi kebenaran matematis (Truth by Mathematics, not Majority).
    /// nullifier: N_network = BLAKE3(N_circuit) dalam format [u8; 32].
    pub fn verify_mathematical_truth(&mut self, nullifier: &[u8; 32]) -> Result<(), &'static str> {
        // 1. Cek double spend — nullifier sudah ada?
        if self.nullifier_set.contains(nullifier) {
            return Err("REJECTED: Double Spend — nullifier sudah ada di SMT");
        }

        // 2. Valid secara matematis — insert ke SMT
        self.nullifier_set.insert(nullifier);

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
