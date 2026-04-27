//! MintNullifierSet — Anti double-claim untuk PoU reward
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.3 + §B.2.2 MC2
//!
//! mint_nullifier = Poseidon2(Poseidon2(node_id_lo, epoch_id), POU_MINT_DOMAIN)
//! Identik dengan NullifierSet transfer — Poseidon2 hash (§B.3).

use crate::EmissionError;
use scalar_crypto::poseidon2::hash_2_to_1;
use std::collections::HashSet;

/// Domain separator "pou_mint" sebagai little-endian u64.
const POU_MINT_DOMAIN: u64 = 0x706f755f6d696e74;

/// MintNullifierSet — mencegah node klaim reward lebih dari sekali per epoch.
pub struct MintNullifierSet {
    spent: HashSet<u64>,
}

impl MintNullifierSet {
    pub fn new() -> Self {
        Self {
            spent: HashSet::new(),
        }
    }

    /// Hitung mint nullifier sesuai §B.2.2 MC2:
    /// Poseidon2(Poseidon2(node_id_lo, epoch_id), POU_MINT_DOMAIN)
    pub fn compute_nullifier(node_id: &[u8; 32], epoch_id: u64) -> u64 {
        let node_id_lo = u64::from_le_bytes(node_id[0..8].try_into().unwrap());
        let intermediate = hash_2_to_1(node_id_lo, epoch_id);
        hash_2_to_1(intermediate, POU_MINT_DOMAIN)
    }

    pub fn is_claimed(&self, node_id: &[u8; 32], epoch_id: u64) -> bool {
        self.spent
            .contains(&Self::compute_nullifier(node_id, epoch_id))
    }

    /// Rekam klaim. Panggil hanya setelah MINT_CLAIM_CIRCUIT terverifikasi.
    pub fn record_claim(
        &mut self,
        node_id: &[u8; 32],
        epoch_id: u64,
    ) -> Result<u64, EmissionError> {
        let nullifier = Self::compute_nullifier(node_id, epoch_id);
        if self.spent.contains(&nullifier) {
            return Err(EmissionError::AlreadyClaimed { epoch_id });
        }
        self.spent.insert(nullifier);
        Ok(nullifier)
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }
}

impl Default for MintNullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    #[test]
    fn test_first_claim_ok() {
        assert!(MintNullifierSet::new().record_claim(&node(1), 0).is_ok());
    }

    #[test]
    fn test_double_claim_rejected() {
        let mut mns = MintNullifierSet::new();
        mns.record_claim(&node(1), 0).unwrap();
        assert!(matches!(
            mns.record_claim(&node(1), 0),
            Err(EmissionError::AlreadyClaimed { epoch_id: 0 })
        ));
    }

    #[test]
    fn test_same_node_diff_epochs() {
        let mut mns = MintNullifierSet::new();
        assert!(mns.record_claim(&node(1), 0).is_ok());
        assert!(mns.record_claim(&node(1), 1).is_ok());
    }

    #[test]
    fn test_diff_nodes_same_epoch() {
        let mut mns = MintNullifierSet::new();
        assert!(mns.record_claim(&node(1), 5).is_ok());
        assert!(mns.record_claim(&node(2), 5).is_ok());
    }

    #[test]
    fn test_nullifier_deterministic() {
        assert_eq!(
            MintNullifierSet::compute_nullifier(&node(7), 42),
            MintNullifierSet::compute_nullifier(&node(7), 42)
        );
    }

    #[test]
    fn test_nullifier_unique_across_epochs() {
        assert_ne!(
            MintNullifierSet::compute_nullifier(&node(7), 0),
            MintNullifierSet::compute_nullifier(&node(7), 1)
        );
    }

    #[test]
    fn test_is_claimed_check() {
        let mut mns = MintNullifierSet::new();
        assert!(!mns.is_claimed(&node(3), 10));
        mns.record_claim(&node(3), 10).unwrap();
        assert!(mns.is_claimed(&node(3), 10));
        assert!(!mns.is_claimed(&node(3), 11));
    }
}
