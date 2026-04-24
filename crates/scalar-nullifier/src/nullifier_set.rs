// crates/scalar-nullifier/src/nullifier_set.rs
//! NullifierSet — struktur utama pengganti blockchain di Scalar Network
//! Sesuai Concept 1 (2.5, 3.2.1) dan Concept 5 Final Spec Layer 1

use crate::smt::{ScalarSMT, RootHash, NonMembershipProof};
use crate::NullifierError;

/// Konversi 32-byte nullifier ke index untuk SMT
/// Gunakan 4 byte pertama sebagai index MVP (expandable ke full 256-bit)
fn nullifier_to_index(nullifier: &[u8; 32]) -> u32 {
    u32::from_le_bytes(nullifier[..4].try_into().unwrap_or([0u8; 4]))
}

fn nullifier_to_node_hash(nullifier: &[u8; 32]) -> crate::smt::NodeHash {
    *nullifier
}

/// NullifierSet lengkap: SMT + fast lookup
/// Sesuai Concept 1 2.9: "Node menyimpan Nullifier Set"
/// Sesuai Concept 5 Layer 1: "State: Sparse Merkle Tree (NullifierSet)"
pub struct NullifierSet {
    /// SMT sebagai struktur data utama (matematis, provable)
    pub tree: ScalarSMT,
    /// Fast lookup O(1) — pre-check sebelum SMT traversal
    spent_registry: std::collections::HashSet<[u8; 32]>,
}

impl Default for NullifierSet {
    fn default() -> Self { Self::new() }
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            tree: ScalarSMT::new(),
            spent_registry: std::collections::HashSet::new(),
        }
    }

    /// Root hash saat ini dari seluruh NullifierSet
    /// Sesuai Concept 1 3.2.1: "SMT_Root = MerkleRoot(NullifierSet)"
    pub fn smt_root(&self) -> RootHash {
        self.tree.root()
    }

    /// Cek cepat O(1) apakah nullifier sudah pernah digunakan
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.spent_registry.contains(nullifier)
    }

    /// Tambah nullifier ke set — mencegah double spend
    /// Sesuai Concept 1 Step 3: "Add N to NullifierSet, update SMT Root"
    pub fn add(&mut self, nullifier: [u8; 32]) -> Result<(), NullifierError> {
        if self.is_spent(&nullifier) {
            return Err(NullifierError::AlreadySpent);
        }

        // Fast lookup update
        self.spent_registry.insert(nullifier);

        // SMT update — root berubah secara matematis
        let index = nullifier_to_index(&nullifier);
        let node_hash = nullifier_to_node_hash(&nullifier);
        self.tree.insert(index, node_hash);

        Ok(())
    }

    /// Buat non-membership proof untuk verifikasi ZK
    /// Sesuai Concept 1 3.2.1: "prove nullifier N TIDAK ADA dalam set"
    /// Ini adalah inti dari anti-double-spend Scalar Network
    pub fn prove_non_membership(&self, nullifier: &[u8; 32]) -> Option<NonMembershipProof> {
        if self.is_spent(nullifier) {
            return None; // Sudah digunakan = double spend attempt
        }
        let index = nullifier_to_index(nullifier);
        self.tree.prove_non_membership(index)
    }

    /// Verifikasi bahwa dua node memiliki state yang sama
    /// Sesuai Concept 1 3.2.1: "Dua node dengan SMT Root sama = Nullifier Set sama"
    pub fn matches_root(&self, other_root: &RootHash) -> bool {
        &self.smt_root() == other_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_spend_prevention() {
        let mut ns = NullifierSet::new();
        let nullifier = [9u8; 32];

        assert!(ns.add(nullifier).is_ok());
        assert!(matches!(ns.add(nullifier), Err(NullifierError::AlreadySpent)));
    }

    #[test]
    fn test_smt_root_changes_after_add() {
        let mut ns = NullifierSet::new();
        let root_before = ns.smt_root();
        ns.add([7u8; 32]).unwrap();
        assert_ne!(root_before, ns.smt_root());
    }

    #[test]
    fn test_non_membership_proof_before_spend() {
        let ns = NullifierSet::new();
        let nullifier = [3u8; 32];
        // Sebelum digunakan, harus bisa buat non-membership proof
        assert!(ns.prove_non_membership(&nullifier).is_some());
    }

    #[test]
    fn test_non_membership_proof_after_spend_is_none() {
        let mut ns = NullifierSet::new();
        let nullifier = [3u8; 32];
        ns.add(nullifier).unwrap();
        // Setelah digunakan, non-membership proof harus None
        assert!(ns.prove_non_membership(&nullifier).is_none());
    }
}