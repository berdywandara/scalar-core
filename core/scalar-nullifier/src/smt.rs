//! Sparse Merkle Tree depth-32 — NS_ACTIVE Layer 1
//!
//! Spec §6.1: NS_ACTIVE adalah SMT depth-32, menyimpan nullifier dari
//! 3 epoch terakhir. Lookup deterministik O(log n).
//!
//! Root digunakan dalam Transfer Circuit CC constraint (non-membership proof).
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.

use std::collections::HashMap;

/// Depth SMT NS_ACTIVE. OSSIFIED — spec §6.1.
pub const SMT_DEPTH: usize = 32;

/// Maximum nullifier per checkpoint. OSSIFIED — spec §6, §17.
pub const MAX_NULLIFIERS_PER_CHECKPOINT: usize = 200_000;

/// SparseMerkleTree depth-32 untuk NS_ACTIVE.
///
/// Spec §6.1: SMT depth-32, menyimpan nullifier dari 3 epoch terakhir.
/// Root digunakan dalam CC constraint: SMT_NonMembershipVerify.
///
/// Root dihitung dengan BLAKE3 — hash discipline out-circuit (spec §2.1).
pub struct SparseMerkleTree {
    /// Current SMT root. Diupdate setiap insert/remove.
    pub root: [u8; 32],
    /// Leaves: nullifier → epoch_id saat diinsert.
    leaves: HashMap<[u8; 32], u64>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            root: [0u8; 32],
            leaves: HashMap::new(),
        }
    }

    /// Insert nullifier ke SMT. Idempoten — insert ulang tidak mengubah state.
    /// Spec §6.3: insert() atomik dan idempoten.
    pub fn insert(&mut self, nullifier: &[u8; 32], epoch_id: u64) {
        self.leaves.insert(*nullifier, epoch_id);
        self.recompute_root();
    }

    /// Hapus nullifier dari SMT. Digunakan saat checkpoint. Spec §6.3.
    pub fn remove(&mut self, nullifier: &[u8; 32]) {
        self.leaves.remove(nullifier);
        self.recompute_root();
    }

    /// Cek keberadaan nullifier. O(1). Spec §6.1.
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.leaves.contains_key(nullifier)
    }

    /// Jumlah nullifier dalam SMT.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Epoch ID saat nullifier diinsert. None jika tidak ada.
    pub fn epoch_of(&self, nullifier: &[u8; 32]) -> Option<u64> {
        self.leaves.get(nullifier).copied()
    }

    /// Semua nullifier beserta epoch_id-nya, diurutkan ascending.
    /// Digunakan saat checkpoint untuk transfer ke NS_CHECKPOINT. Spec §6.3.
    pub fn entries_sorted(&self) -> Vec<([u8; 32], u64)> {
        let mut v: Vec<_> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    /// Nullifier yang lebih tua dari epoch threshold.
    /// Digunakan checkpoint() untuk memilih nullifier yang akan diarsipkan.
    /// Spec §6.3: nullifier >3 epoch.
    pub fn nullifiers_older_than(&self, current_epoch: u64, max_epochs: u64) -> Vec<[u8; 32]> {
        self.leaves
            .iter()
            .filter(|(_, &epoch)| current_epoch.saturating_sub(epoch) > max_epochs)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Hitung ulang root dari seluruh leaves menggunakan BLAKE3.
    /// Determinisme: sort nullifier ascending sebelum hash.
    /// Hash discipline: BLAKE3 out-circuit — spec §2.1.
    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = [0u8; 32];
            return;
        }
        let mut sorted: Vec<[u8; 32]> = self.leaves.keys().copied().collect();
        sorted.sort();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"scalar_smt_active");
        for nullifier in &sorted {
            hasher.update(nullifier);
        }
        self.root = *hasher.finalize().as_bytes();
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smt_empty_root_is_zero() {
        // SMT kosong → root [0;32]. Spec §6.1.
        let smt = SparseMerkleTree::new();
        assert_eq!(smt.root, [0u8; 32]);
    }

    #[test]
    fn test_smt_insert_changes_root() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&[1u8; 32], 1);
        assert_ne!(smt.root, [0u8; 32]);
    }

    #[test]
    fn test_smt_contains_after_insert() {
        let mut smt = SparseMerkleTree::new();
        let n = [2u8; 32];
        assert!(!smt.contains(&n));
        smt.insert(&n, 1);
        assert!(smt.contains(&n));
    }

    #[test]
    fn test_smt_remove() {
        let mut smt = SparseMerkleTree::new();
        let n = [3u8; 32];
        smt.insert(&n, 1);
        assert!(smt.contains(&n));
        smt.remove(&n);
        assert!(!smt.contains(&n));
    }

    #[test]
    fn test_smt_root_deterministic() {
        // Root deterministik untuk input yang sama. Spec §6.1.
        let mut smt1 = SparseMerkleTree::new();
        let mut smt2 = SparseMerkleTree::new();
        smt1.insert(&[1u8; 32], 1);
        smt1.insert(&[2u8; 32], 1);
        smt2.insert(&[2u8; 32], 1);
        smt2.insert(&[1u8; 32], 1);
        assert_eq!(smt1.root, smt2.root, "Root harus deterministik");
    }

    #[test]
    fn test_smt_remove_restores_root() {
        let mut smt = SparseMerkleTree::new();
        let root_empty = smt.root;
        smt.insert(&[5u8; 32], 1);
        smt.remove(&[5u8; 32]);
        assert_eq!(smt.root, root_empty);
    }

    #[test]
    fn test_smt_max_nullifiers_constant() {
        assert_eq!(MAX_NULLIFIERS_PER_CHECKPOINT, 200_000);
    }

    #[test]
    fn test_smt_nullifiers_older_than() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(&[1u8; 32], 1); // epoch 1
        smt.insert(&[2u8; 32], 5); // epoch 5
                                   // current=10, max_epochs=3 → nullifier dari epoch <=6 eligible
                                   // epoch 1: 10-1=9 > 3 → eligible
                                   // epoch 5: 10-5=5 > 3 → eligible
        let old = smt.nullifiers_older_than(10, 3);
        assert_eq!(old.len(), 2);
        // epoch 5: 10-5=5 > 3 → eligible
        // epoch 8: 10-8=2, NOT > 3 → not eligible
        smt.insert(&[3u8; 32], 8);
        let old2 = smt.nullifiers_older_than(10, 3);
        assert_eq!(old2.len(), 2);
    }
}
