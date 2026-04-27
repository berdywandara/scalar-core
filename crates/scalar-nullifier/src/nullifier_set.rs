//! GAP A-004: NullifierSet Integration dengan ScalarSMT
use crate::smt::{NodeHash, ScalarSMT};
use crate::NullifierError;

pub struct NullifierSet {
    pub tree: ScalarSMT,
}

/// Helper untuk konversi nullifier ke tipe NodeHash (u64)
fn nullifier_to_node_hash(nullifier: &[u8; 32]) -> NodeHash {
    // Mengambil 8 byte pertama untuk representasi u64 di Goldilocks Field
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&nullifier[0..8]);
    u64::from_le_bytes(bytes)
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            tree: ScalarSMT::new(),
        }
    }

    /// Menambahkan nullifier baru ke dalam set
    pub fn add(&mut self, index: u64, nullifier: &[u8; 32]) -> Result<(), NullifierError> {
        if self.tree.contains(index) {
            return Err(NullifierError::AlreadyExists);
        }

        let node_hash = nullifier_to_node_hash(nullifier);
        self.tree.insert(index, node_hash);
        Ok(())
    }

    /// Verifikasi apakah koin sudah dibelanjakan
    pub fn is_spent(&self, index: u64) -> bool {
        self.tree.contains(index)
    }
}
