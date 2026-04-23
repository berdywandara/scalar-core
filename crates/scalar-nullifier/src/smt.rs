use scalar_crypto::blake3::{hash, HASH_SIZE};
use std::collections::HashMap;

pub type RootHash = [u8; HASH_SIZE];

/// Kedalaman SMT sejalan dengan ukuran 256-bit dari hash BLAKE3
pub const DEPTH: usize = 256;

/// Sparse Merkle Tree (SMT) Kustom untuk Scalar Network
pub struct ScalarSMT {
    pub root: RootHash,
    /// Menyimpan mapping dari Parent Hash -> (Left Child Hash, Right Child Hash)
    nodes: HashMap<RootHash, (RootHash, RootHash)>,
    /// Cache statis untuk hash dari cabang yang sepenuhnya kosong di setiap level
    empty_roots: Vec<RootHash>,
}

impl Default for ScalarSMT {
    fn default() -> Self {
        Self::new()
    }
}

impl ScalarSMT {
    pub fn new() -> Self {
        let mut empty_roots = Vec::with_capacity(DEPTH + 1);
        let mut current_empty = [0u8; HASH_SIZE];
        empty_roots.push(current_empty);

        // Pre-compute empty roots: dari Leaf (Level 0) naik ke Root (Level 256)
        for _ in 0..DEPTH {
            let mut combined = Vec::with_capacity(HASH_SIZE * 2);
            combined.extend_from_slice(&current_empty);
            combined.extend_from_slice(&current_empty);
            current_empty = hash(&combined);
            empty_roots.push(current_empty);
        }

        Self {
            root: empty_roots[DEPTH], // Root default saat tree kosong
            nodes: HashMap::new(),
            empty_roots,
        }
    }

    /// Helper untuk menghitung hash gabungan dari dua node
    pub fn branch_hash(left: &RootHash, right: &RootHash) -> RootHash {
        let mut combined = Vec::with_capacity(HASH_SIZE * 2);
        combined.extend_from_slice(left);
        combined.extend_from_slice(right);
        hash(&combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smt_initialization() {
        let smt = ScalarSMT::new();
        
        // Verifikasi array empty_roots memiliki 257 elemen (Level 0 hingga 256)
        assert_eq!(smt.empty_roots.len(), DEPTH + 1);
        
        // Verifikasi root SMT cocok dengan perhitungan root kosong pada level 256
        assert_eq!(smt.root, smt.empty_roots[DEPTH]);
    }

    #[test]
    fn test_branch_hash_determinism() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let h1 = ScalarSMT::branch_hash(&left, &right);
        let h2 = ScalarSMT::branch_hash(&left, &right);
        assert_eq!(h1, h2, "Branch hashing harus deterministik");
    }
}
