//! Sparse Merkle Tree untuk pencegahan Double-Spend

pub type RootHash = [u8; 32];

pub struct NullifierSet {
    pub smt_root: RootHash,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self { smt_root: [0; 32] }
    }

    /// Membuktikan bahwa Nullifier TIDAK ADA dalam set (Anti Double-Spend)
    pub fn prove_non_membership(&self, _nullifier: &[u8; 32]) -> Vec<u8> {
        // TODO: Implementasi traverse SMT untuk mencari Empty Node
        vec![]
    }
}
