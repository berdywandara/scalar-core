// File: crates/scalar-nullifier/src/smt.rs

use std::collections::HashSet;

/// NS_HOT: SMT Depth 32 (Mock menggunakan HashSet untuk testing out-circuit)
/// Akan membuktikan C4 In-Circuit menggunakan Poseidon2
pub struct SparseMerkleTree {
    pub root: [u8; 32],
    leaves: HashSet<[u8; 32]>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            root: [0; 32],
            leaves: HashSet::new(),
        }
    }

    pub fn insert(&mut self, nullifier: &[u8; 32]) {
        self.leaves.insert(*nullifier);
        self.root = *nullifier; // Simulating root change
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.leaves.contains(nullifier)
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}
