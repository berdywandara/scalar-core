// crates/scalar-nullifier/src/smt.rs
//! Sparse Merkle Tree untuk Nullifier Set
//! Sesuai Concept 1 (3.2.1) dan Concept 5 Final Spec Layer 1
//! Dioptimalkan untuk Goldilocks Field (u64) dari Poseidon2
//! Depth: 32 (cukup untuk 2^32 nullifiers dalam MVP, expandable ke 256)

use scalar_crypto::poseidon2::hash_2_to_1;
use std::collections::HashMap;

pub type RootHash = u64;
pub type NodeHash = u64;

pub const SMT_DEPTH: usize = 32;

/// Nilai hash yang merepresentasikan "leaf kosong" dalam SMT
/// EMPTY_LEAF = Poseidon2(0, 0) = nilai konstan yang diketahui semua node
fn empty_leaf() -> NodeHash {
    hash_2_to_1(0, 0)
}

/// Precompute empty node hashes untuk setiap level
fn precompute_empty_nodes() -> Vec<NodeHash> {
    let mut empty_nodes = vec![0u64; SMT_DEPTH + 1];
    empty_nodes[0] = empty_leaf();
    for i in 1..=SMT_DEPTH {
        empty_nodes[i] = hash_2_to_1(empty_nodes[i - 1], empty_nodes[i - 1]);
    }
    empty_nodes
}

/// Proof bahwa sebuah nullifier ADA dalam set (membership)
pub struct MembershipProof {
    pub leaf: NodeHash,
    pub siblings: Vec<NodeHash>, // sibling hashes dari leaf ke root
}

/// Proof bahwa sebuah nullifier TIDAK ADA dalam set (non-membership)
/// Inti dari anti-double-spend Scalar Network
pub struct NonMembershipProof {
    pub siblings: Vec<NodeHash>, // path dari posisi kosong ke root
}

/// Sparse Merkle Tree untuk NullifierSet
/// Sesuai Concept 1 Fase 3.2.1: "bisa prove membership dan non-membership"
pub struct ScalarSMT {
    /// Leaves yang terisi: index -> NodeHash (u64 -> u64)
    leaves: HashMap<u64, NodeHash>,
    /// Pre-computed empty node hashes
    empty_nodes: Vec<NodeHash>,
}

impl ScalarSMT {
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            empty_nodes: precompute_empty_nodes(),
        }
    }

    /// Hitung root hash dari seluruh state SMT
    pub fn root(&self) -> RootHash {
        self.compute_node(SMT_DEPTH, 0)
    }

    fn compute_node(&self, depth: usize, index: u64) -> NodeHash {
        if depth == 0 {
            // Leaf level
            return self
                .leaves
                .get(&index)
                .copied()
                .unwrap_or(self.empty_nodes[0]);
        }
        let left = self.compute_node(depth - 1, index * 2);
        let right = self.compute_node(depth - 1, index * 2 + 1);
        hash_2_to_1(left, right)
    }

    /// Insert nullifier ke dalam SMT
    pub fn insert(&mut self, nullifier_index: u64, nullifier_hash: NodeHash) {
        self.leaves.insert(nullifier_index, nullifier_hash);
    }

    /// Cek apakah nullifier ada di SMT
    pub fn contains(&self, nullifier_index: u64) -> bool {
        self.leaves.contains_key(&nullifier_index)
    }

    /// Buat proof NON-MEMBERSHIP — inti anti-double-spend
    pub fn prove_non_membership(&self, nullifier_index: u64) -> Option<NonMembershipProof> {
        if self.contains(nullifier_index) {
            return None; // Nullifier sudah ada → double spend!
        }

        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        let mut current_index = nullifier_index;

        for depth in 0..SMT_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling = self.compute_node(depth, sibling_index);
            siblings.push(sibling);
            current_index /= 2;
        }

        Some(NonMembershipProof { siblings })
    }

    /// Verifikasi proof non-membership terhadap root yang diketahui
    pub fn verify_non_membership(
        nullifier_index: u64,
        proof: &NonMembershipProof,
        expected_root: &RootHash,
        empty_nodes: &[NodeHash],
    ) -> bool {
        if proof.siblings.len() != SMT_DEPTH {
            return false;
        }

        // Mulai dari posisi kosong (empty leaf)
        let mut current = empty_nodes[0];
        let mut current_index = nullifier_index;

        for sibling in &proof.siblings {
            let (left, right) = if current_index % 2 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = hash_2_to_1(left, right);
            current_index /= 2;
        }

        &current == expected_root
    }

    /// Buat proof MEMBERSHIP
    pub fn prove_membership(&self, nullifier_index: u64) -> Option<MembershipProof> {
        let leaf = self.leaves.get(&nullifier_index).copied()?;
        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        let mut current_index = nullifier_index;

        for depth in 0..SMT_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            siblings.push(self.compute_node(depth, sibling_index));
            current_index /= 2;
        }

        Some(MembershipProof { leaf, siblings })
    }
}

impl Default for ScalarSMT {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_smt_has_known_root() {
        let smt = ScalarSMT::new();
        let root = smt.root();
        // Root dari SMT kosong harus deterministik
        let root2 = ScalarSMT::new().root();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_non_membership_proof_valid() {
        let smt = ScalarSMT::new();
        let empty_nodes = precompute_empty_nodes();
        let root = smt.root();

        // Nullifier belum ada → harus bisa buat non-membership proof
        let proof = smt
            .prove_non_membership(42)
            .expect("harus bisa prove non-membership");
        assert!(ScalarSMT::verify_non_membership(
            42,
            &proof,
            &root,
            &empty_nodes
        ));
    }

    #[test]
    fn test_insert_invalidates_non_membership() {
        let mut smt = ScalarSMT::new();
        let nullifier_hash = 12345u64; // Tipe data sekarang u64
        smt.insert(42, nullifier_hash);

        // Setelah insert, non-membership proof harus None
        assert!(smt.prove_non_membership(42).is_none());
        assert!(smt.contains(42));
    }

    #[test]
    fn test_root_changes_after_insert() {
        let mut smt = ScalarSMT::new();
        let root_before = smt.root();
        smt.insert(99, 98765u64); // Tipe data sekarang u64
        let root_after = smt.root();
        assert_ne!(root_before, root_after);
    }
}
