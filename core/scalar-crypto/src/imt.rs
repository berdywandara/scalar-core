//! Incremental Merkle Tree (IMT) — Research Package §3.1
//!
//! Append-only binary Merkle tree with O(1) frontier updates.
//! Hash: Poseidon2 in-circuit ONLY. Spec §2.1.
//! Domain separators: OSSIFIED — Research Package Bagian 8.
//!
//! INV-4.1: imt_membership_verify TRUE iff commitment at leaf_index.
//! INV-4.2: Same insertions → identical frontier bit-per-bit.
//! INV-4.6: UTXOSource mutually exclusive per input.
//! Decision D-003: imt_frontier_root MUST come from quorum SubEpochCommitment.
//! Decision D-006: DOMAIN_IMT_FRONTIER only in SubEpochCommitment hash.

use crate::domain::{DOMAIN_IMT_LEAF, DOMAIN_IMT_NODE};
use crate::poseidon2::field_reduce;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const IMT_DEPTH: usize = 32;
pub const IMT_EMPTY_ROOT: [u8; 32] = [0u8; 32];
pub const IMT_GENESIS_FRONTIER: [[u8; 32]; IMT_DEPTH] = [[0u8; 32]; IMT_DEPTH];

// ── UTXOSource ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UTXOSource {
    EpochSMT,
    SubEpochIMT,
}

// ── IMTError ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMTError {
    TreeFull,
    LeafIndexOutOfBounds { index: u64, count: u64 },
    InvalidPathLength { expected: usize, got: usize },
}

impl core::fmt::Display for IMTError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TreeFull => write!(f, "IMT full"),
            Self::LeafIndexOutOfBounds { index, count } => {
                write!(f, "leaf_index {index} >= count {count}")
            }
            Self::InvalidPathLength { expected, got } => {
                write!(f, "path length {got} != {expected}")
            }
        }
    }
}

// ── IMTPath ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMTPath {
    pub siblings: Vec<[u8; 32]>,
    pub leaf_index: u64,
}

impl IMTPath {
    pub fn new(siblings: Vec<[u8; 32]>, leaf_index: u64) -> Result<Self, IMTError> {
        if siblings.len() != IMT_DEPTH {
            return Err(IMTError::InvalidPathLength {
                expected: IMT_DEPTH,
                got: siblings.len(),
            });
        }
        Ok(Self {
            siblings,
            leaf_index,
        })
    }
}

// ── Hash helpers ──────────────────────────────────────────────────────────────

fn bytes_to_field_elems_with_domain(
    domain: &[u8],
    data1: &[u8; 32],
    data2: Option<&[u8; 32]>,
) -> Vec<u64> {
    let mut input = Vec::new();
    // domain → 2 field elements (8 bytes each)
    let mut d0 = [0u8; 8];
    let copy_len = domain.len().min(8);
    d0[..copy_len].copy_from_slice(&domain[..copy_len]);
    input.push(field_reduce(u64::from_le_bytes(d0)));
    let mut d1 = [0u8; 8];
    if domain.len() > 8 {
        let rem = domain.len() - 8;
        d1[..rem].copy_from_slice(&domain[8..]);
    }
    input.push(field_reduce(u64::from_le_bytes(d1)));
    // data1 → 4 field elements
    for chunk in data1.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        input.push(field_reduce(u64::from_le_bytes(buf)));
    }
    // optional data2 → 4 field elements
    if let Some(d) = data2 {
        for chunk in d.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            input.push(field_reduce(u64::from_le_bytes(buf)));
        }
    }
    input
}

fn field_elems_to_bytes(elems: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &e) in elems.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&e.to_le_bytes());
    }
    out
}

fn hash_imt_leaf(commitment: &[u8; 32], leaf_index: u64) -> [u8; 32] {
    let mut input = bytes_to_field_elems_with_domain(DOMAIN_IMT_LEAF, commitment, None);
    input.push(field_reduce(leaf_index));
    let result = crate::poseidon2::Poseidon2Hasher::hash(&input);
    field_elems_to_bytes(&result)
}

fn hash_imt_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if *left == IMT_EMPTY_ROOT && *right == IMT_EMPTY_ROOT {
        return IMT_EMPTY_ROOT;
    }
    let input = bytes_to_field_elems_with_domain(DOMAIN_IMT_NODE, left, Some(right));
    let result = crate::poseidon2::Poseidon2Hasher::hash(&input);
    field_elems_to_bytes(&result)
}

// ── IncrementalMerkleTree ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IncrementalMerkleTree {
    pub frontier: [[u8; 32]; IMT_DEPTH],
    pub count: u64,
    leaves: Vec<[u8; 32]>,
}

impl IncrementalMerkleTree {
    pub fn new() -> Self {
        Self {
            frontier: IMT_GENESIS_FRONTIER,
            count: 0,
            leaves: Vec::new(),
        }
    }

    pub fn append(&mut self, commitment: &[u8; 32]) -> Result<u64, IMTError> {
        if self.count >= (1u64 << (IMT_DEPTH as u64 - 1)) {
            return Err(IMTError::TreeFull);
        }
        let leaf_index = self.count;
        let leaf_hash = hash_imt_leaf(commitment, leaf_index);
        self.leaves.push(leaf_hash);

        let mut current = leaf_hash;
        let mut n = leaf_index;
        for i in 0..IMT_DEPTH {
            if n & 1 == 0 {
                self.frontier[i] = current;
                break;
            } else {
                let left = self.frontier[i];
                current = hash_imt_node(&left, &current);
                self.frontier[i] = IMT_EMPTY_ROOT;
            }
            n >>= 1;
        }

        self.count += 1;
        Ok(leaf_index)
    }

    pub fn root(&self) -> [u8; 32] {
        if self.count == 0 {
            return IMT_EMPTY_ROOT;
        }
        let mut current = IMT_EMPTY_ROOT;
        let mut n = self.count;
        for i in 0..IMT_DEPTH {
            if n & 1 == 1 {
                current = if current == IMT_EMPTY_ROOT {
                    self.frontier[i]
                } else {
                    hash_imt_node(&self.frontier[i], &current)
                };
            }
            n >>= 1;
            if n == 0 {
                break;
            }
        }
        current
    }

    pub fn prove_membership(&self, leaf_index: u64) -> Result<IMTPath, IMTError> {
        if leaf_index >= self.count {
            return Err(IMTError::LeafIndexOutOfBounds {
                index: leaf_index,
                count: self.count,
            });
        }
        let siblings = self.compute_siblings(leaf_index);
        IMTPath::new(siblings, leaf_index)
    }

    fn compute_siblings(&self, leaf_index: u64) -> Vec<[u8; 32]> {
        let mut siblings = vec![IMT_EMPTY_ROOT; IMT_DEPTH];
        let mut current_level: Vec<[u8; 32]> = self.leaves.clone();
        let mut path_idx = leaf_index as usize;

        for sibling_slot in siblings.iter_mut() {
            let len = current_level.len();
            if len == 0 {
                break;
            }
            let sib_idx = path_idx ^ 1;
            *sibling_slot = if sib_idx < len {
                current_level[sib_idx]
            } else {
                IMT_EMPTY_ROOT
            };
            let mut next_level = Vec::with_capacity(len.div_ceil(2));
            let mut j = 0;
            while j < len {
                if j + 1 < len {
                    next_level.push(hash_imt_node(&current_level[j], &current_level[j + 1]));
                } else {
                    // Odd node carries up as-is — matches root()/frontier behavior.
                    next_level.push(current_level[j]);
                }
                j += 2;
            }
            current_level = next_level;
            path_idx /= 2;
            if current_level.len() <= 1 {
                break;
            }
        }

        siblings
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ── imt_membership_verify — OSSIFIED ─────────────────────────────────────────

pub fn imt_membership_verify(
    commitment: &[u8; 32],
    path: &IMTPath,
    root: &[u8; 32],
    imt_commitment_count: u64,
) -> bool {
    if path.leaf_index >= imt_commitment_count {
        return false;
    }
    if path.siblings.len() != IMT_DEPTH {
        return false;
    }

    let mut current = hash_imt_leaf(commitment, path.leaf_index);

    for level in 0..IMT_DEPTH {
        let sibling = &path.siblings[level];
        let is_right = (path.leaf_index >> level) & 1;

        // Mirror compute_siblings: odd node carries up as-is when sibling is empty.
        current = if *sibling == IMT_EMPTY_ROOT && current != IMT_EMPTY_ROOT {
            current
        } else if is_right == 0 {
            hash_imt_node(&current, sibling)
        } else {
            hash_imt_node(sibling, &current)
        };
    }

    &current == root
}

// ── VerificationResult ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    Valid,
    SubEpochNotFound,
    SubEpochQuorumFailed { subepoch_id: u32 },
    SubEpochHashMismatch,
    IMTFrontierMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSubEpochRef {
    pub epoch_id: u64,
    pub subepoch_id: u32,
    pub subepoch_hash: [u8; 32],
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tv_5_1_genesis_state() {
        let imt = IncrementalMerkleTree::new();
        assert_eq!(imt.frontier, IMT_GENESIS_FRONTIER);
        assert_eq!(imt.count, 0);
        assert_eq!(imt.root(), IMT_EMPTY_ROOT);
    }

    #[test]
    fn tv_5_2_single_commitment_membership() {
        let commitment = [0xABu8; 32];
        let mut imt = IncrementalMerkleTree::new();
        let idx = imt.append(&commitment).unwrap();
        assert_eq!(idx, 0);
        let root = imt.root();
        let path = imt.prove_membership(0).unwrap();
        assert!(
            imt_membership_verify(&commitment, &path, &root, imt.count),
            "tv_5_2: must return TRUE"
        );
        let mut bad = commitment;
        bad[0] ^= 0xFF;
        assert!(!imt_membership_verify(&bad, &path, &root, imt.count));
        let mut path_wrong = path.clone();
        path_wrong.leaf_index = 1;
        assert!(!imt_membership_verify(
            &commitment,
            &path_wrong,
            &root,
            imt.count
        ));
    }

    #[test]
    fn inv_4_1_soundness_multiple_commitments() {
        let mut imt = IncrementalMerkleTree::new();
        let c0 = [0x01u8; 32];
        let c1 = [0x02u8; 32];
        let c2 = [0x03u8; 32];
        imt.append(&c0).unwrap();
        imt.append(&c1).unwrap();
        imt.append(&c2).unwrap();
        let root = imt.root();
        let count = imt.count;
        let p0 = imt.prove_membership(0).unwrap();
        let p1 = imt.prove_membership(1).unwrap();
        let p2 = imt.prove_membership(2).unwrap();
        assert!(imt_membership_verify(&c0, &p0, &root, count));
        assert!(imt_membership_verify(&c1, &p1, &root, count));
        assert!(imt_membership_verify(&c2, &p2, &root, count));
        assert!(!imt_membership_verify(&c0, &p1, &root, count));
        assert!(!imt_membership_verify(&c1, &p0, &root, count));
        assert!(!imt_membership_verify(&c2, &p0, &root, count));
    }

    #[test]
    fn inv_4_2_determinism_same_insertions() {
        let commitments = [[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]];
        let mut imt_a = IncrementalMerkleTree::new();
        let mut imt_b = IncrementalMerkleTree::new();
        for c in &commitments {
            imt_a.append(c).unwrap();
            imt_b.append(c).unwrap();
        }
        assert_eq!(imt_a.root(), imt_b.root());
        assert_eq!(imt_a.frontier, imt_b.frontier);
    }

    #[test]
    fn inv_4_6_utxo_source_is_enum() {
        assert_ne!(UTXOSource::EpochSMT, UTXOSource::SubEpochIMT);
    }

    #[test]
    fn genesis_window_sub_epoch_0() {
        let imt = IncrementalMerkleTree::new();
        assert_eq!(imt.root(), [0u8; 32]);
        assert_eq!(imt.count, 0);
    }

    #[test]
    fn test_imt_commitment_count_bounds() {
        let mut imt = IncrementalMerkleTree::new();
        let c = [0x42u8; 32];
        imt.append(&c).unwrap();
        let root = imt.root();
        let path = imt.prove_membership(0).unwrap();
        assert!(!imt_membership_verify(&c, &path, &root, 0));
        assert!(imt_membership_verify(&c, &path, &root, 1));
    }

    #[test]
    fn test_root_changes_on_append() {
        let mut imt = IncrementalMerkleTree::new();
        let r0 = imt.root();
        imt.append(&[0x01u8; 32]).unwrap();
        let r1 = imt.root();
        imt.append(&[0x02u8; 32]).unwrap();
        let r2 = imt.root();
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);
        assert_ne!(r0, r2);
    }

    #[test]
    fn test_append_returns_sequential_indices() {
        let mut imt = IncrementalMerkleTree::new();
        for i in 0u64..5 {
            assert_eq!(imt.append(&[i as u8; 32]).unwrap(), i);
        }
        assert_eq!(imt.count, 5);
    }

    #[test]
    fn test_prove_membership_out_of_bounds() {
        let imt = IncrementalMerkleTree::new();
        let err = imt.prove_membership(0).unwrap_err();
        assert_eq!(err, IMTError::LeafIndexOutOfBounds { index: 0, count: 0 });
    }

    #[test]
    fn test_verification_result_variants() {
        let _ = VerificationResult::Valid;
        let _ = VerificationResult::SubEpochNotFound;
        let _ = VerificationResult::SubEpochQuorumFailed { subepoch_id: 1 };
        let _ = VerificationResult::SubEpochHashMismatch;
        let _ = VerificationResult::IMTFrontierMismatch;
    }

    #[test]
    fn test_transaction_subepoch_ref_struct() {
        let r = TransactionSubEpochRef {
            epoch_id: 1,
            subepoch_id: 42,
            subepoch_hash: [0xABu8; 32],
        };
        assert_eq!(r.epoch_id, 1);
        assert_eq!(r.subepoch_id, 42);
    }

    #[test]
    fn test_hash_imt_leaf_different_indices_differ() {
        let c = [0x55u8; 32];
        assert_ne!(hash_imt_leaf(&c, 0), hash_imt_leaf(&c, 1));
    }

    #[test]
    fn test_hash_imt_node_asymmetric() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_ne!(hash_imt_node(&a, &b), hash_imt_node(&b, &a));
    }

    #[test]
    fn test_imt_constants() {
        assert_eq!(IMT_DEPTH, 32);
        assert_eq!(IMT_EMPTY_ROOT, [0u8; 32]);
        assert_eq!(IMT_GENESIS_FRONTIER, [[0u8; 32]; 32]);
    }

    #[test]
    fn test_imt_path_wrong_length_rejected() {
        let err = IMTPath::new(vec![[0u8; 32]; 10], 0).unwrap_err();
        assert_eq!(
            err,
            IMTError::InvalidPathLength {
                expected: 32,
                got: 10
            }
        );
    }

    #[test]
    fn test_larger_tree_verify() {
        let mut imt = IncrementalMerkleTree::new();
        for i in 0u64..8 {
            imt.append(&[i as u8; 32]).unwrap();
        }
        let root = imt.root();
        let count = imt.count;
        for i in 0u64..8 {
            let path = imt.prove_membership(i).unwrap();
            assert!(
                imt_membership_verify(&[i as u8; 32], &path, &root, count),
                "verify must pass for leaf {i}"
            );
        }
    }
}
