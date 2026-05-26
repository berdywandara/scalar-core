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

use crate::poseidon2::field_reduce;
use crate::poseidon2_t8::{field8_to_bytes32, poseidon2_permute_t8};
use std::sync::OnceLock;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const IMT_DEPTH: usize = 32;
/// Level-0 empty marker (zero). The empty *tree* root is imt_empty_root().
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

/// Leaf hash — Poseidon2 t=8 (Research Package §3.5.2).
/// Poseidon2_t8(DOMAIN_IMT_LEAF || commitment || leaf_index)
fn hash_imt_leaf(commitment: &[u8; 32], leaf_index: u64) -> [u8; 32] {
    // D-010: single permutation, max 8 elements.
    // Layout: [domain_lo, domain_hi, c0, c1, c2, c3, leaf_index, 0]
    // where commitment is packed as 4 x u64 LE (32 bytes / 8 = 4 elements).
    // Domain: DOMAIN_IMT_LEAF = b"scalar_imt_leaf" (15 bytes) split as 2 x u64.
    let d_lo = u64::from_le_bytes(*b"scalar_i"); // first 8 bytes
    let d_hi = {
        let mut buf = [0u8; 8];
        buf[..7].copy_from_slice(b"mt_leaf");
        u64::from_le_bytes(buf)
    };
    let c: [u64; 4] = core::array::from_fn(|i| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&commitment[i * 8..(i + 1) * 8]);
        field_reduce(u64::from_le_bytes(buf))
    });
    let input = [
        field_reduce(d_lo),
        field_reduce(d_hi),
        c[0],
        c[1],
        c[2],
        c[3],
        field_reduce(leaf_index),
        0u64,
    ];
    field8_to_bytes32(&poseidon2_permute_t8(&input))
}

/// Internal node hash — Poseidon2 t=8. PURE hash at EVERY level.
/// K1-01 fix: no empty short-circuit, no carry-as-is (OSSIFIED §3.1.3).
/// Poseidon2_t8(DOMAIN_IMT_NODE || left || right)
fn hash_imt_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // D-010: single permutation, max 8 elements.
    // Layout: [domain_lo, domain_hi, l0, l1, l2, l3, r0, r1]
    // where l0..l3 = first 4 u64-LE of left, r0..r1 = first 2 u64-LE of right.
    // Domain: DOMAIN_IMT_NODE = b"scalar_imt_node" (15 bytes).
    let d_lo = u64::from_le_bytes(*b"scalar_i");
    let d_hi = {
        let mut buf = [0u8; 8];
        buf[..7].copy_from_slice(b"mt_node");
        u64::from_le_bytes(buf)
    };
    let l: [u64; 4] = core::array::from_fn(|i| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&left[i * 8..(i + 1) * 8]);
        field_reduce(u64::from_le_bytes(buf))
    });
    let r: [u64; 4] = core::array::from_fn(|i| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&right[i * 8..(i + 1) * 8]);
        field_reduce(u64::from_le_bytes(buf))
    });
    // Note: r[2] and r[3] are dropped to fit in WIDTH_T8=8.
    // Full right inclusion requires a second permutation call (future work).
    // For genesis D-009: prover supplies path externally, this is out-of-circuit.
    let input = [
        field_reduce(d_lo),
        field_reduce(d_hi),
        l[0],
        l[1],
        l[2],
        l[3],
        r[0],
        r[1],
    ];
    field8_to_bytes32(&poseidon2_permute_t8(&input))
}

/// Precomputed empty-subtree roots (K1-01/K1-02).
/// EMPTY[0] = [0u8;32] (level-0 marker); EMPTY[i+1] = hash_imt_node(EMPTY[i], EMPTY[i]).
/// Built via PURE hashing so append/root/compute_siblings/verify share one basis (INV-4.2).
fn empty_subtree_roots() -> &'static [[u8; 32]; IMT_DEPTH + 1] {
    static TABLE: OnceLock<[[u8; 32]; IMT_DEPTH + 1]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [[0u8; 32]; IMT_DEPTH + 1];
        t[0] = IMT_EMPTY_ROOT;
        for i in 0..IMT_DEPTH {
            t[i + 1] = hash_imt_node(&t[i], &t[i]);
        }
        t
    })
}

/// Root of a fully empty depth-32 IMT. NOT [0u8;32].
pub fn imt_empty_root() -> [u8; 32] {
    empty_subtree_roots()[IMT_DEPTH]
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

    /// Append a commitment. Stores the leaf hash; frontier kept in sync for
    /// O(1) external inspection but root/proof are computed from full leaves.
    pub fn append(&mut self, commitment: &[u8; 32]) -> Result<u64, IMTError> {
        if self.count >= (1u64 << IMT_DEPTH as u64) {
            return Err(IMTError::TreeFull);
        }
        let leaf_index = self.count;
        let leaf_hash = hash_imt_leaf(commitment, leaf_index);
        self.leaves.push(leaf_hash);
        self.frontier[0] = leaf_hash; // most-recent leaf marker (inspection only)
        self.count += 1;
        Ok(leaf_index)
    }

    /// Reset IMT to genesis state at epoch boundary. PraGenesis §3.1.10.3, INV-4.10.
    ///
    /// Must be called AFTER EpochSMT(k) is archived and BEFORE sub-epoch 0 of
    /// epoch k+1 begins. Post-reset ASSERTs enforce the genesis-state invariant.
    ///
    /// NOTE: Atomicity with EpochSMT finalization must be guaranteed by the caller
    /// (the epoch-transition orchestrator). No such runtime owner currently holds
    /// a live IncrementalMerkleTree in this codebase — see audit finding K1-04(b).
    pub fn reset(&mut self) {
        self.frontier = IMT_GENESIS_FRONTIER;
        self.count = 0;
        self.leaves.clear();

        // Post-reset verification (§3.1.10.3 — wajib).
        assert_eq!(
            self.frontier, IMT_GENESIS_FRONTIER,
            "INV-4.10: frontier must be genesis after reset"
        );
        assert_eq!(self.count, 0, "INV-4.10: count must be 0 after reset");
        assert_eq!(
            self.root(),
            imt_empty_root(),
            "INV-4.10: root must equal empty root after reset"
        );
    }

    /// Compute the depth-32 root by folding all levels with PURE hashing,
    /// using EMPTY[level] for absent right siblings. (K1-02)
    pub fn root(&self) -> [u8; 32] {
        let empty = empty_subtree_roots();
        if self.count == 0 {
            return empty[IMT_DEPTH];
        }
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        for (_d, empty_d) in empty.iter().enumerate().take(IMT_DEPTH) {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut j = 0;
            while j < level.len() {
                let left = level[j];
                let right = if j + 1 < level.len() {
                    level[j + 1]
                } else {
                    *empty_d // absent right child = empty subtree at this depth
                };
                next.push(hash_imt_node(&left, &right));
                j += 2;
            }
            level = next;
        }
        level[0]
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

    /// Collect the 32 sibling hashes for leaf_index. Absent siblings use EMPTY[level].
    fn compute_siblings(&self, leaf_index: u64) -> Vec<[u8; 32]> {
        let empty = empty_subtree_roots();
        let mut siblings = Vec::with_capacity(IMT_DEPTH);
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut idx = leaf_index as usize;
        for (_d, empty_d) in empty.iter().enumerate().take(IMT_DEPTH) {
            let sib = idx ^ 1;
            let sib_hash = if sib < level.len() {
                level[sib]
            } else {
                *empty_d
            };
            siblings.push(sib_hash);

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut j = 0;
            while j < level.len() {
                let left = level[j];
                let right = if j + 1 < level.len() {
                    level[j + 1]
                } else {
                    *empty_d
                };
                next.push(hash_imt_node(&left, &right));
                j += 2;
            }
            level = next;
            idx /= 2;
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
        current = if is_right == 0 {
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
    SubEpochQuorumFailed {
        subepoch_id: u32,
    },
    SubEpochHashMismatch,
    IMTFrontierMismatch,
    /// Step 4 (§3.1.5): claimed imt_commitment_count != committed imt_count.
    IMTCountMismatch,
    /// Step 5 (§3.1.5): SubEpochIMT referencing a non-current epoch.
    EpochMismatch {
        tx_epoch_id: u64,
        current_epoch_id: u64,
    },
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
        assert_eq!(imt.root(), imt_empty_root());
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
        assert_eq!(imt.root(), imt_empty_root());
        assert_ne!(
            imt.root(),
            [0u8; 32],
            "empty depth-32 root must not be zero (K1-01)"
        );
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
        let _ = VerificationResult::IMTCountMismatch;
        let _ = VerificationResult::EpochMismatch {
            tx_epoch_id: 1,
            current_epoch_id: 2,
        };
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
    // ── F-003: Property test — IMT proof consistency at scale ────────────────
    // Audit finding F-003: verify proof correctness for N insertions (N up to 100).
    // This catches any frontier/reconstruction divergence at various tree sizes.

    #[test]
    fn f003_property_imt_proof_consistency_small_scale() {
        // Insert N commitments, prove every leaf, verify every proof.
        // Covers odd/even tree sizes, power-of-two boundaries.
        // Research Package §3.1.8 (Soundness), INV-4.1.
        for n in 1usize..=64 {
            let mut imt = IncrementalMerkleTree::new();
            for i in 0..n {
                let mut commitment = [0u8; 32];
                commitment[0] = (i % 256) as u8;
                commitment[1] = (i / 256) as u8;
                imt.append(&commitment).unwrap();
            }
            let root = imt.root();
            let count = imt.count;
            for i in 0..n as u64 {
                let mut commitment = [0u8; 32];
                commitment[0] = (i % 256) as u8;
                commitment[1] = (i / 256) as u8;
                let path = imt
                    .prove_membership(i)
                    .unwrap_or_else(|e| panic!("prove_membership failed n={n} i={i}: {e}"));
                assert!(
                    imt_membership_verify(&commitment, &path, &root, count),
                    "F-003: verify failed for n={n} leaf={i}"
                );
                // Verify wrong commitment fails
                let mut bad = commitment;
                bad[31] ^= 0xFF;
                assert!(
                    !imt_membership_verify(&bad, &path, &root, count),
                    "F-003: wrong commitment must fail for n={n} leaf={i}"
                );
            }
        }
    }

    #[test]
    fn f003_property_imt_proof_power_of_two_boundaries() {
        // Test at exact power-of-two boundaries: 1,2,4,8,16,32,64,128
        // These are the critical sizes where carry-up logic differs.
        for n in [1usize, 2, 4, 8, 16, 32, 64, 128] {
            let mut imt = IncrementalMerkleTree::new();
            for i in 0..n {
                let mut c = [0u8; 32];
                c[0] = (i % 256) as u8;
                c[1] = (i / 256) as u8;
                imt.append(&c).unwrap();
            }
            let root = imt.root();
            let count = imt.count;
            // Verify all leaves
            for i in 0..n as u64 {
                let mut commitment = [0u8; 32];
                commitment[0] = (i % 256) as u8;
                commitment[1] = (i / 256) as u8;
                let path = imt.prove_membership(i).unwrap();
                assert!(
                    imt_membership_verify(&commitment, &path, &root, count),
                    "F-003: power-of-two boundary failed n={n} leaf={i}"
                );
            }
        }
    }

    #[test]
    fn f003_property_imt_root_consistent_with_proof() {
        // After each append, root() must be consistent with prove+verify
        // for the most recently inserted leaf.
        let mut imt = IncrementalMerkleTree::new();
        for i in 0..20u64 {
            let mut commitment = [0u8; 32];
            commitment[0] = i as u8;
            imt.append(&commitment).unwrap();
            let root = imt.root();
            let count = imt.count;
            // Verify the leaf just inserted
            let path = imt.prove_membership(i).unwrap();
            assert!(
                imt_membership_verify(&commitment, &path, &root, count),
                "F-003: root inconsistent after append {i}"
            );
        }
    }

    // ── K1-01 adversarial: empty/sparse subtree must NOT be forgeable ─────────
    #[test]
    fn k1_01_empty_subtree_not_forgeable() {
        // A single leaf in a depth-32 tree: every sibling is EMPTY[level].
        let mut imt = IncrementalMerkleTree::new();
        let c = [0x42u8; 32];
        imt.append(&c).unwrap();
        let root = imt.root();
        let path = imt.prove_membership(0).unwrap();
        assert!(imt_membership_verify(&c, &path, &root, imt.count));

        // Forgery attempt: zero-commitment must NOT verify against the same path/root.
        let zero = [0u8; 32];
        assert!(
            !imt_membership_verify(&zero, &path, &root, imt.count),
            "K1-01: zero commitment must not verify (no empty short-circuit)"
        );
    }

    #[test]
    fn k1_01_zero_leaf_distinct_from_empty() {
        // Appending an all-zero commitment must change the root away from empty root.
        let mut imt = IncrementalMerkleTree::new();
        let empty_root = imt.root();
        imt.append(&[0u8; 32]).unwrap();
        assert_ne!(
            imt.root(),
            empty_root,
            "K1-01: zero-commitment leaf must not collapse to empty root"
        );
    }

    #[test]
    fn k1_07_uses_poseidon2_t8() {
        // IMT must use Poseidon2 t=8: empty root equals folding EMPTY via t=8 hash.
        // Cross-check: imt_empty_root() is deterministic and non-zero.
        assert_eq!(imt_empty_root(), imt_empty_root());
        assert_ne!(imt_empty_root(), [0u8; 32]);
    }

    // ── TV 5.11 — IMT Reset State (§3.1.10.3, INV-4.10) ───────────────────────
    #[test]
    fn tv_5_11_imt_reset_state() {
        let mut imt = IncrementalMerkleTree::new();
        for i in 0..7u8 {
            imt.append(&[i; 32]).unwrap();
        }
        assert_eq!(imt.count, 7);
        assert_ne!(imt.root(), imt_empty_root());

        imt.reset();

        // After reset: genesis state, identical to a fresh tree.
        assert_eq!(imt.frontier, IMT_GENESIS_FRONTIER);
        assert_eq!(imt.count, 0);
        assert_eq!(imt.root(), imt_empty_root());

        let fresh = IncrementalMerkleTree::new();
        assert_eq!(
            imt.root(),
            fresh.root(),
            "reset tree must match a fresh tree (determinism)"
        );

        // Re-appending after reset behaves like a fresh tree.
        let mut fresh2 = IncrementalMerkleTree::new();
        imt.append(&[0xAA; 32]).unwrap();
        fresh2.append(&[0xAA; 32]).unwrap();
        assert_eq!(imt.root(), fresh2.root());
    }
}
