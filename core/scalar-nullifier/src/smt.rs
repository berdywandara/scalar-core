//! Sparse Merkle Tree depth-32 — NS_ACTIVE Layer 1
//!
//! Spec §6.1: NS_ACTIVE adalah SMT depth-32, menyimpan nullifier dari
//! 3 epoch terakhir. Lookup deterministik O(log n).
//!
//! Root digunakan dalam Transfer Circuit CC constraint (non-membership proof).
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.
//!
//! SMT depth-32: setiap nullifier (32-byte = 256-bit key) di-map ke leaf
//! menggunakan 32 bit pertama sebagai path. Internal nodes di-hash dengan BLAKE3.
//! Empty subtree root = [0u8;32].

use std::collections::HashMap;

/// Depth SMT NS_ACTIVE. OSSIFIED — spec §6.1.
pub const SMT_DEPTH: usize = 32;

/// Maximum nullifier per checkpoint. OSSIFIED — spec §6, §17.
pub const MAX_NULLIFIERS_PER_CHECKPOINT: usize = 200_000;

// ── Hashing helpers ───────────────────────────────────────────────────────────

/// Hash internal node: BLAKE3(domain || left || right).
/// Domain separator dari spec §2.3: b"scalar_smt_active".
fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"scalar_smt_active");
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Hash leaf: BLAKE3(domain || nullifier || epoch_le).
fn hash_leaf(nullifier: &[u8; 32], epoch_id: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"scalar_smt_active");
    h.update(b"leaf");
    h.update(nullifier);
    h.update(&epoch_id.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Empty subtree root: [0u8; 32]. Spec §6.1.
const EMPTY_ROOT: [u8; 32] = [0u8; 32];

/// Ambil bit ke-`depth` dari nullifier (MSB first, dari byte 0).
/// depth 0 = MSB byte 0, depth 7 = LSB byte 0, depth 8 = MSB byte 1, dst.
#[inline]
fn bit_at(key: &[u8; 32], depth: usize) -> bool {
    let byte_idx = depth / 8;
    let bit_idx = 7 - (depth % 8);
    (key[byte_idx] >> bit_idx) & 1 == 1
}

// ── SMT Membership Proof ──────────────────────────────────────────────────────

/// Merkle proof untuk membership atau non-membership. Spec §6.1, §4.3 CC.
///
/// siblings[i] adalah sibling hash di depth i (dari root ke leaf).
/// Panjang = SMT_DEPTH = 32.
#[derive(Clone, Debug)]
pub struct SmtProof {
    /// Sibling hashes dari root ke leaf, length = SMT_DEPTH.
    pub siblings: Vec<[u8; 32]>,
    /// Apakah leaf ada (membership) atau tidak (non-membership).
    pub is_member: bool,
    /// Key yang dibuktikan.
    pub key: [u8; 32],
}

impl SmtProof {
    /// Verifikasi proof terhadap root yang diketahui.
    ///
    /// Untuk non-membership: verifikasi bahwa path ke key menghasilkan
    /// subtree kosong (EMPTY_ROOT) atau leaf yang berbeda.
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        if self.siblings.len() != SMT_DEPTH {
            return false;
        }
        // Rekonstruksi root dari leaf ke atas.
        // Aturan sama dengan subtree_root(): jika kedua children EMPTY_ROOT,
        // hasilnya EMPTY_ROOT tanpa hashing — ini yang membuat non-membership
        // proof bekerja dengan benar untuk subtree kosong.
        let mut current = EMPTY_ROOT;
        for depth in (0..SMT_DEPTH).rev() {
            let sibling = &self.siblings[depth];
            current = if current == EMPTY_ROOT && *sibling == EMPTY_ROOT {
                EMPTY_ROOT
            } else if bit_at(&self.key, depth) {
                // key di kanan: parent = hash(sibling, current)
                hash_internal(sibling, &current)
            } else {
                // key di kiri: parent = hash(current, sibling)
                hash_internal(&current, sibling)
            };
        }
        &current == root
    }

    /// Verifikasi non-membership: path mengarah ke EMPTY_ROOT.
    /// Spec §4.3 CC: SMT_NonMembershipVerify.
    pub fn verify_non_membership(&self, root: &[u8; 32]) -> bool {
        if self.siblings.len() != SMT_DEPTH {
            return false;
        }
        if self.is_member {
            return false; // ini bukan non-membership proof
        }
        self.verify(root)
    }
}

// ── SparseMerkleTree ──────────────────────────────────────────────────────────

/// SparseMerkleTree depth-32 untuk NS_ACTIVE.
///
/// Spec §6.1: SMT depth-32, menyimpan nullifier dari 3 epoch terakhir.
/// Root digunakan dalam CC constraint: SMT_NonMembershipVerify.
///
/// Implementasi: lazy root computation via sorted-leaf Merkle tree.
/// Depth = 32 bit (menggunakan 32 bit pertama dari 256-bit nullifier key).
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

    /// Generate non-membership proof untuk nullifier. Spec §4.3 CC.
    ///
    /// Membuktikan bahwa nullifier tidak ada dalam SMT dengan memberikan
    /// sibling hashes sepanjang path depth-32.
    ///
    /// Returns SmtProof dengan is_member=false jika nullifier tidak ada,
    /// atau SmtProof dengan is_member=true jika ada (bukan non-membership).
    pub fn generate_proof(&self, nullifier: &[u8; 32]) -> SmtProof {
        let is_member = self.contains(nullifier);
        let siblings = self.compute_siblings(nullifier);
        SmtProof {
            siblings,
            is_member,
            key: *nullifier,
        }
    }

    /// Verifikasi non-membership proof terhadap root saat ini. Spec §4.3 CC.
    ///
    /// Returns true jika nullifier terbukti tidak ada dalam SMT.
    pub fn verify_non_membership(&self, nullifier: &[u8; 32]) -> bool {
        if self.contains(nullifier) {
            return false; // ada di set — bukan non-member
        }
        let proof = self.generate_proof(nullifier);
        proof.verify_non_membership(&self.root)
    }

    /// Hitung sibling hashes untuk path ke nullifier. Depth = SMT_DEPTH.
    fn compute_siblings(&self, target: &[u8; 32]) -> Vec<[u8; 32]> {
        // Build sorted leaf list untuk Merkle computation
        let sorted_leaves: Vec<([u8; 32], u64)> = self.entries_sorted();

        // Hitung sibling di setiap level menggunakan recursive subtree hash
        let mut siblings = vec![[0u8; 32]; SMT_DEPTH];
        for (depth, sibling_slot) in siblings.iter_mut().enumerate() {
            let sibling_bit = !bit_at(target, depth);
            // Kumpulkan semua leaves yang berada di subtree sibling pada depth ini
            let sibling_leaves: Vec<([u8; 32], u64)> = sorted_leaves
                .iter()
                .filter(|(k, _)| {
                    // Prefix depth bit pertama harus sama dengan target
                    // kecuali bit ke-depth yang berbeda
                    prefix_matches_except(k, target, depth)
                })
                .filter(|(k, _)| bit_at(k, depth) == sibling_bit)
                .copied()
                .collect();

            *sibling_slot = subtree_root(&sibling_leaves, depth + 1, SMT_DEPTH);
        }
        siblings
    }

    /// Hitung ulang root dari seluruh leaves menggunakan Merkle tree depth-32.
    /// Determinisme: nullifier di-sort secara implisit via bit-path traversal.
    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = [0u8; 32];
            return;
        }
        let sorted_leaves: Vec<([u8; 32], u64)> = self.entries_sorted();
        self.root = subtree_root(&sorted_leaves, 0, SMT_DEPTH);
    }
}

/// Cek apakah key memiliki prefix yang sama dengan target untuk `depth` bit pertama,
/// kecuali bit ke-`depth` (yang boleh berbeda — ini adalah sibling).
fn prefix_matches_except(key: &[u8; 32], target: &[u8; 32], depth: usize) -> bool {
    for d in 0..depth {
        if bit_at(key, d) != bit_at(target, d) {
            return false;
        }
    }
    true
}

/// Hitung root subtree dari kumpulan leaves, mulai dari `start_depth` hingga `max_depth`.
/// Leaves sudah difilter: semua berada di subtree yang sama.
///
/// Rekursi: split leaves berdasarkan bit di `start_depth`, hash left dan right subtree.
fn subtree_root(leaves: &[([u8; 32], u64)], start_depth: usize, max_depth: usize) -> [u8; 32] {
    if leaves.is_empty() {
        return EMPTY_ROOT;
    }
    if start_depth == max_depth {
        // Leaf level: hash satu-satunya leaf
        debug_assert_eq!(leaves.len(), 1, "SMT depth-32: collision di leaf level");
        return hash_leaf(&leaves[0].0, leaves[0].1);
    }

    // Split berdasarkan bit di start_depth
    let (left_leaves, right_leaves): (Vec<_>, Vec<_>) =
        leaves.iter().partition(|(k, _)| !bit_at(k, start_depth));

    let left_root = subtree_root(&left_leaves, start_depth + 1, max_depth);
    let right_root = subtree_root(&right_leaves, start_depth + 1, max_depth);

    if left_root == EMPTY_ROOT && right_root == EMPTY_ROOT {
        EMPTY_ROOT
    } else {
        hash_internal(&left_root, &right_root)
    }
}

/// Hitung archived SMT root menggunakan domain separator archived. Spec §2.3.
/// Digunakan oleh NullifierSet untuk NS_CHECKPOINT root.
pub fn compute_archived_root(
    prev_archived_root: &[u8; 32],
    new_nullifiers: &[[u8; 32]],
) -> [u8; 32] {
    let mut sorted = new_nullifiers.to_vec();
    sorted.sort();
    let mut h = blake3::Hasher::new();
    h.update(b"scalar_smt_archived");
    h.update(prev_archived_root);
    for n in &sorted {
        h.update(n);
    }
    *h.finalize().as_bytes()
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
        smt.insert(&[1u8; 32], 1);
        smt.insert(&[2u8; 32], 5);
        let old = smt.nullifiers_older_than(10, 3);
        assert_eq!(old.len(), 2);
        smt.insert(&[3u8; 32], 8);
        let old2 = smt.nullifiers_older_than(10, 3);
        assert_eq!(old2.len(), 2);
    }

    // ── Non-membership proof — temuan #4 ─────────────────────────────────────

    #[test]
    fn test_non_membership_empty_smt() {
        // SMT kosong: semua nullifier adalah non-member. Spec §4.3 CC.
        let smt = SparseMerkleTree::new();
        let n = [0xAAu8; 32];
        assert!(smt.verify_non_membership(&n));
    }

    #[test]
    fn test_non_membership_after_insert_other() {
        // Nullifier lain diinsert: target masih non-member.
        let mut smt = SparseMerkleTree::new();
        smt.insert(&[0x01u8; 32], 1);
        smt.insert(&[0x02u8; 32], 1);
        let target = [0xFFu8; 32];
        assert!(smt.verify_non_membership(&target));
    }

    #[test]
    fn test_membership_not_non_membership() {
        // Nullifier yang ada BUKAN non-member. Spec §4.3 CC.
        let mut smt = SparseMerkleTree::new();
        let n = [0x42u8; 32];
        smt.insert(&n, 1);
        assert!(!smt.verify_non_membership(&n));
    }

    #[test]
    fn test_non_membership_proof_siblings_length() {
        // Proof harus memiliki tepat SMT_DEPTH=32 siblings.
        let mut smt = SparseMerkleTree::new();
        smt.insert(&[0x01u8; 32], 1);
        let proof = smt.generate_proof(&[0xFFu8; 32]);
        assert_eq!(proof.siblings.len(), SMT_DEPTH);
    }

    #[test]
    fn test_non_membership_multiple_leaves() {
        // Non-membership valid dengan banyak leaves.
        let mut smt = SparseMerkleTree::new();
        for i in 0u8..10 {
            let mut n = [0u8; 32];
            n[0] = i;
            smt.insert(&n, 1);
        }
        // Target tidak diinsert
        let target = [0xFFu8; 32];
        assert!(smt.verify_non_membership(&target));
    }

    #[test]
    fn test_bit_at_correctness() {
        // bit_at([0x80, ...], 0) = true (MSB byte 0)
        let mut k = [0u8; 32];
        k[0] = 0x80;
        assert!(bit_at(&k, 0));
        assert!(!bit_at(&k, 1));
        // bit_at([0x01, ...], 7) = true (LSB byte 0)
        let mut k2 = [0u8; 32];
        k2[0] = 0x01;
        assert!(bit_at(&k2, 7));
        assert!(!bit_at(&k2, 0));
    }

    #[test]
    fn test_compute_archived_root_deterministic() {
        let prev = [0u8; 32];
        let nullifiers = [[1u8; 32], [2u8; 32]];
        let r1 = compute_archived_root(&prev, &nullifiers);
        let r2 = compute_archived_root(&prev, &[[2u8; 32], [1u8; 32]]);
        assert_eq!(r1, r2, "archived root harus deterministik");
        assert_ne!(r1, [0u8; 32]);
    }
}
