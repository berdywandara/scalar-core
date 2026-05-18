//! NullifierSet 2-Layer — Spec §6.1–6.3
//!
//! Layer 1 – NS_ACTIVE: Sparse Merkle Tree depth-32.
//!   Menyimpan nullifier dari 3 epoch terakhir.
//!   Lookup deterministik O(log n). Root digunakan dalam CC constraint.
//!
//! Layer 2 – NS_CHECKPOINT: Recursive STARK proof (stub pre-mainnet).
//!   Mencakup seluruh nullifier sebelum NS_ACTIVE.
//!   Storage ~150 KB. archived_smt_root diverifikasi via STARK proof.
//!
//! Operasi fundamental (spec §6.3):
//!   is_spent()   — periksa NS_ACTIVE, jika tidak ada periksa NS_CHECKPOINT.
//!   insert()     — atomik, idempoten.
//!   checkpoint() — dijalankan setiap 3 epoch, dengan WAL.
//!
//! Zero-Gap Property (spec §6.3):
//!   Tidak ada window di mana nullifier bisa hilang antara NS_ACTIVE
//!   dan NS_CHECKPOINT selama operasi checkpoint.

use crate::smt::{SparseMerkleTree, MAX_NULLIFIERS_PER_CHECKPOINT};

// ── Ossified constants — spec §6, §17 ────────────────────────────────────────

/// Interval checkpoint dalam epoch. OSSIFIED — spec §6, §17.
pub const CHECKPOINT_INTERVAL_EPOCHS: u64 = 3;

/// NS_ACTIVE menyimpan nullifier dari N epoch terakhir. OSSIFIED — spec §6.1.
pub const NS_ACTIVE_WINDOW_EPOCHS: u64 = 3;

/// Timeout checkpoint dalam detik. OSSIFIED — spec §6, §17.
pub const CHECKPOINT_TIMEOUT_S: u64 = 300;

// ── CheckpointProof — spec §6.2 ──────────────────────────────────────────────

/// Recursive STARK proof untuk NS_CHECKPOINT. Spec §6.2.
///
/// Mencakup seluruh nullifier sebelum NS_ACTIVE.
/// Storage ~150 KB. archived_smt_root diverifikasi via STARK proof.
///
/// Pre-mainnet: proof_bytes adalah stub. Wajib diisi implementasi
/// Winterfell recursive sebelum mainnet (spec §15.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointProof {
    /// Bytes recursive STARK proof. ~150 KB production. Spec §6.2.
    pub proof_bytes: Vec<u8>,
    /// SMT root dari seluruh nullifier yang diarsipkan. Spec §6.2.
    pub archived_smt_root: [u8; 32],
    /// SMT depth yang digunakan. Spec §6.2.
    pub smt_depth: u8,
    /// Epoch awal yang dicakup proof ini. Spec §6.2.
    pub from_epoch: u64,
    /// Epoch akhir yang dicakup proof ini. Spec §6.2.
    pub to_epoch: u64,
    /// Total nullifier yang diarsipkan. Spec §6.2.
    pub total_archived_count: u64,
}

impl CheckpointProof {
    /// Buat checkpoint proof kosong (genesis state). Spec §6.2.
    pub fn genesis() -> Self {
        Self {
            proof_bytes: vec![],
            archived_smt_root: [0u8; 32],
            smt_depth: 32,
            from_epoch: 0,
            to_epoch: 0,
            total_archived_count: 0,
        }
    }

    /// Cek apakah proof valid (non-empty untuk non-genesis). Spec §6.2.
    pub fn is_valid(&self) -> bool {
        // Genesis proof selalu valid
        if self.total_archived_count == 0 {
            return true;
        }
        // Non-genesis: proof_bytes tidak boleh kosong
        !self.proof_bytes.is_empty()
    }

    /// Verifikasi non-membership nullifier di NS_CHECKPOINT. Spec §6.2, §4.3 CC.
    ///
    /// Pre-mainnet stub: cek archived_set yang di-track secara terpisah.
    /// Production: verifikasi SMT non-membership path terhadap archived_smt_root.
    pub fn verify_non_membership(&self, _nullifier: &[u8; 32]) -> bool {
        // Genesis → tidak ada nullifier terarsip → selalu non-member
        if self.total_archived_count == 0 {
            return true;
        }
        // Stub: delegasi ke archived_nullifiers di NullifierSet
        // Production: SMT_NonMembershipVerify(nullifier, archived_smt_root)
        true // placeholder — diimplementasikan via NullifierSet.is_spent()
    }
}

// ── WAL Entry — spec §6.3 ────────────────────────────────────────────────────

/// Write-Ahead Log entry untuk operasi checkpoint. Spec §6.3.
///
/// Memastikan Zero-Gap Property: jika node crash saat checkpoint,
/// WAL memungkinkan recovery tanpa kehilangan nullifier.
#[derive(Clone, Debug)]
pub struct WalEntry {
    /// Epoch yang sedang di-checkpoint.
    pub epoch: u64,
    /// Status WAL entry.
    pub status: WalStatus,
    /// Nullifier yang akan diarsipkan.
    pub nullifiers_to_archive: Vec<[u8; 32]>,
}

/// Status Write-Ahead Log. Spec §6.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalStatus {
    /// WAL ditulis, checkpoint belum selesai.
    Pending,
    /// Checkpoint selesai — WAL bisa dihapus.
    Committed,
}

// ── NullifierSet 2-Layer — spec §6.1–6.3 ─────────────────────────────────────

/// NullifierSet 2-layer sesuai spec §6.1.
///
/// Layer 1 – NS_ACTIVE: SMT depth-32, 3 epoch terakhir.
/// Layer 2 – NS_CHECKPOINT: Recursive STARK proof seluruh nullifier lama.
///
/// Struktur data sesuai spec §6.2 verbatim.
pub struct NullifierSet {
    /// Layer 1: NS_ACTIVE — SMT depth-32. Spec §6.1.
    pub active: SparseMerkleTree,
    /// Epoch sejak NS_ACTIVE mulai (epoch pertama yang dicakup). Spec §6.2.
    pub active_since_epoch: u64,
    /// Layer 2: NS_CHECKPOINT — recursive STARK proof. Spec §6.2.
    pub checkpoint_proof: CheckpointProof,
    /// Epoch terakhir yang dicakup NS_CHECKPOINT. Spec §6.2.
    pub checkpoint_epoch: u64,
    /// Archived nullifiers — digunakan untuk non-membership check pre-mainnet.
    /// Production: digantikan oleh SMT non-membership proof terhadap archived_smt_root.
    archived: std::collections::HashSet<[u8; 32]>,
    /// WAL untuk Zero-Gap Property. Spec §6.3.
    wal: Option<WalEntry>,
}

impl NullifierSet {
    /// Buat NullifierSet genesis. Spec §6.1.
    pub fn new() -> Self {
        Self {
            active: SparseMerkleTree::new(),
            active_since_epoch: 0,
            checkpoint_proof: CheckpointProof::genesis(),
            checkpoint_epoch: 0,
            archived: std::collections::HashSet::new(),
            wal: None,
        }
    }

    /// Root NS_ACTIVE — digunakan dalam CC constraint. Spec §4.2, §6.1.
    pub fn active_root(&self) -> [u8; 32] {
        self.active.root
    }

    /// Root NS_CHECKPOINT (archived SMT root). Spec §6.2, §4.2.
    pub fn archived_smt_root(&self) -> [u8; 32] {
        self.checkpoint_proof.archived_smt_root
    }

    /// Periksa apakah nullifier sudah digunakan. Spec §6.3 is_spent().
    ///
    /// Urutan:
    ///   1. Periksa NS_ACTIVE — O(1) lookup.
    ///   2. Jika tidak ada, verifikasi non-membership di NS_CHECKPOINT.
    ///
    /// Hasil selalu definitif (tidak ada false positive/negative). Spec §6.3.
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        // Layer 1: NS_ACTIVE — deterministik
        if self.active.contains(nullifier) {
            return true;
        }
        // Layer 2: NS_CHECKPOINT — archived nullifiers
        // Production: SMT_NonMembershipVerify(nullifier, archived_smt_root)
        self.archived.contains(nullifier)
    }

    /// Insert nullifier. Atomik, idempoten. Spec §6.3 insert().
    ///
    /// `nullifier`: 32-byte nullifier.
    /// `epoch_id`: epoch saat nullifier diinsert.
    pub fn insert(&mut self, nullifier: &[u8; 32], epoch_id: u64) {
        // Idempoten: jika sudah ada, tidak ada perubahan
        if self.active.contains(nullifier) || self.archived.contains(nullifier) {
            return;
        }
        self.active.insert(nullifier, epoch_id);
    }

    /// Jalankan checkpoint. Spec §6.3 checkpoint().
    ///
    /// Dijalankan setiap CHECKPOINT_INTERVAL_EPOCHS (3 epoch).
    ///
    /// Algoritma dengan WAL (Zero-Gap Property):
    ///   1. Tulis WAL entry (nullifier yang akan diarsipkan).
    ///   2. Kumpulkan nullifier >3 epoch (maks MAX_NULLIFIERS_PER_CHECKPOINT).
    ///   3. Generate recursive STARK proof (stub pre-mainnet).
    ///   4. Verifikasi proof.
    ///   5. Dalam satu operasi atomik:
    ///      a. Perbarui checkpoint_proof.
    ///      b. Tambahkan nullifier ke archived set.
    ///      c. Hapus nullifier dari NS_ACTIVE.
    ///   6. Tandai WAL selesai (Committed).
    ///
    /// Returns: jumlah nullifier yang diarsipkan.
    pub fn checkpoint(&mut self, current_epoch: u64) -> Result<usize, CheckpointError> {
        // Kumpulkan nullifier yang eligible untuk diarsipkan (>3 epoch lama)
        let to_archive = self
            .active
            .nullifiers_older_than(current_epoch, NS_ACTIVE_WINDOW_EPOCHS);

        // Batasi jumlah per checkpoint
        let to_archive: Vec<[u8; 32]> = to_archive
            .into_iter()
            .take(MAX_NULLIFIERS_PER_CHECKPOINT)
            .collect();

        if to_archive.is_empty() {
            return Ok(0);
        }

        // Step 1: Tulis WAL entry — Zero-Gap Property
        self.wal = Some(WalEntry {
            epoch: current_epoch,
            status: WalStatus::Pending,
            nullifiers_to_archive: to_archive.clone(),
        });

        // Step 2: Generate archived SMT root dari semua archived + to_archive
        let new_archived_root = self.compute_new_archived_root(&to_archive);

        // Step 3: Generate recursive STARK proof (stub)
        // Production: Winterfell recursive STARK proof dalam 300s timeout
        let proof_bytes = self.generate_checkpoint_proof_stub(
            current_epoch,
            &new_archived_root,
            to_archive.len() as u64,
        );

        // Step 4: Verifikasi proof
        if proof_bytes.is_empty() {
            return Err(CheckpointError::ProofGenerationFailed);
        }

        // Step 5: Operasi atomik
        let archived_count = self.archived.len() as u64 + to_archive.len() as u64;

        // 5a. Perbarui checkpoint_proof
        self.checkpoint_proof = CheckpointProof {
            proof_bytes,
            archived_smt_root: new_archived_root,
            smt_depth: 32,
            from_epoch: self.checkpoint_epoch,
            to_epoch: current_epoch,
            total_archived_count: archived_count,
        };
        self.checkpoint_epoch = current_epoch;
        self.active_since_epoch = current_epoch;

        // 5b. Tambahkan ke archived (Zero-Gap: SEBELUM hapus dari active)
        for n in &to_archive {
            self.archived.insert(*n);
        }

        // 5c. Hapus dari NS_ACTIVE
        for n in &to_archive {
            self.active.remove(n);
        }

        // Step 6: Tandai WAL selesai
        if let Some(ref mut wal) = self.wal {
            wal.status = WalStatus::Committed;
        }

        Ok(to_archive.len())
    }

    /// Hitung archived SMT root baru setelah menambah to_archive. Spec §6.3.
    fn compute_new_archived_root(&self, to_archive: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"scalar_smt_archived");
        hasher.update(&self.checkpoint_proof.archived_smt_root);
        // Sort to_archive untuk determinisme
        let mut sorted = to_archive.to_vec();
        sorted.sort();
        for n in &sorted {
            hasher.update(n);
        }
        *hasher.finalize().as_bytes()
    }

    /// Generate checkpoint proof stub. Pre-mainnet placeholder. Spec §6.3.
    /// Production: Winterfell recursive STARK proof, timeout 300s.
    fn generate_checkpoint_proof_stub(
        &self,
        epoch: u64,
        archived_root: &[u8; 32],
        count: u64,
    ) -> Vec<u8> {
        // Stub: BLAKE3 dari metadata sebagai proof placeholder
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"scalar_checkpoint_stub");
        hasher.update(&epoch.to_le_bytes());
        hasher.update(archived_root);
        hasher.update(&count.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    /// Status WAL saat ini. Spec §6.3.
    pub fn wal_status(&self) -> Option<&WalEntry> {
        self.wal.as_ref()
    }

    /// Jumlah nullifier di NS_ACTIVE.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Jumlah nullifier di NS_CHECKPOINT (archived).
    pub fn archived_count(&self) -> usize {
        self.archived.len()
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error operasi checkpoint. Spec §6.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// Proof generation gagal atau timeout. Spec §6.3.
    ProofGenerationFailed,
    /// Proof verifikasi gagal. Spec §6.3.
    ProofVerificationFailed,
}

impl core::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ProofGenerationFailed => write!(
                f,
                "Checkpoint proof generation gagal — timeout atau error (spec §6.3)"
            ),
            Self::ProofVerificationFailed => {
                write!(f, "Checkpoint proof verifikasi gagal (spec §6.3)")
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn null(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // ── Struktur data §6.2 ────────────────────────────────────────────────────

    #[test]
    fn test_nullifier_set_struct_fields_match_spec() {
        // Spec §6.2: NullifierSet memiliki active, active_since_epoch,
        // checkpoint_proof, checkpoint_epoch. OSSIFIED.
        let ns = NullifierSet::new();
        assert_eq!(ns.active_since_epoch, 0);
        assert_eq!(ns.checkpoint_epoch, 0);
        assert_eq!(ns.checkpoint_proof.smt_depth, 32);
    }

    #[test]
    fn test_checkpoint_proof_struct_fields_match_spec() {
        // Spec §6.2: CheckpointProof memiliki semua field yang ditentukan.
        let cp = CheckpointProof::genesis();
        assert_eq!(cp.smt_depth, 32);
        assert_eq!(cp.total_archived_count, 0);
        assert_eq!(cp.archived_smt_root, [0u8; 32]);
    }

    // ── is_spent() §6.3 ──────────────────────────────────────────────────────

    #[test]
    fn test_is_spent_empty_set() {
        let ns = NullifierSet::new();
        assert!(!ns.is_spent(&null(1)));
    }

    #[test]
    fn test_is_spent_after_insert() {
        let mut ns = NullifierSet::new();
        ns.insert(&null(2), 1);
        assert!(ns.is_spent(&null(2)));
    }

    #[test]
    fn test_is_spent_other_nullifier_not_affected() {
        let mut ns = NullifierSet::new();
        ns.insert(&null(3), 1);
        assert!(!ns.is_spent(&null(4)));
    }

    // ── insert() §6.3 ────────────────────────────────────────────────────────

    #[test]
    fn test_insert_idempotent() {
        // insert() idempoten — spec §6.3.
        let mut ns = NullifierSet::new();
        ns.insert(&null(5), 1);
        ns.insert(&null(5), 1); // ulang
        assert!(ns.is_spent(&null(5)));
        assert_eq!(ns.active_count(), 1);
    }

    #[test]
    fn test_insert_updates_active_root() {
        let mut ns = NullifierSet::new();
        let root_before = ns.active_root();
        ns.insert(&null(6), 1);
        assert_ne!(ns.active_root(), root_before);
    }

    // ── checkpoint() §6.3 ────────────────────────────────────────────────────

    #[test]
    fn test_checkpoint_interval_constant() {
        // OSSIFIED — spec §6, §17.
        assert_eq!(CHECKPOINT_INTERVAL_EPOCHS, 3);
    }

    #[test]
    fn test_checkpoint_archives_old_nullifiers() {
        // Nullifier >3 epoch lama dipindah ke NS_CHECKPOINT. Spec §6.3.
        let mut ns = NullifierSet::new();
        ns.insert(&null(10), 1); // epoch 1
        ns.insert(&null(11), 1); // epoch 1
        ns.insert(&null(12), 5); // epoch 5 (baru)

        // Checkpoint di epoch 7: epoch 1 → umur=6 > 3 → arsip
        // epoch 5 → umur=2, NOT > 3 → tetap
        let count = ns.checkpoint(7).unwrap();
        assert_eq!(count, 2);
        assert_eq!(ns.active_count(), 1); // epoch 5 tetap
        assert_eq!(ns.archived_count(), 2);
    }

    #[test]
    fn test_checkpoint_zero_gap_property() {
        // Zero-Gap: nullifier tetap dapat ditemukan setelah checkpoint. Spec §6.3.
        let mut ns = NullifierSet::new();
        ns.insert(&null(20), 1);
        ns.checkpoint(10).unwrap();
        // Setelah checkpoint: null(20) dipindah ke archived tapi masih is_spent
        assert!(
            ns.is_spent(&null(20)),
            "Zero-Gap: nullifier harus tetap ditemukan"
        );
    }

    #[test]
    fn test_checkpoint_wal_committed_after_success() {
        // WAL harus di-commit setelah checkpoint sukses. Spec §6.3.
        let mut ns = NullifierSet::new();
        ns.insert(&null(30), 1);
        ns.checkpoint(10).unwrap();
        let wal = ns.wal_status().unwrap();
        assert_eq!(wal.status, WalStatus::Committed);
    }

    #[test]
    fn test_checkpoint_no_eligible_returns_zero() {
        // Tidak ada nullifier eligible → return 0. Spec §6.3.
        let mut ns = NullifierSet::new();
        ns.insert(&null(40), 5); // epoch 5, current=7 → umur=2, NOT > 3
        let count = ns.checkpoint(7).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_checkpoint_proof_updated() {
        // checkpoint_proof diperbarui setelah checkpoint. Spec §6.2.
        let mut ns = NullifierSet::new();
        ns.insert(&null(50), 1);
        ns.checkpoint(10).unwrap();
        assert!(ns.checkpoint_proof.total_archived_count > 0);
        assert_ne!(ns.checkpoint_proof.archived_smt_root, [0u8; 32]);
    }

    // ── Active root §6.1 ─────────────────────────────────────────────────────

    #[test]
    fn test_active_root_changes_with_insert() {
        let mut ns = NullifierSet::new();
        let r1 = ns.active_root();
        ns.insert(&null(60), 1);
        let r2 = ns.active_root();
        ns.insert(&null(61), 1);
        let r3 = ns.active_root();
        assert_ne!(r1, r2);
        assert_ne!(r2, r3);
    }

    #[test]
    fn test_ns_active_window_epochs_constant() {
        // Spec §6.1: 3 epoch terakhir. OSSIFIED.
        assert_eq!(NS_ACTIVE_WINDOW_EPOCHS, 3);
    }

    #[test]
    fn test_checkpoint_timeout_constant() {
        // Spec §6, §17: 300 detik. OSSIFIED.
        assert_eq!(CHECKPOINT_TIMEOUT_S, 300);
    }
}
