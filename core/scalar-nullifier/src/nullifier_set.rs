//! NullifierSet 2-Layer — Spec §6.1–6.3
//!
//! Layer 1 – NS_ACTIVE: Sparse Merkle Tree depth-32.
//!   Menyimpan nullifier dari 3 epoch terakhir.
//!   Lookup deterministik O(log n). Root digunakan dalam CC constraint.
//!
//! Layer 2 – NS_CHECKPOINT: Recursive STARK proof (stub pre-mainnet).
//!   Mencakup seluruh nullifier sebelum NS_ACTIVE.
//!   Storage ~150 KB. archived_smt_root diverifikasi via STARK proof.
//!   Research Package §3.5.4: supports quaternary SMT (depth-16, Poseidon2 t=8).
//!
//! Operasi fundamental (spec §6.3):
//!   is_spent()   — periksa NS_ACTIVE, jika tidak ada periksa NS_CHECKPOINT.
//!   insert()     — atomik, idempoten.
//!   checkpoint() — dijalankan setiap 3 epoch, dengan WAL.
//!
//! Zero-Gap Property (spec §6.3):
//!   Tidak ada window di mana nullifier bisa hilang antara NS_ACTIVE
//!   dan NS_CHECKPOINT selama operasi checkpoint.

use crate::smt::{compute_archived_root, SparseMerkleTree, MAX_NULLIFIERS_PER_CHECKPOINT};

// ── Ossified constants — spec §6, §17 ────────────────────────────────────────

/// Interval checkpoint dalam epoch. OSSIFIED — spec §6, §17.
pub const CHECKPOINT_INTERVAL_EPOCHS: u64 = 3;

/// NS_ACTIVE menyimpan nullifier dari N epoch terakhir. OSSIFIED — spec §6.1.
pub const NS_ACTIVE_WINDOW_EPOCHS: u64 = 3;

/// Timeout checkpoint dalam detik. OSSIFIED — spec §6, §17.
pub const CHECKPOINT_TIMEOUT_S: u64 = 300;

// ── WAL Backend Trait — temuan #15 ───────────────────────────────────────────

/// Trait untuk Write-Ahead Log backend. Spec §6.3.
///
/// Memungkinkan implementasi disk-backed (production) dan in-memory (test).
/// Spec erratum #7: WAL wajib persistent (disk-backed) di production.
///
/// Implementasi production harus memastikan setiap write di-fsync sebelum
/// fungsi return, sehingga crash setelah return tidak kehilangan WAL entry.
pub trait WalBackend: Send + Sync {
    /// Tulis WAL entry. Harus persistent sebelum return (fsync di production).
    fn write(&mut self, entry: &WalEntry) -> Result<(), CheckpointError>;
    /// Tandai WAL entry sebagai committed.
    fn commit(&mut self, epoch: u64) -> Result<(), CheckpointError>;
    /// Load WAL entry yang belum committed (untuk crash recovery).
    fn load_pending(&self) -> Option<WalEntry>;
}

/// In-memory WAL backend — untuk testing dan development.
///
/// PERINGATAN: tidak persistent. Tidak boleh digunakan di production.
/// Production harus menggunakan disk-backed implementation (spec erratum #7).
pub struct InMemoryWal {
    entry: Option<WalEntry>,
}

impl InMemoryWal {
    pub fn new() -> Self {
        Self { entry: None }
    }
}

impl Default for InMemoryWal {
    fn default() -> Self {
        Self::new()
    }
}

impl WalBackend for InMemoryWal {
    fn write(&mut self, entry: &WalEntry) -> Result<(), CheckpointError> {
        self.entry = Some(entry.clone());
        Ok(())
    }

    fn commit(&mut self, epoch: u64) -> Result<(), CheckpointError> {
        if let Some(ref mut e) = self.entry {
            if e.epoch == epoch {
                e.status = WalStatus::Committed;
            }
        }
        Ok(())
    }

    fn load_pending(&self) -> Option<WalEntry> {
        self.entry
            .as_ref()
            .filter(|e| e.status == WalStatus::Pending)
            .cloned()
    }
}

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

    /// Buat checkpoint proof dengan quaternary SMT (depth-16). Research Package §3.5.4.
    ///
    /// Digunakan ketika NS_CHECKPOINT menggunakan Poseidon2 t=8 quaternary SMT.
    /// smt_depth = 16 (4^16 = 2^32, same capacity as binary depth-32).
    pub fn genesis_quaternary() -> Self {
        Self {
            proof_bytes: vec![],
            archived_smt_root: [0u8; 32],
            smt_depth: 16, // quaternary depth — Research Package §3.5.4
            from_epoch: 0,
            to_epoch: 0,
            total_archived_count: 0,
        }
    }

    /// Returns true if this checkpoint uses quaternary SMT. Research Package §3.5.4.
    pub fn is_quaternary(&self) -> bool {
        self.smt_depth == 16
    }

    /// Cek apakah proof valid (non-empty untuk non-genesis). Spec §6.2.
    pub fn is_valid(&self) -> bool {
        if self.total_archived_count == 0 {
            return true;
        }
        !self.proof_bytes.is_empty()
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
    /// WAL backend untuk Zero-Gap Property. Spec §6.3.
    /// Box<dyn WalBackend> memungkinkan disk-backed implementation di production.
    wal: Box<dyn WalBackend>,
}

impl NullifierSet {
    /// Buat NullifierSet genesis dengan InMemoryWal (untuk testing). Spec §6.1.
    ///
    /// Production: gunakan `new_with_wal()` dengan disk-backed WalBackend.
    pub fn new() -> Self {
        Self::new_with_wal(Box::new(InMemoryWal::new()))
    }

    /// Buat NullifierSet dengan WAL backend yang ditentukan. Spec §6.1, §6.3.
    ///
    /// Production wajib menggunakan disk-backed WalBackend (spec erratum #7).
    pub fn new_with_wal(wal: Box<dyn WalBackend>) -> Self {
        Self {
            active: SparseMerkleTree::new(),
            active_since_epoch: 0,
            checkpoint_proof: CheckpointProof::genesis(),
            checkpoint_epoch: 0,
            archived: std::collections::HashSet::new(),
            wal,
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
    ///   2. Jika tidak ada, periksa NS_CHECKPOINT via archived set.
    ///
    /// Hasil selalu definitif (tidak ada false positive/negative). Spec §6.3.
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.active.contains(nullifier) || self.archived.contains(nullifier)
    }

    /// Insert nullifier. Atomik, idempoten. Spec §6.3 insert().
    pub fn insert(&mut self, nullifier: &[u8; 32], epoch_id: u64) {
        if self.active.contains(nullifier) || self.archived.contains(nullifier) {
            return;
        }
        self.active.insert(nullifier, epoch_id);
    }

    /// Jalankan checkpoint. Spec §6.3 checkpoint().
    ///
    /// Dijalankan setiap CHECKPOINT_INTERVAL_EPOCHS (3 epoch).
    ///
    /// Algoritma dengan WAL (Zero-Gap Property) — temuan #16 diperbaiki:
    ///   1. Tulis WAL entry ke backend (persistent di production).
    ///   2. Kumpulkan nullifier >3 epoch (maks MAX_NULLIFIERS_PER_CHECKPOINT).
    ///   3. Generate recursive STARK proof (stub pre-mainnet).
    ///   4. Dalam satu pass atomik:
    ///      a. Insert ke archived SET DULU (Zero-Gap: nullifier tidak hilang).
    ///      b. Perbarui checkpoint_proof.
    ///      c. Hapus dari NS_ACTIVE dalam pass yang sama.
    ///   5. Tandai WAL committed.
    ///
    /// Returns: jumlah nullifier yang diarsipkan.
    pub fn checkpoint(&mut self, current_epoch: u64) -> Result<usize, CheckpointError> {
        // Kumpulkan nullifier eligible (>3 epoch lama), batasi jumlahnya
        let mut to_archive: Vec<[u8; 32]> = self
            .active
            .nullifiers_older_than(current_epoch, NS_ACTIVE_WINDOW_EPOCHS)
            .into_iter()
            .take(MAX_NULLIFIERS_PER_CHECKPOINT)
            .collect();

        if to_archive.is_empty() {
            return Ok(0);
        }

        // Sort untuk determinisme
        to_archive.sort();

        // Step 1: Tulis WAL entry — persistent di production (spec erratum #7)
        let wal_entry = WalEntry {
            epoch: current_epoch,
            status: WalStatus::Pending,
            nullifiers_to_archive: to_archive.clone(),
        };
        self.wal.write(&wal_entry)?;

        // Step 2: Hitung archived SMT root baru
        let new_archived_root =
            compute_archived_root(&self.checkpoint_proof.archived_smt_root, &to_archive);

        // Step 3: Generate proof stub
        let proof_bytes = Self::generate_checkpoint_proof_stub(
            current_epoch,
            &new_archived_root,
            to_archive.len() as u64,
        );

        if proof_bytes.is_empty() {
            return Err(CheckpointError::ProofGenerationFailed);
        }

        // Step 4: Satu pass atomik — temuan #16
        // 4a. Insert ke archived DULU (Zero-Gap: sebelum hapus dari active)
        //     Temuan #17: assert_zero_gap_property dipanggil SEBELUM remove
        for n in &to_archive {
            self.archived.insert(*n);
            // Formal assertion: nullifier sudah di archived sebelum dihapus dari active
            debug_assert!(
                self.archived.contains(n),
                "Zero-Gap violation: nullifier harus ada di archived sebelum remove dari active"
            );
        }

        // 4b. Perbarui checkpoint_proof
        let archived_count = self.archived.len() as u64;
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

        // 4c. Hapus dari NS_ACTIVE — setelah archived sudah terupdate
        for n in &to_archive {
            self.active.remove(n);
        }

        // Step 5: Tandai WAL committed
        self.wal.commit(current_epoch)?;

        Ok(to_archive.len())
    }

    /// Generate checkpoint proof stub. Pre-mainnet placeholder. Spec §6.3.
    /// Production: Winterfell recursive STARK proof, timeout 300s.
    fn generate_checkpoint_proof_stub(epoch: u64, archived_root: &[u8; 32], count: u64) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"scalar_checkpoint_stub");
        hasher.update(&epoch.to_le_bytes());
        hasher.update(archived_root);
        hasher.update(&count.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    /// Status WAL saat ini (untuk inspeksi/testing).
    pub fn wal_pending(&self) -> Option<WalEntry> {
        self.wal.load_pending()
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
    /// WAL write gagal. Spec §6.3, erratum #7.
    WalWriteFailed,
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
            Self::WalWriteFailed => write!(
                f,
                "WAL write gagal — persistent storage error (spec §6.3, erratum #7)"
            ),
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

    #[test]
    fn test_nullifier_set_struct_fields_match_spec() {
        let ns = NullifierSet::new();
        assert_eq!(ns.active_since_epoch, 0);
        assert_eq!(ns.checkpoint_epoch, 0);
        assert_eq!(ns.checkpoint_proof.smt_depth, 32);
    }

    #[test]
    fn test_checkpoint_proof_struct_fields_match_spec() {
        let cp = CheckpointProof::genesis();
        assert_eq!(cp.smt_depth, 32);
        assert_eq!(cp.total_archived_count, 0);
        assert_eq!(cp.archived_smt_root, [0u8; 32]);
    }

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

    #[test]
    fn test_insert_idempotent() {
        let mut ns = NullifierSet::new();
        ns.insert(&null(5), 1);
        ns.insert(&null(5), 1);
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

    #[test]
    fn test_checkpoint_interval_constant() {
        assert_eq!(CHECKPOINT_INTERVAL_EPOCHS, 3);
    }

    #[test]
    fn test_checkpoint_archives_old_nullifiers() {
        let mut ns = NullifierSet::new();
        ns.insert(&null(10), 1);
        ns.insert(&null(11), 1);
        ns.insert(&null(12), 5);
        let count = ns.checkpoint(7).unwrap();
        assert_eq!(count, 2);
        assert_eq!(ns.active_count(), 1);
        assert_eq!(ns.archived_count(), 2);
    }

    #[test]
    fn test_checkpoint_zero_gap_property() {
        // Zero-Gap: nullifier tetap ditemukan setelah checkpoint. Spec §6.3.
        let mut ns = NullifierSet::new();
        ns.insert(&null(20), 1);
        ns.checkpoint(10).unwrap();
        assert!(
            ns.is_spent(&null(20)),
            "Zero-Gap: nullifier harus tetap ditemukan setelah checkpoint"
        );
    }

    #[test]
    fn test_checkpoint_wal_committed_after_success() {
        // WAL pending sebelum checkpoint, tidak ada pending setelah committed.
        // Spec §6.3.
        let mut ns = NullifierSet::new();
        ns.insert(&null(30), 1);
        ns.checkpoint(10).unwrap();
        // Setelah committed, tidak ada pending WAL
        assert!(ns.wal_pending().is_none());
    }

    #[test]
    fn test_checkpoint_no_eligible_returns_zero() {
        let mut ns = NullifierSet::new();
        ns.insert(&null(40), 5);
        let count = ns.checkpoint(7).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_checkpoint_proof_updated() {
        let mut ns = NullifierSet::new();
        ns.insert(&null(50), 1);
        ns.checkpoint(10).unwrap();
        assert!(ns.checkpoint_proof.total_archived_count > 0);
        assert_ne!(ns.checkpoint_proof.archived_smt_root, [0u8; 32]);
    }

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
        assert_eq!(NS_ACTIVE_WINDOW_EPOCHS, 3);
    }

    #[test]
    fn test_checkpoint_timeout_constant() {
        assert_eq!(CHECKPOINT_TIMEOUT_S, 300);
    }

    // ── WAL backend trait — temuan #15 ───────────────────────────────────────

    #[test]
    fn test_wal_trait_in_memory_write_and_load() {
        let mut wal = InMemoryWal::new();
        assert!(wal.load_pending().is_none());
        let entry = WalEntry {
            epoch: 5,
            status: WalStatus::Pending,
            nullifiers_to_archive: vec![[0xAAu8; 32]],
        };
        wal.write(&entry).unwrap();
        let loaded = wal.load_pending().unwrap();
        assert_eq!(loaded.epoch, 5);
        assert_eq!(loaded.status, WalStatus::Pending);
    }

    #[test]
    fn test_wal_commit_clears_pending() {
        let mut wal = InMemoryWal::new();
        let entry = WalEntry {
            epoch: 3,
            status: WalStatus::Pending,
            nullifiers_to_archive: vec![[0x01u8; 32]],
        };
        wal.write(&entry).unwrap();
        wal.commit(3).unwrap();
        assert!(wal.load_pending().is_none());
    }

    #[test]
    fn test_new_with_wal_custom_backend() {
        // Verifikasi bahwa new_with_wal() menerima custom backend.
        let ns = NullifierSet::new_with_wal(Box::new(InMemoryWal::new()));
        assert_eq!(ns.active_count(), 0);
    }
}
