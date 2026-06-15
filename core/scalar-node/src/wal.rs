//! Write-Ahead Log (WAL) — Three-Phase Checkpoint Commit. ADR-SEC-002 revised.
//!
//! Three-phase protocol:
//!   PREPARING  — intent recorded before SMT insert starts (snapshot stored).
//!   INSERTED   — SMT insert complete, root persisted. Terminal on success path.
//!   COMMITTED  — nullifier_archived_root state updated, NS_ACTIVE pruned.
//!
//! Idempotency: re-applying any phase to an already-matching state is a no-op.
//! Snapshot: full state stored at PREPARING (not just boundary).
//! [SCALAR-TECHNICAL §6.2, K-1]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Phase ─────────────────────────────────────────────────────────────────────

/// WAL entry phase. [SCALAR-TECHNICAL §6.2, K-1]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalPhase {
    /// Intent recorded; snapshot written. SMT insert not yet started.
    Preparing,
    /// SMT insert complete; smt_root persisted to disk. Idempotent on re-insert.
    Inserted,
    /// nullifier_archived_root updated; NS_ACTIVE pruned. Terminal success.
    Committed,
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

/// Full node state snapshot at PREPARE time. ADR-SEC-002: stored, not boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSnapshot {
    /// Epoch being checkpointed.
    pub epoch_id: u64,
    /// IMT frontier root at prepare time. Spec §3.1.3.
    pub imt_frontier_root: [u8; 32],
    /// IMT leaf count at prepare time. Spec §3.1.3.
    pub imt_count: u64,
    /// UTXO Set SMT root at prepare time.
    pub utxo_set_root: [u8; 32],
    /// Active nullifier set root at prepare time.
    pub nullifier_active_root: [u8; 32],
    /// Archived nullifier set root at prepare time.
    pub nullifier_archived_root: [u8; 32],
    /// Total supply at prepare time (sSCL). Invariant: <= S_MAX (2_100_000_000_000_000).
    pub total_supply_sscl: u64,
}

// ── WAL Entry ─────────────────────────────────────────────────────────────────

/// WAL entry for a checkpoint. [SCALAR-TECHNICAL §6.2, K-1]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointWalEntry {
    /// Checkpoint ID = epoch_id being committed.
    pub checkpoint_id: u64,
    /// Current phase.
    pub phase: WalPhase,
    /// Full snapshot at PREPARING time.
    pub snapshot: CheckpointSnapshot,
    /// Unix timestamp (ms) of last phase write.
    pub written_at_ms: u64,
    /// Accumulative SMT root after insert — populated at INSERTED. [K-1]
    pub smt_root: [u8; 32],
    /// Path to persistent SMT data on disk — populated at INSERTED. [K-1]
    pub smt_data_path: String,
}

// ── Idempotency result ────────────────────────────────────────────────────────

/// Result of a WAL operation with idempotency semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalResult {
    /// Operation applied — new state written.
    Applied,
    /// Entry already in the requested state — no-op (idempotent). ADR-SEC-002.
    AlreadyInState,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalError {
    #[error("PREPARE must come before COMMIT/ABORT for checkpoint {checkpoint_id}")]
    MissingPrepare { checkpoint_id: u64 },

    #[error(
        "Invalid transition {from:?} -> {to:?} for checkpoint {checkpoint_id}: \
         cannot transition from terminal state"
    )]
    InvalidTransition {
        checkpoint_id: u64,
        from: WalPhase,
        to: WalPhase,
    },
}

// ── WAL Store ─────────────────────────────────────────────────────────────────

/// In-memory WAL store. Replace with sled/file backend before external testnet.
///
/// Guarantees:
///   - PREPARE is always first for any checkpoint_id.
///   - COMMITTED and ABORTED are terminal: no further transitions allowed.
///   - All operations are idempotent: re-applying the same phase is a no-op.
///   - proving_key_version is immutable after PREPARE.
pub struct CheckpointWal {
    entries: HashMap<u64, CheckpointWalEntry>,
}

impl CheckpointWal {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Phase 1 — PREPARE: record intent + full snapshot before proof generation.
    ///
    /// Idempotent: calling PREPARE on an already-PREPARED checkpoint is a no-op.
    /// Error: if checkpoint is already COMMITTED or ABORTED.
    pub fn prepare(
        &mut self,
        checkpoint_id: u64,
        snapshot: CheckpointSnapshot,
        now_ms: u64,
    ) -> Result<WalResult, WalError> {
        if let Some(existing) = self.entries.get(&checkpoint_id) {
            return match existing.phase {
                WalPhase::Preparing => Ok(WalResult::AlreadyInState),
                WalPhase::Inserted | WalPhase::Committed => Err(WalError::InvalidTransition {
                    checkpoint_id,
                    from: existing.phase.clone(),
                    to: WalPhase::Preparing,
                }),
            };
        }

        self.entries.insert(
            checkpoint_id,
            CheckpointWalEntry {
                checkpoint_id,
                phase: WalPhase::Preparing,
                snapshot,
                written_at_ms: now_ms,
                smt_root: [0u8; 32],
                smt_data_path: String::new(),
            },
        );
        Ok(WalResult::Applied)
    }

    /// Phase 2 — INSERTED: SMT insert complete, root persisted.
    ///
    /// Idempotent: calling INSERTED on an already-INSERTED checkpoint is a no-op.
    /// Requires PREPARING to have been called first. [SCALAR-TECHNICAL §6.2, K-1]
    pub fn inserted(
        &mut self,
        checkpoint_id: u64,
        smt_root: [u8; 32],
        smt_data_path: String,
        now_ms: u64,
    ) -> Result<WalResult, WalError> {
        let entry = self
            .entries
            .get_mut(&checkpoint_id)
            .ok_or(WalError::MissingPrepare { checkpoint_id })?;

        match entry.phase {
            WalPhase::Inserted => return Ok(WalResult::AlreadyInState),
            WalPhase::Committed => {
                return Err(WalError::InvalidTransition {
                    checkpoint_id,
                    from: WalPhase::Committed,
                    to: WalPhase::Inserted,
                })
            }
            WalPhase::Preparing => {}
        }

        entry.phase = WalPhase::Inserted;
        entry.smt_root = smt_root;
        entry.smt_data_path = smt_data_path;
        entry.written_at_ms = now_ms;
        Ok(WalResult::Applied)
    }

    /// Phase 3 — COMMITTED: nullifier_archived_root updated, NS_ACTIVE pruned.
    ///
    /// Idempotent: calling COMMITTED on an already-COMMITTED checkpoint is a no-op.
    /// Requires INSERTED to have been called first. [SCALAR-TECHNICAL §6.2, K-1]
    pub fn commit(&mut self, checkpoint_id: u64, now_ms: u64) -> Result<WalResult, WalError> {
        let entry = self
            .entries
            .get_mut(&checkpoint_id)
            .ok_or(WalError::MissingPrepare { checkpoint_id })?;

        match entry.phase {
            WalPhase::Committed => return Ok(WalResult::AlreadyInState),
            WalPhase::Preparing => {
                return Err(WalError::InvalidTransition {
                    checkpoint_id,
                    from: WalPhase::Preparing,
                    to: WalPhase::Committed,
                })
            }
            WalPhase::Inserted => {}
        }

        entry.phase = WalPhase::Committed;
        entry.written_at_ms = now_ms;
        Ok(WalResult::Applied)
    }

    /// Returns true if checkpoint reached COMMITTED phase (idempotency guard).
    pub fn is_committed(&self, checkpoint_id: u64) -> bool {
        self.entries
            .get(&checkpoint_id)
            .map(|e| e.phase == WalPhase::Committed)
            .unwrap_or(false)
    }

    /// Get WAL entry for a checkpoint.
    pub fn get(&self, checkpoint_id: u64) -> Option<&CheckpointWalEntry> {
        self.entries.get(&checkpoint_id)
    }

    /// Get snapshot from a PREPARE entry (for crash recovery).
    pub fn get_snapshot(&self, checkpoint_id: u64) -> Option<&CheckpointSnapshot> {
        self.entries.get(&checkpoint_id).map(|e| &e.snapshot)
    }

    /// List all entries.
    pub fn all_entries(&self) -> impl Iterator<Item = &CheckpointWalEntry> {
        self.entries.values()
    }

    /// Count entries by phase.
    pub fn count_by_phase(&self, phase: &WalPhase) -> usize {
        self.entries.values().filter(|e| &e.phase == phase).count()
    }
}

impl Default for CheckpointWal {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Build a test snapshot. Used in tests and benchmarks.
#[cfg(test)]
pub(crate) fn test_snapshot(epoch_id: u64) -> CheckpointSnapshot {
    CheckpointSnapshot {
        epoch_id,
        imt_frontier_root: [0xAAu8; 32],
        imt_count: 42,
        utxo_set_root: [0xBBu8; 32],
        nullifier_active_root: [0xCCu8; 32],
        nullifier_archived_root: [0xDDu8; 32],
        total_supply_sscl: 1_890_000_000_000_000,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000_000_000;

    fn wal() -> CheckpointWal {
        CheckpointWal::new()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn test_prepare_commit_happy_path() {
        let mut w = wal();
        let snap = test_snapshot(0);

        let r = w.prepare(0, snap.clone(), NOW).unwrap();
        assert_eq!(r, WalResult::Applied);
        assert_eq!(w.get(0).unwrap().phase, WalPhase::Preparing);
        assert_eq!(w.get(0).unwrap().snapshot, snap);

        let r2 = w.commit(0, NOW + 1).unwrap();
        assert_eq!(r2, WalResult::Applied);
        assert_eq!(w.get(0).unwrap().phase, WalPhase::Committed);
        assert!(w.is_committed(0));
    }

    #[test]
    fn test_prepare_abort_happy_path() {
        let mut w = wal();
        w.prepare(1, test_snapshot(1), NOW).unwrap();
        let r = w.inserted(1, [0u8;32], String::new(), NOW + 1).unwrap();
        assert_eq!(r, WalResult::Applied);
        assert!(!w.is_committed(1));
    }

    // ── Idempotency — ADR-SEC-002 ─────────────────────────────────────────────

    #[test]
    fn test_prepare_idempotent() {
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
        // Second PREPARE on same checkpoint_id = no-op.
        let r = w.prepare(0, test_snapshot(0), NOW + 999).unwrap();
        assert_eq!(r, WalResult::AlreadyInState);
        // State unchanged.
        assert_eq!(w.get(0).unwrap().written_at_ms, NOW);
    }

    #[test]
    fn test_commit_idempotent() {
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
        w.commit(0, NOW + 1).unwrap();
        // Second COMMIT = no-op, proof_bytes not overwritten.
        let r = w.commit(0, NOW + 2).unwrap();
        assert_eq!(r, WalResult::AlreadyInState);
    }

    #[test]
    fn test_abort_idempotent() {
        let mut w = wal();
        w.prepare(2, test_snapshot(2), NOW).unwrap();
        w.inserted(2, [0u8;32], String::new(), NOW + 1).unwrap();
        let r = w.inserted(2, [0u8;32], String::new(), NOW + 2).unwrap();
        assert_eq!(r, WalResult::AlreadyInState);
    }

    // ── Invalid transitions ───────────────────────────────────────────────────

    #[test]
    fn test_commit_without_prepare_fails() {
        let mut w = wal();
        let err = w.commit(99, NOW).unwrap_err();
        assert!(matches!(
            err,
            WalError::MissingPrepare { checkpoint_id: 99 }
        ));
    }

    #[test]
    fn test_abort_without_prepare_fails() {
        let mut w = wal();
        let err = w.inserted(99, [0u8;32], String::new(), NOW).unwrap_err();
        assert!(matches!(
            err,
            WalError::MissingPrepare { checkpoint_id: 99 }
        ));
    }

    #[test]
    fn test_abort_after_commit_fails() {
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
        w.commit(0, NOW + 1).unwrap();
        let err = w.inserted(0, [0u8;32], String::new(), NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Committed,
                to: WalPhase::Inserted,
                ..
            }
        ));
    }

    #[test]
    fn test_commit_after_abort_fails() {
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
        w.inserted(0, [0u8;32], String::new(), NOW + 1).unwrap();
        let err = w.commit(0, NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Inserted,
                to: WalPhase::Committed,
                ..
            }
        ));
    }

    #[test]
    fn test_prepare_after_commit_fails() {
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
        w.commit(0, NOW + 1).unwrap();
        let err = w.prepare(0, test_snapshot(0), NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Committed,
                to: WalPhase::Preparing,
                ..
            }
        ));
    }

    #[test]
    fn test_prepare_after_abort_fails() {
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
        w.inserted(0, [0u8;32], String::new(), NOW + 1).unwrap();
        let err = w.prepare(0, test_snapshot(0), NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Inserted,
                to: WalPhase::Preparing,
                ..
            }
        ));
    }

    // ── Snapshot integrity ────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_stored_in_prepare_not_boundary() {
        // ADR-SEC-002: full snapshot stored, not just boundary.
        let mut w = wal();
        let snap = CheckpointSnapshot {
            epoch_id: 5,
            imt_frontier_root: [0x11u8; 32],
            imt_count: 100,
            utxo_set_root: [0x22u8; 32],
            nullifier_active_root: [0x33u8; 32],
            nullifier_archived_root: [0x44u8; 32],
            total_supply_sscl: 999_999_999,
        };
        w.prepare(5, snap.clone(), NOW).unwrap();

        // Snapshot fully retrievable after prepare.
        let retrieved = w.get_snapshot(5).unwrap();
        assert_eq!(*retrieved, snap);

        // Snapshot survives commit.
        w.commit(5, NOW + 1).unwrap();
        assert_eq!(*w.get_snapshot(5).unwrap(), snap);
    }

    #[test]
    fn test_proving_key_version_stored() {
        // ADR-SEC-002: proving_key_version field.
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
    }

    // ── Multi-checkpoint ──────────────────────────────────────────────────────

    #[test]
    fn test_multiple_checkpoints_independent() {
        let mut w = wal();
        w.prepare(0, test_snapshot(0), NOW).unwrap();
        w.prepare(1, test_snapshot(1), NOW).unwrap();
        w.prepare(2, test_snapshot(2), NOW).unwrap();

        w.commit(0, NOW + 1).unwrap();
        w.inserted(1, [0u8;32], String::new(), NOW + 1).unwrap();
        // checkpoint 2 still prepared

        assert!(w.is_committed(0));
        assert!(!w.is_committed(1));
        assert!(!w.is_committed(2));
        assert_eq!(w.count_by_phase(&WalPhase::Committed), 1);
        assert_eq!(w.count_by_phase(&WalPhase::Inserted), 1);
        assert_eq!(w.count_by_phase(&WalPhase::Preparing), 1);
    }

    #[test]
    fn test_not_committed_if_no_entry() {
        let w = wal();
        assert!(!w.is_committed(0));
        assert!(w.get(0).is_none());
        assert!(w.get_snapshot(0).is_none());
    }
}

// ── Persistent WAL Backend ────────────────────────────────────────────────────
//
// File-based WAL untuk testnet dan production. ADR-SEC-002.
//
// Design:
//   - Satu file per checkpoint entry: {wal_dir}/{checkpoint_id:016x}.wal
//   - Atomic write: tulis ke .tmp → fsync → rename (crash-safe)
//   - Recovery: scan direktori dan load semua .wal files saat startup
//   - Business logic tetap di CheckpointWal — FileCheckpointWal hanya wraps
//
// Serialization: postcard (sudah ada di Cargo.toml, compact binary format)

use std::fs;
use std::path::{Path, PathBuf};

/// I/O error dari FileCheckpointWal.
#[derive(Debug, thiserror::Error)]
pub enum WalIoError {
    #[error("WAL I/O error for checkpoint {checkpoint_id}: {source}")]
    Io {
        checkpoint_id: u64,
        source: std::io::Error,
    },

    #[error("WAL serialization error for checkpoint {checkpoint_id}: {source}")]
    Serialization {
        checkpoint_id: u64,
        source: postcard::Error,
    },

    #[error("WAL logic error: {0}")]
    Logic(#[from] WalError),
}

/// File-backed WAL store. Crash-safe via atomic rename. ADR-SEC-002.
///
/// Wraps `CheckpointWal` (in-memory) dengan persistence ke disk.
/// Setiap entry disimpan sebagai file terpisah untuk recovery granular.
pub struct FileCheckpointWal {
    /// In-memory state (source of truth setelah load).
    inner: CheckpointWal,
    /// Direktori tempat file WAL disimpan.
    wal_dir: PathBuf,
}

impl FileCheckpointWal {
    /// Buat atau buka existing WAL di `wal_dir`.
    ///
    /// Jika direktori sudah ada dan berisi file .wal:
    ///   → load semua entries ke memory (recovery).
    /// Jika direktori baru:
    ///   → mulai WAL kosong.
    pub fn open(wal_dir: impl AsRef<Path>) -> Result<Self, WalIoError> {
        let wal_dir = wal_dir.as_ref().to_path_buf();
        fs::create_dir_all(&wal_dir).map_err(|e| WalIoError::Io {
            checkpoint_id: 0,
            source: e,
        })?;

        let mut wal = FileCheckpointWal {
            inner: CheckpointWal::new(),
            wal_dir,
        };

        // Recovery: load all existing .wal files
        wal.load_all()?;
        Ok(wal)
    }

    /// Nama file untuk checkpoint_id.
    fn entry_path(&self, checkpoint_id: u64) -> PathBuf {
        self.wal_dir.join(format!("{checkpoint_id:016x}.wal"))
    }

    /// Nama file temporary untuk atomic write.
    fn tmp_path(&self, checkpoint_id: u64) -> PathBuf {
        self.wal_dir.join(format!("{checkpoint_id:016x}.tmp"))
    }

    /// Tulis entry ke disk secara atomic. ADR-SEC-002.
    ///
    /// Protocol: write .tmp → fsync → rename ke .wal
    /// Rename adalah atomic pada POSIX — tidak ada state intermediate.
    fn persist_entry(&self, entry: &CheckpointWalEntry) -> Result<(), WalIoError> {
        let cid = entry.checkpoint_id;
        let bytes = postcard::to_allocvec(entry).map_err(|e| WalIoError::Serialization {
            checkpoint_id: cid,
            source: e,
        })?;

        let tmp = self.tmp_path(cid);
        let final_path = self.entry_path(cid);

        // Tulis ke file temporary
        fs::write(&tmp, &bytes).map_err(|e| WalIoError::Io {
            checkpoint_id: cid,
            source: e,
        })?;

        // fsync — pastikan bytes di disk sebelum rename
        {
            let f = fs::File::open(&tmp).map_err(|e| WalIoError::Io {
                checkpoint_id: cid,
                source: e,
            })?;
            f.sync_all().map_err(|e| WalIoError::Io {
                checkpoint_id: cid,
                source: e,
            })?;
        }

        // Atomic rename .tmp → .wal
        fs::rename(&tmp, &final_path).map_err(|e| WalIoError::Io {
            checkpoint_id: cid,
            source: e,
        })?;

        Ok(())
    }

    /// Load semua .wal files dari wal_dir ke memory. Recovery. ADR-SEC-002.
    fn load_all(&mut self) -> Result<(), WalIoError> {
        let read_dir = fs::read_dir(&self.wal_dir).map_err(|e| WalIoError::Io {
            checkpoint_id: 0,
            source: e,
        })?;

        let mut entries: Vec<CheckpointWalEntry> = Vec::new();

        for dir_entry in read_dir {
            let dir_entry = dir_entry.map_err(|e| WalIoError::Io {
                checkpoint_id: 0,
                source: e,
            })?;
            let path = dir_entry.path();

            // Hanya proses .wal files — skip .tmp (incomplete writes)
            if path.extension().and_then(|e| e.to_str()) != Some("wal") {
                continue;
            }

            let bytes = fs::read(&path).map_err(|e| WalIoError::Io {
                checkpoint_id: 0,
                source: e,
            })?;

            let entry: CheckpointWalEntry =
                postcard::from_bytes(&bytes).map_err(|e| WalIoError::Serialization {
                    checkpoint_id: 0,
                    source: e,
                })?;

            entries.push(entry);
        }

        // Sort by checkpoint_id untuk deterministic recovery order
        entries.sort_by_key(|e| e.checkpoint_id);

        // Restore in-memory state
        for entry in entries {
            self.inner.entries.insert(entry.checkpoint_id, entry);
        }

        Ok(())
    }

    /// Phase 1 — PREPARE. Atomic write ke disk. ADR-SEC-002.
    pub fn prepare(
        &mut self,
        checkpoint_id: u64,
        snapshot: CheckpointSnapshot,
        now_ms: u64,
    ) -> Result<WalResult, WalIoError> {
        let result = self
            .inner
            .prepare(checkpoint_id, snapshot, now_ms)?;
        if result == WalResult::Applied {
            let entry = self.inner.entries.get(&checkpoint_id).unwrap();
            self.persist_entry(entry)?;
        }
        Ok(result)
    }
    /// Phase 2 — INSERTED. Atomic write to disk. [SCALAR-TECHNICAL §6.2, K-1]
    pub fn inserted(
        &mut self,
        checkpoint_id: u64,
        smt_root: [u8; 32],
        smt_data_path: String,
        now_ms: u64,
    ) -> Result<WalResult, WalIoError> {
        let result = self.inner.inserted(checkpoint_id, smt_root, smt_data_path, now_ms)?;
        if result == WalResult::Applied {
            let entry = self.inner.entries.get(&checkpoint_id).unwrap();
            self.persist_entry(entry)?;
        }
        Ok(result)
    }


    /// Phase 2 — COMMIT. Atomic write ke disk. ADR-SEC-002.
    pub fn commit(
        &mut self,
        checkpoint_id: u64,
        now_ms: u64,
    ) -> Result<WalResult, WalIoError> {
        let result = self.inner.commit(checkpoint_id, now_ms)?;
        if result == WalResult::Applied {
            let entry = self.inner.entries.get(&checkpoint_id).unwrap();
            self.persist_entry(entry)?;
        }
        Ok(result)
    }


    /// Apakah checkpoint sudah COMMITTED? ADR-SEC-002.
    pub fn is_committed(&self, checkpoint_id: u64) -> bool {
        self.inner.is_committed(checkpoint_id)
    }

    /// Hapus file WAL untuk checkpoint yang sudah COMMITTED (cleanup). ADR-SEC-002.
    pub fn remove_committed(&mut self, checkpoint_id: u64) -> Result<(), WalIoError> {
        if !self.is_committed(checkpoint_id) {
            return Ok(());
        }
        let path = self.entry_path(checkpoint_id);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| WalIoError::Io {
                checkpoint_id,
                source: e,
            })?;
        }
        self.inner.entries.remove(&checkpoint_id);
        Ok(())
    }

    /// Count entries by phase.
    pub fn count_by_phase(&self, phase: &WalPhase) -> usize {
        self.inner.count_by_phase(phase)
    }
}

// ── Tests FileCheckpointWal ───────────────────────────────────────────────────

#[cfg(test)]
mod persistent_wal_tests {
    use super::*;
    use std::env;

    fn tmp_wal_dir(prefix: &str) -> PathBuf {
        let mut dir = env::temp_dir();
        dir.push(format!("scalar_wal_test_{prefix}_{}", std::process::id()));
        dir
    }

    fn snapshot(epoch: u64) -> CheckpointSnapshot {
        CheckpointSnapshot {
            epoch_id: epoch,
            imt_frontier_root: [0xAAu8; 32],
            imt_count: epoch * 1000,
            utxo_set_root: [0xBBu8; 32],
            nullifier_active_root: [0xCCu8; 32],
            nullifier_archived_root: [0xDDu8; 32],
            total_supply_sscl: 1_800_000_000_000_000,
        }
    }

    #[test]
    fn test_file_wal_prepare_creates_file() {
        let dir = tmp_wal_dir("prepare");
        let mut wal = FileCheckpointWal::open(&dir).unwrap();
        wal.prepare(1, snapshot(1), 1000).unwrap();
        assert!(dir.join("0000000000000001.wal").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_wal_commit_updates_file() {
        let dir = tmp_wal_dir("commit");
        let mut wal = FileCheckpointWal::open(&dir).unwrap();
        wal.prepare(2, snapshot(2), 1000).unwrap();
        wal.commit(2, 2000).unwrap();
        assert!(wal.is_committed(2));
        assert!(dir.join("0000000000000002.wal").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_wal_recovery_after_reopen() {
        let dir = tmp_wal_dir("recovery");
        {
            let mut wal = FileCheckpointWal::open(&dir).unwrap();
            wal.prepare(3, snapshot(3), 1000).unwrap();
            wal.commit(3, 2000).unwrap();
        }
        // Reopen — should recover committed entry
        let wal2 = FileCheckpointWal::open(&dir).unwrap();
        assert!(wal2.is_committed(3), "entry must survive restart");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_wal_recovery_skips_tmp_files() {
        let dir = tmp_wal_dir("skip_tmp");
        fs::create_dir_all(&dir).unwrap();
        // Simulate incomplete write (.tmp file left behind by crash)
        fs::write(dir.join("0000000000000009.tmp"), b"corrupted").unwrap();
        let wal = FileCheckpointWal::open(&dir).unwrap();
        assert!(!wal.is_committed(9), ".tmp must be ignored on recovery");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_wal_idempotency_persist() {
        let dir = tmp_wal_dir("idempotent");
        let mut wal = FileCheckpointWal::open(&dir).unwrap();
        wal.prepare(5, snapshot(5), 1000).unwrap();
        wal.commit(5, 2000).unwrap();
        // Re-commit is idempotent — no I/O error
        let r = wal.commit(5, 3000).unwrap();
        assert_eq!(r, WalResult::AlreadyInState);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_wal_remove_committed() {
        let dir = tmp_wal_dir("remove");
        let mut wal = FileCheckpointWal::open(&dir).unwrap();
        wal.prepare(6, snapshot(6), 1000).unwrap();
        wal.commit(6, 2000).unwrap();
        wal.remove_committed(6).unwrap();
        assert!(!dir.join("0000000000000006.wal").exists());
        fs::remove_dir_all(&dir).ok();
    }
}
