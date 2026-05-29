//! Write-Ahead Log (WAL) — Three-Phase Checkpoint Commit. ADR-SEC-002 revised.
//!
//! Three-phase protocol:
//!   PREPARE — intent recorded before proof generation starts (snapshot stored).
//!   COMMIT  — success recorded after proof verified. Terminal success.
//!   ABORT   — failure recorded. Terminal failure, allows retry via new PREPARE.
//!
//! Idempotency: re-applying any phase to an already-matching state is a no-op.
//! Snapshot: full state stored at PREPARE (not just boundary). ADR-SEC-002.
//! proving_key_version: tracks which proving key was used. ADR-SEC-002.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Phase ─────────────────────────────────────────────────────────────────────

/// WAL entry phase. ADR-SEC-002 revised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalPhase {
    /// Intent recorded before proof generation. Recoverable.
    Prepared,
    /// Proof generated and verified. Terminal success — idempotent on re-commit.
    Committed,
    /// Proof generation failed. Terminal failure — allows fresh PREPARE retry.
    Aborted,
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

/// WAL entry for a checkpoint. ADR-SEC-002 revised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointWalEntry {
    /// Checkpoint ID = epoch_id being committed.
    pub checkpoint_id: u64,
    /// Current phase.
    pub phase: WalPhase,
    /// Proving key version used. ADR-SEC-002.
    pub proving_key_version: u32,
    /// Full snapshot at PREPARE time. ADR-SEC-002: stored, not boundary.
    pub snapshot: CheckpointSnapshot,
    /// Unix timestamp (ms) of last phase write.
    pub written_at_ms: u64,
    /// Proof bytes — populated at COMMIT, empty at PREPARE/ABORT.
    pub proof_bytes: Vec<u8>,
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
        proving_key_version: u32,
        snapshot: CheckpointSnapshot,
        now_ms: u64,
    ) -> Result<WalResult, WalError> {
        if let Some(existing) = self.entries.get(&checkpoint_id) {
            return match existing.phase {
                // Idempotent: same prepare, same key version — no-op.
                WalPhase::Prepared => Ok(WalResult::AlreadyInState),
                // Terminal states: cannot re-prepare a committed/aborted checkpoint.
                WalPhase::Committed | WalPhase::Aborted => {
                    Err(WalError::InvalidTransition {
                        checkpoint_id,
                        from: existing.phase.clone(),
                        to: WalPhase::Prepared,
                    })
                }
            };
        }

        self.entries.insert(
            checkpoint_id,
            CheckpointWalEntry {
                checkpoint_id,
                phase: WalPhase::Prepared,
                proving_key_version,
                snapshot,
                written_at_ms: now_ms,
                proof_bytes: Vec::new(),
            },
        );
        Ok(WalResult::Applied)
    }

    /// Phase 2 — COMMIT: record success after proof verified.
    ///
    /// Idempotent: calling COMMIT on an already-COMMITTED checkpoint is a no-op.
    /// Requires PREPARE to have been called first.
    /// Error: ABORT → COMMIT transition is invalid.
    pub fn commit(
        &mut self,
        checkpoint_id: u64,
        proof_bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<WalResult, WalError> {
        let entry = self
            .entries
            .get_mut(&checkpoint_id)
            .ok_or(WalError::MissingPrepare { checkpoint_id })?;

        match entry.phase {
            WalPhase::Committed => return Ok(WalResult::AlreadyInState),
            WalPhase::Aborted => {
                return Err(WalError::InvalidTransition {
                    checkpoint_id,
                    from: WalPhase::Aborted,
                    to: WalPhase::Committed,
                })
            }
            WalPhase::Prepared => {}
        }

        entry.phase = WalPhase::Committed;
        entry.proof_bytes = proof_bytes;
        entry.written_at_ms = now_ms;
        Ok(WalResult::Applied)
    }

    /// Phase 3 — ABORT: record failure. Allows fresh PREPARE retry.
    ///
    /// Idempotent: calling ABORT on an already-ABORTED checkpoint is a no-op.
    /// Requires PREPARE to have been called first.
    /// Error: COMMIT → ABORT transition is invalid.
    pub fn abort(
        &mut self,
        checkpoint_id: u64,
        now_ms: u64,
    ) -> Result<WalResult, WalError> {
        let entry = self
            .entries
            .get_mut(&checkpoint_id)
            .ok_or(WalError::MissingPrepare { checkpoint_id })?;

        match entry.phase {
            WalPhase::Aborted => return Ok(WalResult::AlreadyInState),
            WalPhase::Committed => {
                return Err(WalError::InvalidTransition {
                    checkpoint_id,
                    from: WalPhase::Committed,
                    to: WalPhase::Aborted,
                })
            }
            WalPhase::Prepared => {}
        }

        entry.phase = WalPhase::Aborted;
        entry.written_at_ms = now_ms;
        Ok(WalResult::Applied)
    }

    /// Check if checkpoint is already committed (idempotency guard for callers).
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
    const PKV: u32 = 1; // proving_key_version

    fn wal() -> CheckpointWal {
        CheckpointWal::new()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn test_prepare_commit_happy_path() {
        let mut w = wal();
        let snap = test_snapshot(0);

        let r = w.prepare(0, PKV, snap.clone(), NOW).unwrap();
        assert_eq!(r, WalResult::Applied);
        assert_eq!(w.get(0).unwrap().phase, WalPhase::Prepared);
        assert_eq!(w.get(0).unwrap().proving_key_version, PKV);
        assert_eq!(w.get(0).unwrap().snapshot, snap);

        let r2 = w.commit(0, vec![0x01, 0x02], NOW + 1).unwrap();
        assert_eq!(r2, WalResult::Applied);
        assert_eq!(w.get(0).unwrap().phase, WalPhase::Committed);
        assert_eq!(w.get(0).unwrap().proof_bytes, vec![0x01, 0x02]);
        assert!(w.is_committed(0));
    }

    #[test]
    fn test_prepare_abort_happy_path() {
        let mut w = wal();
        w.prepare(1, PKV, test_snapshot(1), NOW).unwrap();
        let r = w.abort(1, NOW + 1).unwrap();
        assert_eq!(r, WalResult::Applied);
        assert_eq!(w.get(1).unwrap().phase, WalPhase::Aborted);
        assert!(!w.is_committed(1));
    }

    // ── Idempotency — ADR-SEC-002 ─────────────────────────────────────────────

    #[test]
    fn test_prepare_idempotent() {
        let mut w = wal();
        w.prepare(0, PKV, test_snapshot(0), NOW).unwrap();
        // Second PREPARE on same checkpoint_id = no-op.
        let r = w.prepare(0, PKV, test_snapshot(0), NOW + 999).unwrap();
        assert_eq!(r, WalResult::AlreadyInState);
        // State unchanged.
        assert_eq!(w.get(0).unwrap().written_at_ms, NOW);
    }

    #[test]
    fn test_commit_idempotent() {
        let mut w = wal();
        w.prepare(0, PKV, test_snapshot(0), NOW).unwrap();
        w.commit(0, vec![0xFF], NOW + 1).unwrap();
        // Second COMMIT = no-op, proof_bytes not overwritten.
        let r = w.commit(0, vec![0x00], NOW + 2).unwrap();
        assert_eq!(r, WalResult::AlreadyInState);
        assert_eq!(w.get(0).unwrap().proof_bytes, vec![0xFF]);
    }

    #[test]
    fn test_abort_idempotent() {
        let mut w = wal();
        w.prepare(2, PKV, test_snapshot(2), NOW).unwrap();
        w.abort(2, NOW + 1).unwrap();
        let r = w.abort(2, NOW + 2).unwrap();
        assert_eq!(r, WalResult::AlreadyInState);
    }

    // ── Invalid transitions ───────────────────────────────────────────────────

    #[test]
    fn test_commit_without_prepare_fails() {
        let mut w = wal();
        let err = w.commit(99, vec![], NOW).unwrap_err();
        assert!(matches!(err, WalError::MissingPrepare { checkpoint_id: 99 }));
    }

    #[test]
    fn test_abort_without_prepare_fails() {
        let mut w = wal();
        let err = w.abort(99, NOW).unwrap_err();
        assert!(matches!(err, WalError::MissingPrepare { checkpoint_id: 99 }));
    }

    #[test]
    fn test_abort_after_commit_fails() {
        let mut w = wal();
        w.prepare(0, PKV, test_snapshot(0), NOW).unwrap();
        w.commit(0, vec![], NOW + 1).unwrap();
        let err = w.abort(0, NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Committed,
                to: WalPhase::Aborted,
                ..
            }
        ));
    }

    #[test]
    fn test_commit_after_abort_fails() {
        let mut w = wal();
        w.prepare(0, PKV, test_snapshot(0), NOW).unwrap();
        w.abort(0, NOW + 1).unwrap();
        let err = w.commit(0, vec![], NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Aborted,
                to: WalPhase::Committed,
                ..
            }
        ));
    }

    #[test]
    fn test_prepare_after_commit_fails() {
        let mut w = wal();
        w.prepare(0, PKV, test_snapshot(0), NOW).unwrap();
        w.commit(0, vec![], NOW + 1).unwrap();
        let err = w.prepare(0, PKV, test_snapshot(0), NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Committed,
                to: WalPhase::Prepared,
                ..
            }
        ));
    }

    #[test]
    fn test_prepare_after_abort_fails() {
        let mut w = wal();
        w.prepare(0, PKV, test_snapshot(0), NOW).unwrap();
        w.abort(0, NOW + 1).unwrap();
        let err = w.prepare(0, PKV, test_snapshot(0), NOW + 2).unwrap_err();
        assert!(matches!(
            err,
            WalError::InvalidTransition {
                from: WalPhase::Aborted,
                to: WalPhase::Prepared,
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
        w.prepare(5, PKV, snap.clone(), NOW).unwrap();

        // Snapshot fully retrievable after prepare.
        let retrieved = w.get_snapshot(5).unwrap();
        assert_eq!(*retrieved, snap);

        // Snapshot survives commit.
        w.commit(5, vec![0xAB], NOW + 1).unwrap();
        assert_eq!(*w.get_snapshot(5).unwrap(), snap);
    }

    #[test]
    fn test_proving_key_version_stored() {
        // ADR-SEC-002: proving_key_version field.
        let mut w = wal();
        w.prepare(0, 42, test_snapshot(0), NOW).unwrap();
        assert_eq!(w.get(0).unwrap().proving_key_version, 42);
    }

    // ── Multi-checkpoint ──────────────────────────────────────────────────────

    #[test]
    fn test_multiple_checkpoints_independent() {
        let mut w = wal();
        w.prepare(0, PKV, test_snapshot(0), NOW).unwrap();
        w.prepare(1, PKV, test_snapshot(1), NOW).unwrap();
        w.prepare(2, PKV, test_snapshot(2), NOW).unwrap();

        w.commit(0, vec![0x01], NOW + 1).unwrap();
        w.abort(1, NOW + 1).unwrap();
        // checkpoint 2 still prepared

        assert!(w.is_committed(0));
        assert!(!w.is_committed(1));
        assert!(!w.is_committed(2));
        assert_eq!(w.count_by_phase(&WalPhase::Committed), 1);
        assert_eq!(w.count_by_phase(&WalPhase::Aborted), 1);
        assert_eq!(w.count_by_phase(&WalPhase::Prepared), 1);
    }

    #[test]
    fn test_not_committed_if_no_entry() {
        let w = wal();
        assert!(!w.is_committed(0));
        assert!(w.get(0).is_none());
        assert!(w.get_snapshot(0).is_none());
    }
}
