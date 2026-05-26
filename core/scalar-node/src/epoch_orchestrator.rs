//! Epoch Transition Orchestrator — B.1, B.2, B.3, INV-4.10
//!
//! Memegang IMT dan UtxoSetAccumulator, menjalankan urutan atomic epoch transition:
//!   finalize EpochSMT(k) → reset IMT → mulai sub-epoch 0 epoch k+1
//!
//! Crash-recovery: deteksi state tidak konsisten (EpochSMT terarsip tapi IMT
//! belum reset, atau sebaliknya), selesaikan reset sebelum memproses tx.
//!
//! Spec: PraGenesis §3.1.10.2, INV-4.10, TV5.14

use scalar_crypto::imt::IncrementalMerkleTree;
use scalar_emission::utxo_set_smt::{UtxoSetAccumulator, UtxoSetState, GENESIS_EPOCH_ID};

/// Status konsistensi state IMT + EpochSMT. INV-4.10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicityStatus {
    /// State konsisten — IMT dan EpochSMT sejalan dengan epoch saat ini.
    Consistent { epoch: u64 },
    /// EpochSMT sudah diarsipkan untuk epoch k, tapi IMT belum di-reset.
    /// → Harus reset IMT sebelum melanjutkan.
    SMTArchivedImtNotReset { archived_epoch: u64 },
    /// IMT sudah di-reset, tapi EpochSMT belum diarsipkan untuk epoch sebelumnya.
    /// → Harus arsipkan EpochSMT dulu.
    ImtResetSmtNotArchived { current_epoch: u64 },
    /// Keduanya di-reset (genesis atau setelah transisi sukses).
    Fresh,
}

/// Epoch Transition Orchestrator. Spec §3.1.10.2.
///
/// Runtime owner yang memegang IMT dan EpochSMT, menjamin atomicity reset.
pub struct EpochTransitionOrchestrator {
    /// Incremental Merkle Tree untuk komitmen UTXO intra-epoch.
    pub imt: IncrementalMerkleTree,
    /// UTXO Set SMT untuk komitmen UTXO lintas-epoch.
    pub utxo_set_smt: UtxoSetAccumulator,
    /// Epoch saat ini.
    current_epoch: u64,
    /// Flag: apakah EpochSMT sudah di-finalize untuk epoch saat ini.
    smt_archived_this_epoch: bool,
    /// Flag: apakah IMT sudah di-reset untuk epoch saat ini.
    imt_reset_this_epoch: bool,
}

impl EpochTransitionOrchestrator {
    /// Buat orchestrator baru dalam genesis state. Spec §3.1.7.
    pub fn new() -> Self {
        Self {
            imt: IncrementalMerkleTree::new(),
            utxo_set_smt: UtxoSetAccumulator::new(),
            current_epoch: GENESIS_EPOCH_ID,
            smt_archived_this_epoch: false,
            imt_reset_this_epoch: false,
        }
    }

    /// Deteksi inkonsistensi state (crash-recovery). B.2, TV5.14.
    ///
    /// Returns AtomicityStatus berdasarkan flag internal.
    pub fn detect_atomicity_status(&self) -> AtomicityStatus {
        match (self.smt_archived_this_epoch, self.imt_reset_this_epoch) {
            (true, true) => {
                // Keduanya sudah selesai untuk epoch ini → siap lanjut.
                AtomicityStatus::Consistent {
                    epoch: self.current_epoch,
                }
            }
            (true, false) => {
                // EpochSMT sudah diarsipkan, IMT belum di-reset.
                AtomicityStatus::SMTArchivedImtNotReset {
                    archived_epoch: self.current_epoch,
                }
            }
            (false, true) => {
                // IMT sudah di-reset, EpochSMT belum diarsipkan.
                AtomicityStatus::ImtResetSmtNotArchived {
                    current_epoch: self.current_epoch,
                }
            }
            (false, false) => {
                if self.current_epoch == GENESIS_EPOCH_ID && self.imt.count == 0 {
                    AtomicityStatus::Fresh
                } else {
                    // Belum ada transisi yang terjadi di epoch ini — normal.
                    AtomicityStatus::Consistent {
                        epoch: self.current_epoch,
                    }
                }
            }
        }
    }

    /// Eksekusi transisi epoch secara ATOMIC. B.1, B.3, INV-4.10.
    ///
    /// Urutan wajib (§3.1.10.2):
    ///   1. Finalize EpochSMT(k) — ambil snapshot, arsipkan
    ///   2. Reset IMT ke genesis state
    ///   3. Mulai sub-epoch 0 epoch (k+1)
    ///
    /// Returns snapshot UtxoSetState untuk epoch yang baru diarsipkan.
    pub fn execute_epoch_transition(
        &mut self,
        new_epoch_id: u64,
    ) -> Result<UtxoSetState, EpochTransitionError> {
        // Pre-condition: new_epoch_id harus = current_epoch + 1
        if new_epoch_id != self.current_epoch + 1 {
            return Err(EpochTransitionError::NonSequentialEpoch {
                expected: self.current_epoch + 1,
                got: new_epoch_id,
            });
        }

        // Step 1: Finalize EpochSMT(k). Spec §3.1.10.2.
        let snapshot = self.utxo_set_smt.take_snapshot(self.current_epoch);

        // Step 2: Reset IMT ke genesis state. Spec §3.1.10.3.
        self.imt.reset();
        // Post-reset verification sudah ada di dalam imt.reset() (assert).

        // Step 3: Mulai sub-epoch 0 epoch (k+1).
        self.current_epoch = new_epoch_id;
        self.smt_archived_this_epoch = false; // siap arsip lagi nanti
        self.imt_reset_this_epoch = false;

        Ok(snapshot)
    }

    /// Recover dari crash — selesaikan transisi yang terputus. B.2, TV5.14.
    ///
    /// Dipanggil saat startup setelah detect_atomicity_status() mendeteksi
    /// state tidak konsisten.
    pub fn recover_inconsistent_state(&mut self) -> Result<(), EpochTransitionError> {
        match self.detect_atomicity_status() {
            AtomicityStatus::Consistent { .. } | AtomicityStatus::Fresh => {
                // Tidak ada yang perlu dilakukan.
                Ok(())
            }
            AtomicityStatus::SMTArchivedImtNotReset { .. } => {
                // EpochSMT sudah diarsipkan, tapi IMT belum di-reset.
                // Selesaikan reset.
                self.imt.reset();
                self.imt_reset_this_epoch = true;
                Ok(())
            }
            AtomicityStatus::ImtResetSmtNotArchived { current_epoch } => {
                // IMT sudah di-reset, tapi EpochSMT belum diarsipkan.
                // Arsipkan sekarang.
                let _snapshot = self.utxo_set_smt.take_snapshot(current_epoch);
                self.smt_archived_this_epoch = true;
                Ok(())
            }
        }
    }

    /// Proses transaksi valid di dalam epoch berjalan.
    /// Menambahkan output commitment ke IMT dan UtxoSetAccumulator.
    pub fn process_transaction(
        &mut self,
        commitment: &[u8; 32],
    ) -> Result<(), EpochTransitionError> {
        // Tolak transaksi jika state tidak konsisten. B.2.
        match self.detect_atomicity_status() {
            AtomicityStatus::Consistent { .. } | AtomicityStatus::Fresh => {}
            _ => return Err(EpochTransitionError::InconsistentState),
        }

        self.imt
            .append(commitment)
            .map_err(|e| EpochTransitionError::ImtError(format!("{:?}", e)))?;
        self.utxo_set_smt
            .insert_utxo(*commitment, self.current_epoch);
        Ok(())
    }

    /// Ambil epoch saat ini.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Ambil IMT frontier root. Spec §3.1.3.
    pub fn imt_frontier_root(&self) -> [u8; 32] {
        self.imt.root()
    }

    /// Ambil IMT count. Spec §3.1.3.
    pub fn imt_count(&self) -> u64 {
        self.imt.count
    }

    /// Ambil UTXO set root.
    pub fn utxo_set_root(&self) -> [u8; 32] {
        self.utxo_set_smt.root()
    }
}

impl Default for EpochTransitionOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EpochTransitionError {
    #[error("Epoch transition must be sequential: expected {expected}, got {got}")]
    NonSequentialEpoch { expected: u64, got: u64 },
    #[error("State is inconsistent — resolve before processing transactions")]
    InconsistentState,
    #[error("IMT error: {0}")]
    ImtError(String),
}

// ── Tests: TV5.14 Reset Atomicity ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_crypto::imt::IMT_GENESIS_FRONTIER;

    #[test]
    fn test_orchestrator_genesis_state() {
        let orch = EpochTransitionOrchestrator::new();
        assert_eq!(orch.current_epoch(), GENESIS_EPOCH_ID);
        assert_eq!(orch.imt_count(), 0);
        // D3: empty UtxoSetEpochSMT root = imt_empty_root(), NOT [0u8;32].
        assert_eq!(orch.utxo_set_root(), scalar_crypto::imt::imt_empty_root());
        assert_ne!(orch.utxo_set_root(), [0u8; 32]);
        assert_eq!(orch.detect_atomicity_status(), AtomicityStatus::Fresh);
    }

    #[test]
    fn test_execute_epoch_transition_atomic() {
        // TV5.14 / B.1: transisi epoch atomik. Spec §3.1.10.2.
        let mut orch = EpochTransitionOrchestrator::new();

        // Tambahkan beberapa komitmen di epoch 0
        orch.process_transaction(&[0xAAu8; 32]).unwrap();
        orch.process_transaction(&[0xBBu8; 32]).unwrap();
        assert_eq!(orch.imt_count(), 2);
        assert_ne!(orch.imt_frontier_root(), [0u8; 32]);

        // Eksekusi transisi epoch: 0 → 1
        let snapshot = orch.execute_epoch_transition(1).unwrap();
        assert_eq!(snapshot.snapshot_epoch, 0);
        assert_ne!(snapshot.utxo_set_root, [0u8; 32]);

        // Setelah transisi: IMT harus genesis, epoch = 1
        assert_eq!(orch.current_epoch(), 1);
        assert_eq!(orch.imt_count(), 0);
        assert_eq!(orch.imt.frontier, IMT_GENESIS_FRONTIER);
        assert_eq!(
            orch.detect_atomicity_status(),
            AtomicityStatus::Consistent { epoch: 1 }
        );
    }

    #[test]
    fn test_non_sequential_epoch_rejected() {
        let mut orch = EpochTransitionOrchestrator::new();
        // Lompat dari 0 ke 5 — harus ditolak
        let result = orch.execute_epoch_transition(5);
        assert!(matches!(
            result,
            Err(EpochTransitionError::NonSequentialEpoch {
                expected: 1,
                got: 5
            })
        ));
    }

    #[test]
    fn test_tv5_14_reset_atomicity_crash_before_imt_reset() {
        // TV5.14: Simulasi crash setelah EpochSMT diarsipkan, sebelum IMT di-reset.
        let mut orch = EpochTransitionOrchestrator::new();
        orch.process_transaction(&[0xCCu8; 32]).unwrap();

        // Simulasi: arsipkan EpochSMT tapi jangan reset IMT
        let _snapshot = orch.utxo_set_smt.take_snapshot(0);
        orch.smt_archived_this_epoch = true;
        // IMT masih berisi data epoch 0
        assert_eq!(orch.imt_count(), 1);
        assert_eq!(
            orch.detect_atomicity_status(),
            AtomicityStatus::SMTArchivedImtNotReset { archived_epoch: 0 }
        );

        // Recover: harus reset IMT
        orch.recover_inconsistent_state().unwrap();
        assert_eq!(orch.imt_count(), 0);
        assert_eq!(orch.imt.frontier, IMT_GENESIS_FRONTIER);
    }

    #[test]
    fn test_tv5_14_reset_atomicity_crash_before_smt_archive() {
        // TV5.14: Simulasi crash setelah IMT di-reset, sebelum EpochSMT diarsipkan.
        let mut orch = EpochTransitionOrchestrator::new();
        orch.process_transaction(&[0xDDu8; 32]).unwrap();

        // Simulasi: reset IMT tapi jangan arsipkan EpochSMT
        orch.imt.reset();
        orch.imt_reset_this_epoch = true;
        // EpochSMT belum diarsipkan
        assert_eq!(
            orch.detect_atomicity_status(),
            AtomicityStatus::ImtResetSmtNotArchived { current_epoch: 0 }
        );

        // Recover: harus arsipkan EpochSMT
        orch.recover_inconsistent_state().unwrap();
        assert!(orch.smt_archived_this_epoch);
    }

    #[test]
    fn test_tv5_14_no_tx_during_inconsistent_state() {
        // TV5.14: Transaksi harus ditolak selama state tidak konsisten.
        let mut orch = EpochTransitionOrchestrator::new();
        orch.process_transaction(&[0x01u8; 32]).unwrap();

        // Buat state tidak konsisten
        orch.smt_archived_this_epoch = true;
        // imt_reset_this_epoch = false

        // Transaksi harus ditolak
        let result = orch.process_transaction(&[0x02u8; 32]);
        assert!(matches!(
            result,
            Err(EpochTransitionError::InconsistentState)
        ));
    }

    #[test]
    fn test_tv5_14_full_crash_recovery_flow() {
        // TV5.14: Full crash-recovery flow. Spec §5.14.
        let mut orch = EpochTransitionOrchestrator::new();

        // Epoch 0: proses transaksi
        orch.process_transaction(&[0x11u8; 32]).unwrap();
        orch.process_transaction(&[0x22u8; 32]).unwrap();

        // Transisi normal 0 → 1
        let _snap = orch.execute_epoch_transition(1).unwrap();

        // Epoch 1: proses transaksi
        orch.process_transaction(&[0x33u8; 32]).unwrap();

        // Simulasi crash: setelah arsip EpochSMT tapi sebelum reset IMT
        let _snap2 = orch.utxo_set_smt.take_snapshot(1);
        orch.smt_archived_this_epoch = true;
        orch.imt_reset_this_epoch = false;
        assert_eq!(
            orch.detect_atomicity_status(),
            AtomicityStatus::SMTArchivedImtNotReset { archived_epoch: 1 }
        );

        // Recovery: reset IMT
        orch.recover_inconsistent_state().unwrap();

        // Sekarang state harus konsisten
        assert_eq!(orch.imt_count(), 0);

        // Transaksi bisa diproses lagi
        orch.process_transaction(&[0x44u8; 32]).unwrap();
        assert_eq!(orch.imt_count(), 1);
    }

    #[test]
    fn test_imt_utxo_independence() {
        // INV-4.10: IMT dan UtxoSetAccumulator harus independen.
        let mut orch = EpochTransitionOrchestrator::new();

        orch.process_transaction(&[0xAAu8; 32]).unwrap();
        orch.process_transaction(&[0xBBu8; 32]).unwrap();

        let imt_root_before = orch.imt_frontier_root();
        let utxo_root_before = orch.utxo_set_root();

        // Setelah transisi, keduanya berubah
        let _ = orch.execute_epoch_transition(1).unwrap();

        assert_eq!(orch.imt_count(), 0);
        // IMT root harus berbeda dari sebelum transisi
        assert_ne!(orch.imt_frontier_root(), imt_root_before);
        // UTXO root harus tetap (tidak berubah oleh reset IMT)
        assert_eq!(orch.utxo_set_root(), utxo_root_before);
    }
}
