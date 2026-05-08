//! Node Resumption Protocol — Spec §10.5
//!
//! 5 fase resumption saat node kembali online setelah offline:
//!
//! Phase 1: DETECTION
//!   Node mendeteksi dirinya offline (gap dalam seq_num chain).
//!   Gap = seq_num_current - seq_num_last_known > 0.
//!
//! Phase 2: SYNC
//!   Node mendownload EpochAnchor dari peers untuk setiap epoch yang di-miss.
//!   Verifikasi SPHINCS+ signature setiap EpochAnchor.
//!
//! Phase 3: STATE_REBUILD
//!   Node rebuild state lokal:
//!   - Replay NullifierSet promotions yang di-miss
//!   - Update MaturityStore dengan gap (epoch offline = w=0)
//!   - Sinkronisasi SMT root
//!
//! Phase 4: VALIDATION
//!   Node meminta 3 peer independen untuk konfirmasi state hash.
//!   Quorum: 2/3 peer harus setuju pada state hash.
//!
//! Phase 5: RESUME
//!   Node mulai kirim heartbeat kembali.
//!   seq_num dilanjutkan dari seq_num terbaru (bukan dari 0).
//!   Uptime credit dimulai dari epoch berikutnya (tidak retroaktif).
//!
//! No floating point. No wall-clock for epoch boundary (Rule T-1 §7.2c).

// ── Constants — spec §10.5 ───────────────────────────────────────────────────

/// Minimum peer untuk validasi state saat resumption. Spec §10.5 Phase 4.
pub const RESUMPTION_VALIDATION_PEERS: u32 = 3;

/// Quorum peer yang harus setuju pada state hash. Spec §10.5 Phase 4.
/// 2/3 dari RESUMPTION_VALIDATION_PEERS.
pub const RESUMPTION_VALIDATION_QUORUM: u32 = 2;

/// Maximum epoch gap yang bisa di-sync otomatis. Spec §10.5 Phase 2.
/// Jika gap > threshold → node harus full resync dari genesis.
pub const RESUMPTION_MAX_AUTO_SYNC_EPOCHS: u64 = 100;

// ── ResumptionPhase — spec §10.5 ─────────────────────────────────────────────

/// Fase resumption node. Spec §10.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumptionPhase {
    /// Phase 1: Node mendeteksi gap dalam seq_num chain. Spec §10.5.
    Detection {
        last_known_seq_num: u32,
        current_seq_num: u32,
        gap_epochs: u64,
    },
    /// Phase 2: Download EpochAnchor untuk epoch yang di-miss. Spec §10.5.
    Sync {
        epochs_to_sync: Vec<u64>,
        synced_count: u32,
    },
    /// Phase 3: Rebuild state lokal. Spec §10.5.
    StateRebuild {
        epochs_rebuilt: u32,
        smt_root: [u8; 32],
    },
    /// Phase 4: Validasi state dengan peers. Spec §10.5.
    Validation {
        state_hash: [u8; 32],
        confirmations: u32,
        required: u32,
    },
    /// Phase 5: Node resume normal operation. Spec §10.5.
    Resumed {
        resume_seq_num: u32,
        resume_epoch: u64,
    },
    /// Resumption gagal — node harus full resync. Spec §10.5.
    Failed { reason: ResumptionFailReason },
}

/// Alasan kegagalan resumption. Spec §10.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumptionFailReason {
    /// Gap terlalu besar untuk auto-sync. Spec §10.5 Phase 2.
    GapTooLarge { gap_epochs: u64, max: u64 },
    /// Tidak cukup peer untuk validasi. Spec §10.5 Phase 4.
    InsufficientPeers { available: u32, required: u32 },
    /// Quorum gagal — peer tidak setuju pada state hash. Spec §10.5 Phase 4.
    ValidationQuorumFailed { confirmations: u32, required: u32 },
    /// EpochAnchor tidak valid (signature fail). Spec §10.5 Phase 2.
    InvalidEpochAnchor { epoch_id: u64 },
}

// ── ResumptionProtocol — spec §10.5 ──────────────────────────────────────────

/// Node Resumption Protocol state machine. Spec §10.5.
pub struct ResumptionProtocol {
    pub node_id: [u8; 4],
    pub phase: ResumptionPhase,
}

impl ResumptionProtocol {
    /// Inisialisasi protokol saat node mendeteksi gap. Spec §10.5 Phase 1.
    pub fn new(node_id: [u8; 4], last_known_seq_num: u32, current_seq_num: u32) -> Self {
        let gap_epochs = compute_gap_epochs(last_known_seq_num, current_seq_num);
        Self {
            node_id,
            phase: ResumptionPhase::Detection {
                last_known_seq_num,
                current_seq_num,
                gap_epochs,
            },
        }
    }

    /// Phase 1 → Phase 2: Mulai sync EpochAnchor. Spec §10.5.
    ///
    /// Returns Err jika gap terlalu besar untuk auto-sync.
    pub fn start_sync(&mut self, epochs_to_sync: Vec<u64>) -> Result<(), ResumptionFailReason> {
        let gap_epochs = epochs_to_sync.len() as u64;
        if gap_epochs > RESUMPTION_MAX_AUTO_SYNC_EPOCHS {
            let reason = ResumptionFailReason::GapTooLarge {
                gap_epochs,
                max: RESUMPTION_MAX_AUTO_SYNC_EPOCHS,
            };
            self.phase = ResumptionPhase::Failed {
                reason: reason.clone(),
            };
            return Err(reason);
        }
        self.phase = ResumptionPhase::Sync {
            epochs_to_sync,
            synced_count: 0,
        };
        Ok(())
    }

    /// Phase 2: Record satu epoch berhasil di-sync. Spec §10.5 Phase 2.
    pub fn record_epoch_synced(&mut self) {
        if let ResumptionPhase::Sync { synced_count, .. } = &mut self.phase {
            *synced_count += 1;
        }
    }

    /// Phase 2 → Phase 3: Mulai rebuild state. Spec §10.5 Phase 3.
    pub fn start_state_rebuild(&mut self, smt_root: [u8; 32]) {
        self.phase = ResumptionPhase::StateRebuild {
            epochs_rebuilt: 0,
            smt_root,
        };
    }

    /// Phase 3: Record satu epoch berhasil di-rebuild. Spec §10.5 Phase 3.
    pub fn record_epoch_rebuilt(&mut self) {
        if let ResumptionPhase::StateRebuild { epochs_rebuilt, .. } = &mut self.phase {
            *epochs_rebuilt += 1;
        }
    }

    /// Phase 3 → Phase 4: Mulai validasi dengan peers. Spec §10.5 Phase 4.
    pub fn start_validation(&mut self, state_hash: [u8; 32]) {
        self.phase = ResumptionPhase::Validation {
            state_hash,
            confirmations: 0,
            required: RESUMPTION_VALIDATION_QUORUM,
        };
    }

    /// Phase 4: Record konfirmasi dari satu peer. Spec §10.5 Phase 4.
    ///
    /// Returns true jika quorum tercapai.
    pub fn record_peer_confirmation(&mut self, peer_state_hash: &[u8; 32]) -> bool {
        if let ResumptionPhase::Validation {
            state_hash,
            confirmations,
            required,
        } = &mut self.phase
        {
            if peer_state_hash == state_hash {
                *confirmations += 1;
            }
            *confirmations >= *required
        } else {
            false
        }
    }

    /// Phase 4 → Phase 5: Resume normal operation. Spec §10.5 Phase 5.
    ///
    /// `resume_seq_num`: seq_num terakhir yang diketahui (dilanjutkan dari sini).
    /// `resume_epoch`: epoch untuk mulai credit uptime (tidak retroaktif).
    ///
    /// RULE T-1: seq_num menentukan epoch boundary, BUKAN wall-clock. Spec §7.2c.
    pub fn resume(
        &mut self,
        resume_seq_num: u32,
        resume_epoch: u64,
    ) -> Result<(), ResumptionFailReason> {
        if let ResumptionPhase::Validation {
            confirmations,
            required,
            ..
        } = &self.phase
        {
            if *confirmations < *required {
                let reason = ResumptionFailReason::ValidationQuorumFailed {
                    confirmations: *confirmations,
                    required: *required,
                };
                self.phase = ResumptionPhase::Failed {
                    reason: reason.clone(),
                };
                return Err(reason);
            }
        }
        self.phase = ResumptionPhase::Resumed {
            resume_seq_num,
            resume_epoch,
        };
        Ok(())
    }

    /// Cek apakah node sudah resume. Spec §10.5 Phase 5.
    pub fn is_resumed(&self) -> bool {
        matches!(self.phase, ResumptionPhase::Resumed { .. })
    }

    /// Cek apakah resumption gagal. Spec §10.5.
    pub fn is_failed(&self) -> bool {
        matches!(self.phase, ResumptionPhase::Failed { .. })
    }
}

// ── Helper functions — spec §10.5 ────────────────────────────────────────────

/// Compute gap dalam epochs dari dua seq_num. Spec §10.5 Phase 1.
///
/// RULE T-1: epoch boundary dari seq_num, BUKAN wall-clock. Spec §7.2c.
pub fn compute_gap_epochs(last_known_seq_num: u32, current_seq_num: u32) -> u64 {
    use crate::liveness::EPOCH_HB_COUNT;
    if current_seq_num <= last_known_seq_num {
        return 0;
    }
    let gap_hb = current_seq_num - last_known_seq_num;
    // Gap dalam epochs = gap_hb / EPOCH_HB_COUNT (integer division)
    (gap_hb / EPOCH_HB_COUNT) as u64
}

/// Compute state hash untuk validasi peer. Spec §10.5 Phase 4.
///
/// state_hash = BLAKE3(smt_root || epoch_id_le64 || node_id)
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_resumption_state_hash(
    smt_root: &[u8; 32],
    epoch_id: u64,
    node_id: &[u8; 4],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(smt_root);
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(node_id);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node() -> [u8; 4] {
        [0x01, 0x02, 0x03, 0x04]
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_resumption_validation_peers_is_3() {
        // Spec §10.5 Phase 4: min 3 peer untuk validasi.
        assert_eq!(RESUMPTION_VALIDATION_PEERS, 3u32);
    }

    #[test]
    fn test_resumption_validation_quorum_is_2() {
        // Spec §10.5 Phase 4: quorum 2/3.
        assert_eq!(RESUMPTION_VALIDATION_QUORUM, 2u32);
    }

    #[test]
    fn test_resumption_max_auto_sync_epochs_is_100() {
        // Spec §10.5 Phase 2: max 100 epoch auto-sync.
        assert_eq!(RESUMPTION_MAX_AUTO_SYNC_EPOCHS, 100u64);
    }

    // ── Phase 1: Detection ────────────────────────────────────────────────────

    #[test]
    fn test_phase1_detection_on_new() {
        // Phase 1 saat node mendeteksi gap. Spec §10.5.
        let protocol = ResumptionProtocol::new(make_node(), 4_320, 8_640);
        assert!(matches!(
            protocol.phase,
            ResumptionPhase::Detection { gap_epochs: 1, .. }
        ));
    }

    #[test]
    fn test_phase1_no_gap_zero_epochs() {
        // Tidak ada gap → gap_epochs = 0.
        let protocol = ResumptionProtocol::new(make_node(), 100, 100);
        assert!(matches!(
            protocol.phase,
            ResumptionPhase::Detection { gap_epochs: 0, .. }
        ));
    }

    // ── Phase 2: Sync ─────────────────────────────────────────────────────────

    #[test]
    fn test_phase2_sync_starts() {
        // Phase 1 → Phase 2. Spec §10.5.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        let epochs = vec![0u64];
        protocol.start_sync(epochs).unwrap();
        assert!(matches!(protocol.phase, ResumptionPhase::Sync { .. }));
    }

    #[test]
    fn test_phase2_gap_too_large_fails() {
        // Gap > 100 epoch → auto-sync gagal. Spec §10.5 Phase 2.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320 * 101);
        let epochs: Vec<u64> = (0..=100).collect(); // 101 epochs
        let err = protocol.start_sync(epochs).unwrap_err();
        assert!(matches!(err, ResumptionFailReason::GapTooLarge { .. }));
        assert!(protocol.is_failed());
    }

    #[test]
    fn test_phase2_record_epoch_synced() {
        // synced_count bertambah. Spec §10.5 Phase 2.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.record_epoch_synced();
        if let ResumptionPhase::Sync { synced_count, .. } = &protocol.phase {
            assert_eq!(*synced_count, 1);
        }
    }

    // ── Phase 3: StateRebuild ─────────────────────────────────────────────────

    #[test]
    fn test_phase3_state_rebuild() {
        // Phase 2 → Phase 3. Spec §10.5.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0xAAu8; 32]);
        assert!(matches!(
            protocol.phase,
            ResumptionPhase::StateRebuild { .. }
        ));
    }

    #[test]
    fn test_phase3_record_epoch_rebuilt() {
        // epochs_rebuilt bertambah. Spec §10.5 Phase 3.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0u8; 32]);
        protocol.record_epoch_rebuilt();
        if let ResumptionPhase::StateRebuild { epochs_rebuilt, .. } = &protocol.phase {
            assert_eq!(*epochs_rebuilt, 1);
        }
    }

    // ── Phase 4: Validation ───────────────────────────────────────────────────

    #[test]
    fn test_phase4_validation_starts() {
        // Phase 3 → Phase 4. Spec §10.5.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0u8; 32]);
        protocol.start_validation([0xBBu8; 32]);
        assert!(matches!(protocol.phase, ResumptionPhase::Validation { .. }));
    }

    #[test]
    fn test_phase4_quorum_achieved() {
        // 2 konfirmasi → quorum tercapai. Spec §10.5 Phase 4.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0u8; 32]);
        let state_hash = [0xBBu8; 32];
        protocol.start_validation(state_hash);
        assert!(!protocol.record_peer_confirmation(&state_hash)); // 1 → not yet
        assert!(protocol.record_peer_confirmation(&state_hash)); // 2 → quorum!
    }

    #[test]
    fn test_phase4_wrong_hash_not_counted() {
        // Hash salah tidak dihitung sebagai konfirmasi. Spec §10.5 Phase 4.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0u8; 32]);
        protocol.start_validation([0xBBu8; 32]);
        let wrong_hash = [0xFFu8; 32];
        assert!(!protocol.record_peer_confirmation(&wrong_hash));
        if let ResumptionPhase::Validation { confirmations, .. } = &protocol.phase {
            assert_eq!(*confirmations, 0);
        }
    }

    // ── Phase 5: Resume ───────────────────────────────────────────────────────

    #[test]
    fn test_phase5_resume_after_quorum() {
        // Phase 4 → Phase 5 setelah quorum. Spec §10.5 Phase 5.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0u8; 32]);
        let state_hash = [0xBBu8; 32];
        protocol.start_validation(state_hash);
        protocol.record_peer_confirmation(&state_hash);
        protocol.record_peer_confirmation(&state_hash);
        protocol.resume(4_320, 1).unwrap();
        assert!(protocol.is_resumed());
    }

    #[test]
    fn test_phase5_resume_without_quorum_fails() {
        // Resume tanpa quorum → fail. Spec §10.5 Phase 4.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0u8; 32]);
        protocol.start_validation([0xBBu8; 32]);
        // Hanya 1 konfirmasi (butuh 2)
        protocol.record_peer_confirmation(&[0xBBu8; 32]);
        let err = protocol.resume(4_320, 1).unwrap_err();
        assert!(matches!(
            err,
            ResumptionFailReason::ValidationQuorumFailed { .. }
        ));
        assert!(protocol.is_failed());
    }

    #[test]
    fn test_phase5_uptime_not_retroactive() {
        // resume_epoch = epoch berikutnya, bukan epoch yang di-miss. Spec §10.5.
        let mut protocol = ResumptionProtocol::new(make_node(), 0, 4_320);
        protocol.start_sync(vec![0]).unwrap();
        protocol.start_state_rebuild([0u8; 32]);
        let state_hash = [0xBBu8; 32];
        protocol.start_validation(state_hash);
        protocol.record_peer_confirmation(&state_hash);
        protocol.record_peer_confirmation(&state_hash);
        protocol.resume(4_320, 1).unwrap(); // epoch 1 = epoch berikutnya
        if let ResumptionPhase::Resumed { resume_epoch, .. } = &protocol.phase {
            assert_eq!(*resume_epoch, 1); // tidak retroaktif ke epoch 0
        }
    }

    // ── compute_gap_epochs ────────────────────────────────────────────────────

    #[test]
    fn test_compute_gap_epochs_one_epoch() {
        // Spec §10.5 Phase 1: gap = 4320 HB = 1 epoch.
        assert_eq!(compute_gap_epochs(0, 4_320), 1);
    }

    #[test]
    fn test_compute_gap_epochs_zero() {
        // Tidak ada gap. Spec §10.5.
        assert_eq!(compute_gap_epochs(100, 100), 0);
    }

    #[test]
    fn test_compute_gap_epochs_uses_seq_num_not_wall_clock() {
        // RULE T-1: epoch boundary dari seq_num. Spec §7.2c.
        // Fungsi tidak menerima wall-clock parameter.
        let gap = compute_gap_epochs(4_320, 8_640);
        assert_eq!(gap, 1);
    }

    #[test]
    fn test_compute_gap_epochs_partial_epoch() {
        // Gap < EPOCH_HB_COUNT → 0 epoch. Spec §10.5.
        assert_eq!(compute_gap_epochs(0, 100), 0);
    }

    // ── compute_resumption_state_hash ─────────────────────────────────────────

    #[test]
    fn test_state_hash_deterministic() {
        // state_hash deterministik. Spec §10.5 Phase 4.
        let h1 = compute_resumption_state_hash(&[0xAAu8; 32], 5, &make_node());
        let h2 = compute_resumption_state_hash(&[0xAAu8; 32], 5, &make_node());
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_state_hash_different_epoch_differs() {
        // epoch berbeda → hash berbeda. Spec §10.5 Phase 4.
        let h1 = compute_resumption_state_hash(&[0u8; 32], 1, &make_node());
        let h2 = compute_resumption_state_hash(&[0u8; 32], 2, &make_node());
        assert_ne!(h1, h2);
    }
}
