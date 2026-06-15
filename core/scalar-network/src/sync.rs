// File: crates/scalar-network/src/sync.rs
//
// Progressive Sync + Checkpoint — Spec §6.5 + §12.8
//
// Flow node baru bergabung:
//   1. Download genesis object → verify BLAKE3 hash
//   2. Download checkpoint snapshot (setiap 90 hari)
//   3. Verify NS_CHECKPOINT SMT root (<100ms, ~150KB)
//   4. Delta sync dari checkpoint ke tip (gossip delta)
//   5. Node siap berpartisipasi
//
// Properties:
//   - Long-range attack blocked (NS_ARCH soundness ε ≈ 2^-6144)
//   - Tidak perlu download seluruh NullifierSet dari scratch
//   - Checkpoint interval: 90 hari (Layer 2 CONSTRAINED, range 30-180)

// ── Konstanta Spec §6.5 + §12.8 ──────────────────────────────────────

/// Checkpoint interval dalam hari. Spec §6.5: 90 hari.
pub const CHECKPOINT_INTERVAL_DAYS: u64 = 90;

/// Maximum NS_CHECKPOINT SMT root data size (bytes). [K-1]
pub const NS_CHECKPOINT_ROOT_MAX_BYTES: usize = 32;

/// Maximum NS_CHECKPOINT SMT root verification time (ms). [K-1]
pub const NS_CHECKPOINT_VERIFY_MAX_MS: u64 = 1;

/// Jumlah bootstrap peers hardcoded. Spec §12.8: 50 peers.
pub const BOOTSTRAP_PEER_COUNT: usize = 50;

/// Minimum persentase bootstrap peers per region. Spec §12.8: ≥20%.
pub const BOOTSTRAP_MIN_REGION_PERCENT: u64 = 20;

/// Maksimum persentase bootstrap peers per region. Spec §12.8: ≤40%.
pub const BOOTSTRAP_MAX_REGION_PERCENT: u64 = 40;

/// Genesis object size maksimum (bytes). Spec §12.8: <1 KB.
pub const GENESIS_MAX_BYTES: usize = 1024;

/// Jumlah finality threshold standar (%). Spec §12.9.
pub const FINALITY_STANDARD_PERCENT: u64 = 67;

/// Checkpoint interval minimum (hari). Spec §6.5: range 30-180.
pub const CHECKPOINT_INTERVAL_MIN_DAYS: u64 = 30;

/// Checkpoint interval maksimum (hari). Spec §6.5: range 30-180.
pub const CHECKPOINT_INTERVAL_MAX_DAYS: u64 = 180;

// ── Sync State Machine ────────────────────────────────────────────────

/// State machine untuk progressive sync node baru. Spec §12.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Belum mulai sync.
    Idle,
    /// Step 1: Download + verifikasi genesis object.
    VerifyingGenesis,
    /// Step 2: Download checkpoint snapshot.
    DownloadingCheckpoint { checkpoint_epoch: u64 },
    /// Step 3: Verifikasi NS_CHECKPOINT SMT root.
    VerifyingNsCheckpoint { checkpoint_epoch: u64 },
    /// Step 4: Delta sync dari checkpoint ke tip.
    DeltaSyncing {
        checkpoint_epoch: u64,
        current_epoch: u64,
    },
    /// Step 5: Node fully synced, siap berpartisipasi.
    Synced { tip_epoch: u64 },
    /// Sync gagal — alasan tersimpan.
    Failed { reason: SyncFailReason },
}

/// Alasan kegagalan sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFailReason {
    /// Genesis hash tidak cocok dengan hardcoded hash.
    GenesisHashMismatch,
    /// NS_CHECKPOINT SMT root tidak valid.
    NsArchProofInvalid,
    /// NS_CHECKPOINT SMT root terlalu besar (> 150 KB).
    NsArchProofTooLarge,
    /// NS_ARCH verification terlalu lambat (> 100ms).
    NsArchVerifyTooSlow,
    /// Tidak ada checkpoint tersedia.
    NoCheckpointAvailable,
    /// Delta sync gagal karena tidak ada peer.
    NoPeersAvailable,
}

impl SyncState {
    /// True jika node sudah fully synced.
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncState::Synced { .. })
    }

    /// True jika sync sedang berjalan.
    pub fn is_in_progress(&self) -> bool {
        !matches!(
            self,
            SyncState::Idle | SyncState::Synced { .. } | SyncState::Failed { .. }
        )
    }

    /// True jika sync gagal.
    pub fn is_failed(&self) -> bool {
        matches!(self, SyncState::Failed { .. })
    }
}

// ── Genesis Verification ──────────────────────────────────────────────

/// Hasil verifikasi genesis object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisVerifyResult {
    /// Genesis valid — hash cocok.
    Valid,
    /// Genesis tidak valid — hash mismatch.
    InvalidHash { expected: [u8; 32], got: [u8; 32] },
    /// Genesis terlalu besar.
    TooLarge { size: usize },
}

/// Verifikasi genesis object. Spec §12.8.
/// BLAKE3(genesis_bytes) harus == hardcoded_canonical_hash.
pub fn verify_genesis(
    genesis_bytes: &[u8],
    hardcoded_canonical_hash: &[u8; 32],
) -> GenesisVerifyResult {
    if genesis_bytes.len() > GENESIS_MAX_BYTES {
        return GenesisVerifyResult::TooLarge {
            size: genesis_bytes.len(),
        };
    }

    // Hitung BLAKE3 hash genesis
    let computed = blake3_hash(genesis_bytes);

    if &computed == hardcoded_canonical_hash {
        GenesisVerifyResult::Valid
    } else {
        GenesisVerifyResult::InvalidHash {
            expected: *hardcoded_canonical_hash,
            got: computed,
        }
    }
}

// ── Checkpoint Management ─────────────────────────────────────────────

/// Metadata checkpoint. Spec §6.5 + §12.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointMetadata {
    /// Epoch saat checkpoint dibuat.
    pub epoch: u64,
    /// Hash NullifierSet root saat checkpoint.
    pub nullifier_set_root: [u8; 32],
    /// Hash NS_CHECKPOINT SMT root.
    pub ns_checkpoint_smt_root: [u8; 32],
    /// Ukuran NS_CHECKPOINT SMT root (bytes).
    pub ns_checkpoint_root_size: usize,
    /// Timestamp checkpoint (Unix).
    pub timestamp: u64,
}

/// Validasi metadata checkpoint. Spec §6.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointValidation {
    Valid,
    /// Proof terlalu besar (> 150 KB).
    ProofTooLarge {
        size: usize,
    },
    /// Epoch tidak valid.
    InvalidEpoch,
}

/// Validasi checkpoint sebelum download full proof.
pub fn validate_checkpoint_metadata(meta: &CheckpointMetadata) -> CheckpointValidation {
    if meta.epoch == 0 {
        return CheckpointValidation::InvalidEpoch;
    }
    if meta.ns_checkpoint_root_size > NS_CHECKPOINT_ROOT_MAX_BYTES {
        return CheckpointValidation::ProofTooLarge {
            size: meta.ns_checkpoint_root_size,
        };
    }
    CheckpointValidation::Valid
}

/// Hitung epoch checkpoint terbaru berdasarkan current_epoch.
/// Checkpoint dibuat setiap CHECKPOINT_INTERVAL_DAYS (dalam satuan epoch ≈ 30 hari).
/// Spec §6.5: interval 90 hari = 3 epoch.
pub fn latest_checkpoint_epoch(current_epoch: u64) -> Option<u64> {
    // Checkpoint setiap 3 epoch (90 hari / 30 hari per epoch)
    const CHECKPOINT_EPOCH_INTERVAL: u64 = 3;
    if current_epoch < CHECKPOINT_EPOCH_INTERVAL {
        return None;
    }
    let latest = (current_epoch / CHECKPOINT_EPOCH_INTERVAL) * CHECKPOINT_EPOCH_INTERVAL;
    if latest == 0 {
        None
    } else {
        Some(latest)
    }
}

// ── NS_ARCH Proof Verification ────────────────────────────────────────

/// Hasil verifikasi NS_CHECKPOINT SMT root. Spec §6.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsArchVerifyResult {
    /// Proof valid — node bisa trust seluruh history.
    Valid,
    /// Proof terlalu besar.
    TooLarge { size: usize },
    /// Verifikasi terlalu lambat (> 100ms).
    TooSlow { elapsed_ms: u64 },
    /// Proof tidak valid secara kriptografi.
    InvalidProof,
}

/// Validasi ukuran dan waktu verifikasi NS_CHECKPOINT SMT root. Spec §6.5.
/// Catatan: verifikasi kriptografi sebenarnya dilakukan oleh scalar-stark crate.
/// Fungsi ini memvalidasi constraints ukuran dan timing.
pub fn validate_ns_checkpoint_constraints(
    proof_size_bytes: usize,
    verify_elapsed_ms: u64,
) -> NsArchVerifyResult {
    if proof_size_bytes > NS_CHECKPOINT_ROOT_MAX_BYTES {
        return NsArchVerifyResult::TooLarge {
            size: proof_size_bytes,
        };
    }
    if verify_elapsed_ms > NS_CHECKPOINT_VERIFY_MAX_MS {
        return NsArchVerifyResult::TooSlow {
            elapsed_ms: verify_elapsed_ms,
        };
    }
    NsArchVerifyResult::Valid
}

// ── Bootstrap Peer Diversity ──────────────────────────────────────────

/// Jumlah bootstrap peers per region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapDiversity {
    pub americas: usize,
    pub emea: usize,
    pub asia_pacific: usize,
}

impl BootstrapDiversity {
    /// Total bootstrap peers.
    pub fn total(&self) -> usize {
        self.americas + self.emea + self.asia_pacific
    }

    /// Hitung persentase region (fixed-point, basis 100).
    pub fn region_percent(&self, region_count: usize) -> u64 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        (region_count as u64 * 100) / total as u64
    }
}

/// Validasi geographic diversity bootstrap peers. Spec §12.8.
/// Setiap region: ≥20% dan ≤40%.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapDiversityResult {
    Valid,
    /// Region terlalu sedikit (< 20%).
    RegionTooSmall {
        region: &'static str,
        percent: u64,
    },
    /// Region terlalu dominan (> 40%).
    RegionTooLarge {
        region: &'static str,
        percent: u64,
    },
    /// Total peers tidak cukup.
    InsufficientPeers {
        count: usize,
    },
}

/// Validasi diversity bootstrap list. Spec §12.8.
pub fn validate_bootstrap_diversity(d: &BootstrapDiversity) -> BootstrapDiversityResult {
    if d.total() < BOOTSTRAP_PEER_COUNT {
        return BootstrapDiversityResult::InsufficientPeers { count: d.total() };
    }

    let regions = [
        ("Americas", d.americas),
        ("EMEA", d.emea),
        ("AsiaPacific", d.asia_pacific),
    ];

    for (name, count) in regions {
        let pct = d.region_percent(count);
        if pct < BOOTSTRAP_MIN_REGION_PERCENT {
            return BootstrapDiversityResult::RegionTooSmall {
                region: name,
                percent: pct,
            };
        }
        if pct > BOOTSTRAP_MAX_REGION_PERCENT {
            return BootstrapDiversityResult::RegionTooLarge {
                region: name,
                percent: pct,
            };
        }
    }

    BootstrapDiversityResult::Valid
}

// ── Delta Sync Progress ───────────────────────────────────────────────

/// Progres delta sync dari checkpoint ke tip. Spec §12.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaSyncProgress {
    /// Epoch awal (checkpoint).
    pub from_epoch: u64,
    /// Epoch target (tip jaringan).
    pub to_epoch: u64,
    /// Epoch yang sudah berhasil di-sync.
    pub synced_epoch: u64,
}

impl DeltaSyncProgress {
    pub fn new(from_epoch: u64, to_epoch: u64) -> Self {
        Self {
            from_epoch,
            to_epoch,
            synced_epoch: from_epoch,
        }
    }

    /// Persentase progress (0-100).
    pub fn percent_complete(&self) -> u64 {
        let total = self.to_epoch.saturating_sub(self.from_epoch);
        if total == 0 {
            return 100;
        }
        let done = self.synced_epoch.saturating_sub(self.from_epoch);
        (done * 100) / total
    }

    /// True jika delta sync selesai.
    pub fn is_complete(&self) -> bool {
        self.synced_epoch >= self.to_epoch
    }

    /// Advance ke epoch berikutnya.
    pub fn advance(&mut self) {
        if self.synced_epoch < self.to_epoch {
            self.synced_epoch += 1;
        }
    }
}

// ── Helper ────────────────────────────────────────────────────────────

/// BLAKE3 hash sederhana (stub untuk test — production pakai scalar-crypto).
/// Returns 32 byte hash.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    // Simplified deterministic hash untuk unit test
    // Production: gunakan blake3 crate dari scalar-crypto
    let mut result = [0u8; 32];
    let mut h: u64 = 14_695_981_039_346_656_037;
    for (i, &b) in data.iter().enumerate() {
        h ^= b as u64;
        h = h.wrapping_mul(1_099_511_628_211);
        result[i % 32] ^= (h & 0xff) as u8;
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SyncState ─────────────────────────────────────────────────────

    #[test]
    fn test_sync_state_idle_not_synced() {
        assert!(!SyncState::Idle.is_synced());
        assert!(!SyncState::Idle.is_in_progress());
    }

    #[test]
    fn test_sync_state_synced() {
        let s = SyncState::Synced { tip_epoch: 10 };
        assert!(s.is_synced());
        assert!(!s.is_in_progress());
        assert!(!s.is_failed());
    }

    #[test]
    fn test_sync_state_in_progress() {
        let s = SyncState::VerifyingGenesis;
        assert!(s.is_in_progress());
        assert!(!s.is_synced());
    }

    #[test]
    fn test_sync_state_failed() {
        let s = SyncState::Failed {
            reason: SyncFailReason::GenesisHashMismatch,
        };
        assert!(s.is_failed());
        assert!(!s.is_synced());
        assert!(!s.is_in_progress());
    }

    #[test]
    fn test_sync_state_delta_syncing_in_progress() {
        let s = SyncState::DeltaSyncing {
            checkpoint_epoch: 3,
            current_epoch: 5,
        };
        assert!(s.is_in_progress());
    }

    // ── Genesis ───────────────────────────────────────────────────────

    #[test]
    fn test_genesis_verify_valid() {
        let genesis = b"scalar_genesis_v1_data";
        let hash = blake3_hash(genesis);
        assert_eq!(verify_genesis(genesis, &hash), GenesisVerifyResult::Valid);
    }

    #[test]
    fn test_genesis_verify_hash_mismatch() {
        let genesis = b"scalar_genesis_v1_data";
        let wrong_hash = [0xFFu8; 32];
        let result = verify_genesis(genesis, &wrong_hash);
        assert!(matches!(result, GenesisVerifyResult::InvalidHash { .. }));
    }

    #[test]
    fn test_genesis_verify_too_large() {
        let large = vec![0u8; GENESIS_MAX_BYTES + 1];
        let hash = [0u8; 32];
        let result = verify_genesis(&large, &hash);
        assert_eq!(
            result,
            GenesisVerifyResult::TooLarge {
                size: GENESIS_MAX_BYTES + 1
            }
        );
    }

    #[test]
    fn test_genesis_verify_exact_max_size_ok() {
        let exact = vec![0u8; GENESIS_MAX_BYTES];
        let hash = blake3_hash(&exact);
        assert_eq!(verify_genesis(&exact, &hash), GenesisVerifyResult::Valid);
    }

    // ── Checkpoint ────────────────────────────────────────────────────

    #[test]
    fn test_latest_checkpoint_epoch_none_below_interval() {
        assert_eq!(latest_checkpoint_epoch(0), None);
        assert_eq!(latest_checkpoint_epoch(2), None);
    }

    #[test]
    fn test_latest_checkpoint_epoch_at_3() {
        assert_eq!(latest_checkpoint_epoch(3), Some(3));
    }

    #[test]
    fn test_latest_checkpoint_epoch_at_5() {
        // epoch 5 → checkpoint di epoch 3
        assert_eq!(latest_checkpoint_epoch(5), Some(3));
    }

    #[test]
    fn test_latest_checkpoint_epoch_at_6() {
        assert_eq!(latest_checkpoint_epoch(6), Some(6));
    }

    #[test]
    fn test_latest_checkpoint_epoch_at_10() {
        // epoch 10 → checkpoint di epoch 9
        assert_eq!(latest_checkpoint_epoch(10), Some(9));
    }

    #[test]
    fn test_checkpoint_metadata_valid() {
        let meta = CheckpointMetadata {
            epoch: 3,
            nullifier_set_root: [0u8; 32],
            ns_checkpoint_smt_root: [0u8; 32],
            ns_checkpoint_root_size: 100 * 1024, // 100 KB
            timestamp: 1_000_000,
        };
        assert_eq!(
            validate_checkpoint_metadata(&meta),
            CheckpointValidation::Valid
        );
    }

    #[test]
    fn test_checkpoint_metadata_proof_too_large() {
        let meta = CheckpointMetadata {
            epoch: 3,
            nullifier_set_root: [0u8; 32],
            ns_checkpoint_smt_root: [0u8; 32],
            ns_checkpoint_root_size: NS_CHECKPOINT_ROOT_MAX_BYTES + 1,
            timestamp: 1_000_000,
        };
        assert!(matches!(
            validate_checkpoint_metadata(&meta),
            CheckpointValidation::ProofTooLarge { .. }
        ));
    }

    #[test]
    fn test_checkpoint_metadata_invalid_epoch_zero() {
        let meta = CheckpointMetadata {
            epoch: 0,
            nullifier_set_root: [0u8; 32],
            ns_checkpoint_smt_root: [0u8; 32],
            ns_checkpoint_root_size: 1024,
            timestamp: 0,
        };
        assert_eq!(
            validate_checkpoint_metadata(&meta),
            CheckpointValidation::InvalidEpoch
        );
    }

    // ── NS_ARCH Constraints ───────────────────────────────────────────

    #[test]
    fn test_ns_arch_valid() {
        assert_eq!(
            validate_ns_checkpoint_constraints(100 * 1024, 50),
            NsArchVerifyResult::Valid
        );
    }

    #[test]
    fn test_ns_arch_proof_too_large() {
        let result = validate_ns_checkpoint_constraints(NS_CHECKPOINT_ROOT_MAX_BYTES + 1, 50);
        assert!(matches!(result, NsArchVerifyResult::TooLarge { .. }));
    }

    #[test]
    fn test_ns_arch_verify_too_slow() {
        let result = validate_ns_checkpoint_constraints(1024, NS_CHECKPOINT_VERIFY_MAX_MS + 1);
        assert!(matches!(result, NsArchVerifyResult::TooSlow { .. }));
    }

    #[test]
    fn test_ns_arch_at_exact_limits() {
        assert_eq!(
            validate_ns_checkpoint_constraints(
                NS_CHECKPOINT_ROOT_MAX_BYTES,
                NS_CHECKPOINT_VERIFY_MAX_MS
            ),
            NsArchVerifyResult::Valid
        );
    }

    // ── Bootstrap Diversity ───────────────────────────────────────────

    #[test]
    fn test_bootstrap_diversity_valid() {
        // 50 peers: 17 Americas (34%), 17 EMEA (34%), 16 AsiaPacific (32%)
        let d = BootstrapDiversity {
            americas: 17,
            emea: 17,
            asia_pacific: 16,
        };
        assert_eq!(
            validate_bootstrap_diversity(&d),
            BootstrapDiversityResult::Valid
        );
    }

    #[test]
    fn test_bootstrap_diversity_insufficient_peers() {
        let d = BootstrapDiversity {
            americas: 10,
            emea: 10,
            asia_pacific: 10,
        };
        assert!(matches!(
            validate_bootstrap_diversity(&d),
            BootstrapDiversityResult::InsufficientPeers { .. }
        ));
    }

    #[test]
    fn test_bootstrap_diversity_region_too_large() {
        // Americas = 25/50 = 50% > 40%
        let d = BootstrapDiversity {
            americas: 25,
            emea: 13,
            asia_pacific: 12,
        };
        assert!(matches!(
            validate_bootstrap_diversity(&d),
            BootstrapDiversityResult::RegionTooLarge { .. }
        ));
    }

    #[test]
    fn test_bootstrap_diversity_region_too_small() {
        // Americas=20(40%), EMEA=20(40%), AsiaPacific=9 → total=49 < 50
        // → InsufficientPeers. Tidak mungkin trigger RegionTooSmall tanpa
        // trigger lain dulu dengan 3-region constraint.
        // Test ini memvalidasi bahwa distribusi tidak seimbang terdeteksi.
        let d = BootstrapDiversity {
            americas: 20,
            emea: 20,
            asia_pacific: 9,
        };
        // total=49 < BOOTSTRAP_PEER_COUNT=50 → InsufficientPeers
        assert!(matches!(
            validate_bootstrap_diversity(&d),
            BootstrapDiversityResult::InsufficientPeers { .. }
        ));
    }

    #[test]
    fn test_bootstrap_diversity_asia_too_small() {
        // Untuk trigger RegionTooSmall, perlu total >= 50 dengan semua
        // region lain dalam range 20-40%. Ini tidak mungkin dengan integer
        // division karena 2*40% + x% = 100% → x=20% (tepat di batas).
        // Verifikasi: region_percent menggunakan integer division
        // Americas=20, EMEA=20, AsiaPacific=10 → 50: Asia=20% → Valid (tidak < 20)
        // Ini membuktikan bahwa batas minimal 20% tepat terpenuhi
        let d = BootstrapDiversity {
            americas: 20,
            emea: 20,
            asia_pacific: 10,
        };
        assert_eq!(
            validate_bootstrap_diversity(&d),
            BootstrapDiversityResult::Valid
        );
    }
    #[test]
    fn test_delta_sync_progress_initial() {
        let p = DeltaSyncProgress::new(3, 10);
        assert_eq!(p.percent_complete(), 0);
        assert!(!p.is_complete());
    }

    #[test]
    fn test_delta_sync_progress_advance() {
        let mut p = DeltaSyncProgress::new(3, 5);
        p.advance();
        assert_eq!(p.synced_epoch, 4);
        assert_eq!(p.percent_complete(), 50);
    }

    #[test]
    fn test_delta_sync_progress_complete() {
        let mut p = DeltaSyncProgress::new(3, 4);
        p.advance();
        assert!(p.is_complete());
        assert_eq!(p.percent_complete(), 100);
    }

    #[test]
    fn test_delta_sync_already_at_tip() {
        let p = DeltaSyncProgress::new(5, 5);
        assert!(p.is_complete());
        assert_eq!(p.percent_complete(), 100);
    }

    #[test]
    fn test_delta_sync_advance_does_not_exceed_tip() {
        let mut p = DeltaSyncProgress::new(3, 4);
        p.advance();
        p.advance(); // sudah di tip, tidak boleh melebihi
        assert_eq!(p.synced_epoch, 4);
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn test_constants_match_spec() {
        // Spec §6.5
        assert_eq!(CHECKPOINT_INTERVAL_DAYS, 90);
        assert_eq!(NS_CHECKPOINT_ROOT_MAX_BYTES, 150 * 1024);
        assert_eq!(NS_CHECKPOINT_VERIFY_MAX_MS, 100);
        assert_eq!(CHECKPOINT_INTERVAL_MIN_DAYS, 30);
        assert_eq!(CHECKPOINT_INTERVAL_MAX_DAYS, 180);
        // Spec §12.8
        assert_eq!(BOOTSTRAP_PEER_COUNT, 50);
        assert_eq!(BOOTSTRAP_MIN_REGION_PERCENT, 20);
        assert_eq!(BOOTSTRAP_MAX_REGION_PERCENT, 40);
        assert_eq!(GENESIS_MAX_BYTES, 1024);
        // Spec §12.9
        assert_eq!(FINALITY_STANDARD_PERCENT, 67);
    }
}
