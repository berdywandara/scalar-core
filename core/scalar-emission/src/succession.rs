//! Succession Protocol — Spec §10.4
//!
//! Mekanisme recovery node jika operator tidak bisa melanjutkan operasi.
//!
//! PREVENTIF (dibuat saat primary masih aktif):
//!   SuccessionProof: node_id_primary, node_id_backup, commitment_epoch,
//!                    sig_primary, sig_backup
//!
//! KLAIM (saat primary tidak bisa operasi):
//!   SuccessionClaim: node_id_backup, claim_epoch, succession_proof,
//!                    sig_claim, fee_paid_sscl
//!
//! TIMELOCK: 1 epoch (30 hari) setelah claim
//! DECAY: 85% maturity ditransfer ke backup (15% hilang sebagai penalty)
//! CANCEL: Primary bisa cancel selama timelock jika masih aktif
//! ANTI-SPAM: Minimum fee SUCCESSION_ANTI_SPAM_FEE_SSCL = 10_000 sSCL

use std::collections::HashMap;

// ── Constants — Spec §10.4 ────────────────────────────────────────────────────

/// Anti-spam fee minimum untuk SuccessionClaim. Spec §10.4. Layer 2 CONSTRAINED.
/// Default: 10_000 sSCL. Range: 1_000-100_000 sSCL.
pub const SUCCESSION_ANTI_SPAM_FEE_SSCL: u64 = 10_000;

/// Timelock succession dalam epoch. Spec §10.4: 1 epoch = 30 hari.
/// Layer 2 CONSTRAINED. Range: 7-90 hari (~1-3 epoch).
pub const SUCCESSION_TIMELOCK_EPOCHS: u64 = 1;

/// Maturity yang ditransfer ke backup (85%). Spec §10.4. Layer 2 CONSTRAINED.
/// Fixed-point basis 1_000_000. 85% = 850_000.
pub const SUCCESSION_MATURITY_TRANSFER_FP: u64 = 850_000;

/// Fixed-point basis. Spec §7.3.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

// ── SuccessionProof — Spec §10.4 ─────────────────────────────────────────────

/// Bukti preventif succession. Dibuat saat primary masih aktif. Spec §10.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessionProof {
    /// NodeID yang akan digantikan (primary). Spec §10.4.
    pub node_id_primary: [u8; 32],
    /// NodeID pengganti (backup). Spec §10.4.
    pub node_id_backup: [u8; 32],
    /// Epoch saat proof dibuat. Spec §10.4.
    pub commitment_epoch: u64,
    /// SPHINCS+ signature dari NodeKey_primary. Spec §10.4.
    pub sig_primary: Vec<u8>,
    /// SPHINCS+ signature dari NodeKey_backup. Spec §10.4.
    pub sig_backup: Vec<u8>,
}

// ── SuccessionClaim — Spec §10.4 ─────────────────────────────────────────────

/// Klaim succession saat primary tidak bisa operasi. Spec §10.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessionClaim {
    /// NodeID backup yang mengajukan klaim. Spec §10.4.
    pub node_id_backup: [u8; 32],
    /// Epoch saat klaim diajukan. Spec §10.4.
    pub claim_epoch: u64,
    /// Bukti succession preventif. Spec §10.4.
    pub succession_proof: SuccessionProof,
    /// SPHINCS+ signature dari NodeKey_backup. Spec §10.4.
    pub sig_claim: Vec<u8>,
    /// Fee anti-spam yang dibayar. Harus ≥ SUCCESSION_ANTI_SPAM_FEE_SSCL.
    pub fee_paid_sscl: u64,
}

// ── Error ────────────────────────────────────────────────────────────────────

/// Error operasi succession. Spec §10.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessionError {
    /// Fee anti-spam kurang dari minimum. Spec §10.4.
    InsufficientFee { paid: u64, required: u64 },
    /// Backup node ID di claim tidak cocok dengan proof. Spec §10.4.
    BackupNodeMismatch,
    /// Klaim sudah ada untuk primary ini.
    ClaimAlreadyExists,
    /// Klaim tidak ditemukan.
    ClaimNotFound,
    /// Timelock belum selesai — belum bisa dieksekusi. Spec §10.4.
    TimelockNotExpired {
        claim_epoch: u64,
        current_epoch: u64,
    },
    /// Klaim sudah dibatalkan oleh primary. Spec §10.4.
    ClaimCancelled,
    /// Klaim sudah dieksekusi.
    ClaimAlreadyExecuted,
}

impl core::fmt::Display for SuccessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientFee { paid, required } => {
                write!(f, "Fee anti-spam kurang: {paid} < {required} (spec §10.4)")
            }
            Self::BackupNodeMismatch => write!(f, "Backup node ID tidak cocok dengan proof"),
            Self::ClaimAlreadyExists => write!(f, "Klaim sudah ada untuk primary ini"),
            Self::ClaimNotFound => write!(f, "Klaim tidak ditemukan"),
            Self::TimelockNotExpired { claim_epoch, current_epoch } => write!(
                f,
                "Timelock belum selesai: claim={claim_epoch}, current={current_epoch}, perlu +{SUCCESSION_TIMELOCK_EPOCHS}"
            ),
            Self::ClaimCancelled => write!(f, "Klaim dibatalkan oleh primary"),
            Self::ClaimAlreadyExecuted => write!(f, "Klaim sudah dieksekusi"),
        }
    }
}

// ── ClaimStatus ───────────────────────────────────────────────────────────────

/// Status SuccessionClaim. Spec §10.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimStatus {
    /// Klaim aktif, dalam timelock. Spec §10.4.
    Pending,
    /// Klaim dibatalkan oleh primary. Spec §10.4.
    Cancelled,
    /// Klaim berhasil dieksekusi setelah timelock. Spec §10.4.
    Executed,
}

/// Entry klaim dalam store.
#[derive(Debug, Clone)]
pub struct ClaimEntry {
    pub claim: SuccessionClaim,
    pub status: ClaimStatus,
}

// ── SuccessionStore — Spec §16.1 ─────────────────────────────────────────────

/// Store semua succession claims aktif. Spec §16.1.
#[derive(Default)]
pub struct SuccessionStore {
    /// Key: node_id_primary → ClaimEntry
    claims: HashMap<[u8; 32], ClaimEntry>,
}

impl SuccessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validasi dan simpan SuccessionClaim. Spec §10.4.
    ///
    /// Validasi:
    /// 1. fee_paid_sscl ≥ SUCCESSION_ANTI_SPAM_FEE_SSCL
    /// 2. claim.node_id_backup == proof.node_id_backup
    /// 3. Tidak ada klaim aktif untuk primary yang sama
    pub fn submit_claim(&mut self, claim: SuccessionClaim) -> Result<(), SuccessionError> {
        // Anti-spam fee check — spec §10.4
        if claim.fee_paid_sscl < SUCCESSION_ANTI_SPAM_FEE_SSCL {
            return Err(SuccessionError::InsufficientFee {
                paid: claim.fee_paid_sscl,
                required: SUCCESSION_ANTI_SPAM_FEE_SSCL,
            });
        }
        // Backup node harus cocok dengan proof — spec §10.4
        if claim.node_id_backup != claim.succession_proof.node_id_backup {
            return Err(SuccessionError::BackupNodeMismatch);
        }
        // Tidak ada klaim aktif untuk primary yang sama
        let primary_id = claim.succession_proof.node_id_primary;
        if let Some(existing) = self.claims.get(&primary_id) {
            if existing.status == ClaimStatus::Pending {
                return Err(SuccessionError::ClaimAlreadyExists);
            }
        }
        self.claims.insert(
            primary_id,
            ClaimEntry {
                claim,
                status: ClaimStatus::Pending,
            },
        );
        Ok(())
    }

    /// Primary cancel klaim selama timelock. Spec §10.4.
    /// Primary bisa cancel jika masih aktif.
    pub fn cancel_claim(&mut self, primary_id: &[u8; 32]) -> Result<(), SuccessionError> {
        let entry = self
            .claims
            .get_mut(primary_id)
            .ok_or(SuccessionError::ClaimNotFound)?;
        match entry.status {
            ClaimStatus::Cancelled => Err(SuccessionError::ClaimCancelled),
            ClaimStatus::Executed => Err(SuccessionError::ClaimAlreadyExecuted),
            ClaimStatus::Pending => {
                entry.status = ClaimStatus::Cancelled;
                Ok(())
            }
        }
    }

    /// Execute succession setelah timelock selesai. Spec §10.4.
    ///
    /// Transfer 85% maturity dari primary ke backup.
    /// 15% hilang sebagai penalty gap.
    ///
    /// `maturity_store`: map node_id → maturity_value.
    pub fn execute_succession(
        &mut self,
        primary_id: &[u8; 32],
        current_epoch: u64,
        maturity_store: &mut HashMap<[u8; 32], u64>,
    ) -> Result<[u8; 32], SuccessionError> {
        let entry = self
            .claims
            .get_mut(primary_id)
            .ok_or(SuccessionError::ClaimNotFound)?;

        match entry.status {
            ClaimStatus::Cancelled => return Err(SuccessionError::ClaimCancelled),
            ClaimStatus::Executed => return Err(SuccessionError::ClaimAlreadyExecuted),
            ClaimStatus::Pending => {}
        }

        // Timelock check — spec §10.4: 1 epoch setelah claim
        let claim_epoch = entry.claim.claim_epoch;
        if current_epoch < claim_epoch + SUCCESSION_TIMELOCK_EPOCHS {
            return Err(SuccessionError::TimelockNotExpired {
                claim_epoch,
                current_epoch,
            });
        }

        let backup_id = entry.claim.node_id_backup;

        // Apply 85% maturity transfer — spec §10.4
        // transferred = primary_maturity × 850_000 / 1_000_000
        let primary_maturity = maturity_store.get(primary_id).copied().unwrap_or(0);
        let transferred =
            primary_maturity.saturating_mul(SUCCESSION_MATURITY_TRANSFER_FP) / FIXED_POINT_BASIS;

        // Reset primary maturity ke 0
        maturity_store.insert(*primary_id, 0);
        // Tambahkan ke backup
        let backup_current = maturity_store.get(&backup_id).copied().unwrap_or(0);
        maturity_store.insert(backup_id, backup_current.saturating_add(transferred));

        entry.status = ClaimStatus::Executed;
        Ok(backup_id)
    }

    /// Cek status klaim untuk primary.
    pub fn claim_status(&self, primary_id: &[u8; 32]) -> Option<&ClaimStatus> {
        self.claims.get(primary_id).map(|e| &e.status)
    }

    /// Jumlah klaim aktif (Pending).
    pub fn pending_count(&self) -> usize {
        self.claims
            .values()
            .filter(|e| e.status == ClaimStatus::Pending)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    fn make_proof(primary_b: u8, backup_b: u8, epoch: u64) -> SuccessionProof {
        SuccessionProof {
            node_id_primary: node(primary_b),
            node_id_backup: node(backup_b),
            commitment_epoch: epoch,
            sig_primary: vec![0u8; 8],
            sig_backup: vec![0u8; 8],
        }
    }

    fn make_claim(primary_b: u8, backup_b: u8, claim_epoch: u64, fee: u64) -> SuccessionClaim {
        SuccessionClaim {
            node_id_backup: node(backup_b),
            claim_epoch,
            succession_proof: make_proof(primary_b, backup_b, claim_epoch),
            sig_claim: vec![0u8; 8],
            fee_paid_sscl: fee,
        }
    }

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn test_anti_spam_fee_is_10000() {
        // Spec §10.4: SUCCESSION_ANTI_SPAM_FEE_SSCL = 10_000 sSCL. Layer 2 CONSTRAINED.
        assert_eq!(SUCCESSION_ANTI_SPAM_FEE_SSCL, 10_000u64);
    }

    #[test]
    fn test_timelock_is_1_epoch() {
        // Spec §10.4: timelock = 1 epoch (30 hari). Layer 2 CONSTRAINED.
        assert_eq!(SUCCESSION_TIMELOCK_EPOCHS, 1u64);
    }

    #[test]
    fn test_maturity_transfer_is_85_percent() {
        // Spec §10.4: 85% maturity ditransfer. Layer 2 CONSTRAINED.
        assert_eq!(SUCCESSION_MATURITY_TRANSFER_FP, 850_000u64);
    }

    // ── submit_claim ─────────────────────────────────────────────────────────

    #[test]
    fn test_valid_claim_accepted() {
        let mut store = SuccessionStore::new();
        let claim = make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL);
        assert!(store.submit_claim(claim).is_ok());
        assert_eq!(store.pending_count(), 1);
    }

    #[test]
    fn test_insufficient_fee_rejected() {
        // Spec §10.4: fee < 10_000 → rejected.
        let mut store = SuccessionStore::new();
        let claim = make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL - 1);
        let err = store.submit_claim(claim).unwrap_err();
        assert_eq!(
            err,
            SuccessionError::InsufficientFee {
                paid: 9_999,
                required: 10_000
            }
        );
    }

    #[test]
    fn test_backup_node_mismatch_rejected() {
        // backup_id di claim ≠ backup_id di proof → rejected.
        let mut store = SuccessionStore::new();
        let mut claim = make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL);
        claim.node_id_backup = node(3); // berbeda dari proof
        let err = store.submit_claim(claim).unwrap_err();
        assert_eq!(err, SuccessionError::BackupNodeMismatch);
    }

    #[test]
    fn test_duplicate_claim_for_same_primary_rejected() {
        let mut store = SuccessionStore::new();
        let claim1 = make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL);
        let claim2 = make_claim(1, 3, 11, SUCCESSION_ANTI_SPAM_FEE_SSCL);
        store.submit_claim(claim1).unwrap();
        let err = store.submit_claim(claim2).unwrap_err();
        assert_eq!(err, SuccessionError::ClaimAlreadyExists);
    }

    // ── cancel_claim ─────────────────────────────────────────────────────────

    #[test]
    fn test_primary_can_cancel_during_timelock() {
        // Spec §10.4: primary bisa cancel selama timelock.
        let mut store = SuccessionStore::new();
        store
            .submit_claim(make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL))
            .unwrap();
        assert!(store.cancel_claim(&node(1)).is_ok());
        assert_eq!(store.claim_status(&node(1)), Some(&ClaimStatus::Cancelled));
    }

    #[test]
    fn test_cancel_nonexistent_claim_fails() {
        let mut store = SuccessionStore::new();
        let err = store.cancel_claim(&node(99)).unwrap_err();
        assert_eq!(err, SuccessionError::ClaimNotFound);
    }

    // ── execute_succession ───────────────────────────────────────────────────

    #[test]
    fn test_execute_after_timelock_succeeds() {
        // Spec §10.4: execute setelah timelock selesai.
        let mut store = SuccessionStore::new();
        store
            .submit_claim(make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL))
            .unwrap();
        let mut maturity: HashMap<[u8; 32], u64> = HashMap::new();
        maturity.insert(node(1), 1_000_000);

        // current_epoch = 10 + 1 = 11 → timelock selesai
        let backup_id = store
            .execute_succession(&node(1), 11, &mut maturity)
            .unwrap();
        assert_eq!(backup_id, node(2));
        assert_eq!(store.claim_status(&node(1)), Some(&ClaimStatus::Executed));
    }

    #[test]
    fn test_execute_before_timelock_fails() {
        // Spec §10.4: tidak bisa execute sebelum timelock selesai.
        let mut store = SuccessionStore::new();
        store
            .submit_claim(make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL))
            .unwrap();
        let mut maturity: HashMap<[u8; 32], u64> = HashMap::new();
        // current_epoch = 10 → belum cukup (butuh ≥ 11)
        let err = store
            .execute_succession(&node(1), 10, &mut maturity)
            .unwrap_err();
        assert_eq!(
            err,
            SuccessionError::TimelockNotExpired {
                claim_epoch: 10,
                current_epoch: 10
            }
        );
    }

    #[test]
    fn test_maturity_decay_85_percent_transfer() {
        // Spec §10.4: 85% ditransfer, 15% hilang.
        let mut store = SuccessionStore::new();
        store
            .submit_claim(make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL))
            .unwrap();
        let mut maturity: HashMap<[u8; 32], u64> = HashMap::new();
        maturity.insert(node(1), 1_000_000); // primary maturity

        store
            .execute_succession(&node(1), 11, &mut maturity)
            .unwrap();

        // Primary di-reset ke 0
        assert_eq!(*maturity.get(&node(1)).unwrap(), 0);
        // Backup mendapat 85% = 850_000
        assert_eq!(*maturity.get(&node(2)).unwrap(), 850_000);
    }

    #[test]
    fn test_maturity_penalty_15_percent_lost() {
        // 15% hilang — tidak ada ke mana-mana (penalty gap). Spec §10.4.
        let mut store = SuccessionStore::new();
        store
            .submit_claim(make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL))
            .unwrap();
        let mut maturity: HashMap<[u8; 32], u64> = HashMap::new();
        maturity.insert(node(1), 1_000_000);
        store
            .execute_succession(&node(1), 11, &mut maturity)
            .unwrap();

        let primary = *maturity.get(&node(1)).unwrap();
        let backup = *maturity.get(&node(2)).unwrap();
        assert_eq!(primary + backup, 850_000); // total = 85%, 15% hilang
    }

    #[test]
    fn test_execute_cancelled_claim_fails() {
        let mut store = SuccessionStore::new();
        store
            .submit_claim(make_claim(1, 2, 10, SUCCESSION_ANTI_SPAM_FEE_SSCL))
            .unwrap();
        store.cancel_claim(&node(1)).unwrap();
        let mut maturity: HashMap<[u8; 32], u64> = HashMap::new();
        let err = store
            .execute_succession(&node(1), 11, &mut maturity)
            .unwrap_err();
        assert_eq!(err, SuccessionError::ClaimCancelled);
    }

    #[test]
    fn test_no_floating_point() {
        // Semua kalkulasi murni integer.
        let transferred =
            1_000_000u64.saturating_mul(SUCCESSION_MATURITY_TRANSFER_FP) / FIXED_POINT_BASIS;
        assert_eq!(transferred, 850_000);
    }
}
