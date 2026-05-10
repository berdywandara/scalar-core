// File: crates/scalar-stark/src/air.rs
//
// Transfer Circuit Public Input v11.1-FINAL — Spec §4.2, §4.3, §4.4
//
// Delta dari v5.0 (PR-V12-005 FIX):
//   + utxo_set_root : [u8;32] — CB constraint (UTXO Set Membership)
//     Root ini adalah snapshot deterministik dari epoch k-1 yang dihasilkan
//     via canonical transaction ordering (PR-V12-003 + PR-V12-004).
//     ANTI-DOUBLE-SPEND: root TIDAK boleh berasal dari epoch yang sama.
//     Spec §4.2, §4.3 CB, §8.5 v11.1-FINAL.
//
// Constraint counts sesuai spec §4.4:
//   2-in/2-out  = ~40,650
//   10-in/10-out = ~202,000

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Constraint counts per komponen (OSSIFIED §4.4) ────────────────────────────
pub const CONSTRAINTS_C1_PER_INPUT: usize = 200;
pub const CONSTRAINTS_C2_PER_INPUT: usize = 200;
/// SMT depth-32 genesis membership. Spec §4.3 CB (sebelumnya C3).
pub const CONSTRAINTS_C3_PER_INPUT: usize = 6_464;
/// SMT depth-32 non-membership. Spec §4.3 CC (sebelumnya C4).
pub const CONSTRAINTS_C4_PER_INPUT: usize = 12_800;
pub const CONSTRAINTS_C5: usize = 10;
/// Range proof via bit decomposition. Spec §4.3 C6.
pub const CONSTRAINTS_C6_PER_VALUE: usize = 163;
pub const CONSTRAINTS_C7_PER_OUTPUT: usize = 200;
/// In-circuit authorization. Spec §4.3 CF (sebelumnya C8).
pub const CONSTRAINTS_C8: usize = 200;
/// Version compatibility. Spec §4.3 CG (sebelumnya C9).
pub const CONSTRAINTS_C9: usize = 10;
/// Censorship resistance. Spec §4.3 CG (sebelumnya C10).
pub const CONSTRAINTS_C10: usize = 50;

/// T_MAX_WAIT = 30 menit dalam milidetik. Layer 2 CONSTRAINED. Spec §4.3 CG.
pub const T_MAX_WAIT_MS: u64 = 30 * 60 * 1_000; // 1_800_000 ms

pub const VALID_CRYPTO_VERSIONS: [u8; 1] = [0x01];

// ── Public Input Transfer Circuit v11.1-FINAL ────────────────────────────────

/// Public Input Transfer Circuit v11.1-FINAL.
///
/// Spec §4.2 — field baru vs v5.0:
///   + utxo_set_root : [u8;32] — CB: UTXO Set Membership constraint
///
/// CB CONSTRAINT (spec §4.3 CB, §8.5 v11.1-FINAL):
///   utxo_set_root adalah snapshot deterministik dari SMT seluruh UTXO
///   pada akhir epoch k-1, dihasilkan via canonical transaction ordering.
///
///   WAJIB: root dari epoch k-1 (committed), BUKAN dari epoch yang sama (k).
///   Ini mencegah pengeluaran UTXO pada epoch yang sama dengan pembuatannya.
///
///   Verifikasi: MerkleVerify(leaf=input_commitment, path, root=utxo_set_root) == TRUE
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferCircuitPublicInput {
    /// CB: Root SMT dari semua UTXO epoch k-1 (canonical ordering). Spec §4.2, §4.3 CB.
    /// ANTI-DOUBLE-SPEND: harus dari epoch k-1, BUKAN epoch k saat ini.
    /// Dihasilkan via sort_transactions_canonical() — PR-V12-003.
    /// Disimpan via UtxoSetSMT::take_snapshot() — PR-V12-004.
    pub utxo_set_root: [u8; 32],
    /// CG: versi kriptografi aktif. Harus ∈ valid_versions(current_epoch).
    pub crypto_version: u8,
    /// CG: waktu tx masuk pool (unix ms). Enforce T_MAX_WAIT.
    pub entry_timestamp: u64,
    /// Unix timestamp saat proving.
    pub current_timestamp: u64,
}

impl TransferCircuitPublicInput {
    /// Validasi CB constraint: utxo_set_root harus dari epoch k-1. Spec §4.3 CB.
    ///
    /// `snapshot_epoch`: epoch dari mana root diambil.
    /// `current_epoch`: epoch transaksi saat ini (k).
    ///
    /// Returns true jika root valid untuk digunakan dalam transfer di epoch k.
    /// ANTI-DOUBLE-SPEND: snapshot_epoch HARUS == current_epoch - 1.
    pub fn validate_cb_utxo_root_epoch(&self, snapshot_epoch: u64, current_epoch: u64) -> bool {
        // CB constraint: root dari epoch k-1 (committed), bukan epoch k
        // Spec §4.2: "snapshot pada epoch terkomit sebelumnya"
        if current_epoch == 0 {
            // Genesis: epoch 0 menggunakan genesis root
            return snapshot_epoch == 0;
        }
        snapshot_epoch == current_epoch - 1
    }

    /// Verifikasi bahwa utxo_set_root bukan zero (uninitialized). Spec §4.3 CB.
    pub fn validate_cb_root_non_zero(&self) -> bool {
        self.utxo_set_root != [0u8; 32]
    }
}

/// Public Input lengkap untuk verifier node — digunakan oleh scalar-node.
///
/// Diupdate di v11.1-FINAL: tambah utxo_set_root untuk CB constraint.
/// Spec §4.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarPublicInputs {
    /// Legacy genesis root (v5.0). Dipertahankan untuk backward compat.
    pub genesis_smt_root: u64,
    /// CB: UTXO Set Root dari epoch k-1 (canonical ordering). Spec §4.2 v11.1-FINAL.
    /// Menggantikan genesis_smt_root sebagai primary UTXO membership root.
    pub utxo_set_root: [u8; 32],
    pub current_nullifier_smt_root: u64,
    pub fee_value: u64,
    pub timestamp: u64,
    /// CG: waktu tx masuk pool
    pub entry_timestamp: u64,
    /// CG: versi kriptografi
    pub crypto_version: u8,
}

/// Private Witness — WAJIB di-zeroize dari RAM setelah digunakan.
/// Spec §2.4: immediate zeroize setelah signing.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TransferWitness {
    pub(crate) secret_key: [u8; 32],
}

// ── C9/CG: Version Compatibility ─────────────────────────────────────────────

/// Verifikasi crypto_version ∈ valid_versions. Spec §4.3 CG (~10 constraints).
pub fn verify_c9_crypto_version(version: u8) -> Result<(), &'static str> {
    if VALID_CRYPTO_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err("Constraint CG FAIL: crypto_version tidak valid atau sudah deprecated")
    }
}

// ── C10/CG: Censorship Resistance ────────────────────────────────────────────

/// CG: Tx harus diproses dalam T_MAX_WAIT dari entry_timestamp.
/// Spec §4.3 CG: T_MAX_WAIT = 30 menit (1_800_000 ms).
pub fn verify_c10_tx_within_wait_window(entry_ts_ms: u64, current_ts_ms: u64) -> bool {
    if current_ts_ms < entry_ts_ms {
        return false;
    }
    (current_ts_ms - entry_ts_ms) <= T_MAX_WAIT_MS
}

/// CG: Cek apakah tx sudah expired.
pub fn is_tx_censorship_expired(entry_ts_ms: u64, current_ts_ms: u64) -> bool {
    if current_ts_ms < entry_ts_ms {
        return false;
    }
    (current_ts_ms - entry_ts_ms) > T_MAX_WAIT_MS
}

// ── CB: UTXO Set Membership constraint ───────────────────────────────────────

/// Error CB constraint. Spec §4.3 CB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbConstraintError {
    /// utxo_set_root berasal dari epoch yang sama (k) — anti-double-spend violation.
    /// Spec §4.3 CB: root harus dari epoch k-1.
    RootFromCurrentEpoch {
        snapshot_epoch: u64,
        current_epoch: u64,
    },
    /// utxo_set_root adalah zero — tidak diinisialisasi.
    ZeroRoot,
    /// snapshot_epoch lebih baru dari current_epoch — tidak valid.
    FutureSnapshot {
        snapshot_epoch: u64,
        current_epoch: u64,
    },
}

impl core::fmt::Display for CbConstraintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RootFromCurrentEpoch {
                snapshot_epoch,
                current_epoch,
            } => write!(
                f,
                "CB FAIL: utxo_set_root dari epoch {snapshot_epoch} \
                 tidak valid untuk transaksi epoch {current_epoch} \
                 (harus dari epoch k-1={}) — spec §4.3 CB",
                current_epoch - 1
            ),
            Self::ZeroRoot => write!(
                f,
                "CB FAIL: utxo_set_root adalah zero — tidak diinisialisasi — spec §4.3 CB"
            ),
            Self::FutureSnapshot {
                snapshot_epoch,
                current_epoch,
            } => write!(
                f,
                "CB FAIL: snapshot_epoch {snapshot_epoch} > current_epoch {current_epoch} \
                 — root dari masa depan tidak valid"
            ),
        }
    }
}

/// Validasi CB constraint untuk utxo_set_root. Spec §4.3 CB, §8.5 v11.1-FINAL.
///
/// `utxo_set_root`: root yang disuplai pada proof.
/// `snapshot_epoch`: epoch dari mana root diambil (dari UtxoSetState).
/// `current_epoch`: epoch transaksi saat ini (k).
///
/// Verifikasi:
/// 1. utxo_set_root != zero
/// 2. snapshot_epoch == current_epoch - 1 (atau genesis edge case)
/// 3. snapshot_epoch tidak lebih baru dari current_epoch
///
/// Spec §4.2: "utxo_set_root adalah snapshot dari SMT seluruh UTXO pada
/// epoch terkomit sebelumnya — diambil setelah semua transaksi epoch k-1
/// diproses secara deterministik menggunakan canonical transaction ordering."
pub fn validate_cb_utxo_root(
    utxo_set_root: &[u8; 32],
    snapshot_epoch: u64,
    current_epoch: u64,
) -> Result<(), CbConstraintError> {
    // Constraint 1: root tidak boleh zero
    if *utxo_set_root == [0u8; 32] {
        return Err(CbConstraintError::ZeroRoot);
    }

    // Constraint 2: snapshot tidak dari masa depan
    if snapshot_epoch > current_epoch {
        return Err(CbConstraintError::FutureSnapshot {
            snapshot_epoch,
            current_epoch,
        });
    }

    // Constraint 3: root harus dari epoch k-1 (committed epoch sebelumnya)
    // Genesis edge case: epoch 0 boleh pakai snapshot epoch 0
    let expected_snapshot_epoch = if current_epoch == 0 {
        0
    } else {
        current_epoch - 1
    };

    if snapshot_epoch != expected_snapshot_epoch {
        return Err(CbConstraintError::RootFromCurrentEpoch {
            snapshot_epoch,
            current_epoch,
        });
    }

    Ok(())
}

// ── Constraint count ──────────────────────────────────────────────────────────

/// Hitung total constraints berdasarkan jumlah input/output. Spec §4.4.
pub fn compute_total_constraints(num_inputs: usize, num_outputs: usize) -> usize {
    let c1 = CONSTRAINTS_C1_PER_INPUT * num_inputs;
    let c2 = CONSTRAINTS_C2_PER_INPUT * num_inputs;
    let c3 = CONSTRAINTS_C3_PER_INPUT * num_inputs;
    let c4 = CONSTRAINTS_C4_PER_INPUT * num_inputs;
    let c5 = CONSTRAINTS_C5;
    let c6 = CONSTRAINTS_C6_PER_VALUE * (num_inputs + num_outputs);
    let c7 = CONSTRAINTS_C7_PER_OUTPUT * num_outputs;
    let c8 = CONSTRAINTS_C8;
    let c9 = CONSTRAINTS_C9;
    let c10 = CONSTRAINTS_C10;
    c1 + c2 + c3 + c4 + c5 + c6 + c7 + c8 + c9 + c10
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_utxo_root() -> [u8; 32] {
        [0x42u8; 32]
    }

    // ── CG (C9) ───────────────────────────────────────────────────────────────

    #[test]
    fn test_c9_valid_version_accepted() {
        assert!(verify_c9_crypto_version(0x01).is_ok());
    }

    #[test]
    fn test_c9_invalid_version_rejected() {
        assert!(verify_c9_crypto_version(0x00).is_err());
        assert!(verify_c9_crypto_version(0xFF).is_err());
        assert!(verify_c9_crypto_version(0x02).is_err());
    }

    // ── CG (C10) ──────────────────────────────────────────────────────────────

    #[test]
    fn test_c10_within_window_accepted() {
        let entry = 1_000_000_000u64;
        let current = entry + 1_000_000;
        assert!(verify_c10_tx_within_wait_window(entry, current));
    }

    #[test]
    fn test_c10_at_exact_boundary_accepted() {
        let entry = 1_000_000_000u64;
        let current = entry + T_MAX_WAIT_MS;
        assert!(verify_c10_tx_within_wait_window(entry, current));
    }

    #[test]
    fn test_c10_past_boundary_rejected() {
        let entry = 1_000_000_000u64;
        let current = entry + T_MAX_WAIT_MS + 1;
        assert!(!verify_c10_tx_within_wait_window(entry, current));
    }

    #[test]
    fn test_c10_future_entry_timestamp_rejected() {
        let entry = 2_000_000_000u64;
        let current = 1_000_000_000u64;
        assert!(!verify_c10_tx_within_wait_window(entry, current));
    }

    #[test]
    fn test_c10_expired_tx_flagged() {
        let entry = 1_000_000_000u64;
        let current = entry + T_MAX_WAIT_MS + 60_000;
        assert!(is_tx_censorship_expired(entry, current));
    }

    #[test]
    fn test_c10_non_expired_tx_not_flagged() {
        let entry = 1_000_000_000u64;
        let current = entry + 60_000;
        assert!(!is_tx_censorship_expired(entry, current));
    }

    // ── CB: UTXO Set Root ─────────────────────────────────────────────────────

    #[test]
    fn test_transfer_cb_utxo_root_correct_epoch() {
        // Root dari epoch k-1 diterima. Spec §4.3 CB.
        let root = valid_utxo_root();
        let result = validate_cb_utxo_root(&root, 4, 5); // snapshot=4, current=5
        assert!(
            result.is_ok(),
            "Root dari epoch k-1 harus diterima: {:?}",
            result
        );
    }

    #[test]
    fn test_transfer_cb_utxo_root_from_current_epoch_rejected() {
        // Root dari epoch k (sama) harus ditolak. Spec §4.3 CB.
        // ANTI-DOUBLE-SPEND: tidak boleh spending UTXO yang dibuat epoch yang sama.
        let root = valid_utxo_root();
        let result = validate_cb_utxo_root(&root, 5, 5); // snapshot=5 = current → REJECT
        assert!(
            matches!(result, Err(CbConstraintError::RootFromCurrentEpoch { .. })),
            "Root dari epoch yang sama harus ditolak — anti-double-spend"
        );
    }

    #[test]
    fn test_transfer_cb_zero_root_rejected() {
        // Zero root → tidak diinisialisasi → ditolak. Spec §4.3 CB.
        let zero_root = [0u8; 32];
        let result = validate_cb_utxo_root(&zero_root, 4, 5);
        assert_eq!(result, Err(CbConstraintError::ZeroRoot));
    }

    #[test]
    fn test_transfer_cb_future_snapshot_rejected() {
        // snapshot_epoch > current_epoch → invalid. Spec §4.3 CB.
        let root = valid_utxo_root();
        let result = validate_cb_utxo_root(&root, 6, 5); // snapshot=6 > current=5
        assert!(matches!(
            result,
            Err(CbConstraintError::FutureSnapshot { .. })
        ));
    }

    #[test]
    fn test_transfer_cb_genesis_epoch_accepted() {
        // Genesis (epoch 0): snapshot_epoch = 0, current_epoch = 0. Spec §4.3 CB.
        let root = valid_utxo_root();
        let result = validate_cb_utxo_root(&root, 0, 0);
        assert!(result.is_ok(), "Genesis epoch harus diterima: {:?}", result);
    }

    #[test]
    fn test_transfer_cb_epoch_1_uses_snapshot_0() {
        // Epoch 1: snapshot dari epoch 0 (genesis). Spec §4.3 CB.
        let root = valid_utxo_root();
        let result = validate_cb_utxo_root(&root, 0, 1);
        assert!(result.is_ok(), "Epoch 1 harus menggunakan snapshot epoch 0");
    }

    // ── TransferCircuitPublicInput CB methods ─────────────────────────────────

    #[test]
    fn test_transfer_proof_valid_with_canonical_root() {
        // Proof valid dengan utxo_set_root dari canonical ordering. Spec §4.3 CB.
        let pi = TransferCircuitPublicInput {
            utxo_set_root: valid_utxo_root(),
            crypto_version: 0x01,
            entry_timestamp: 1_000_000_000,
            current_timestamp: 1_000_001_000,
        };
        assert!(pi.validate_cb_utxo_root_epoch(4, 5));
        assert!(pi.validate_cb_root_non_zero());
    }

    #[test]
    fn regression_test_utxo_root_not_current_epoch() {
        // Regression: spending dari epoch sama → proof invalid. Spec §4.3 CB.
        let pi = TransferCircuitPublicInput {
            utxo_set_root: valid_utxo_root(),
            crypto_version: 0x01,
            entry_timestamp: 1_000_000_000,
            current_timestamp: 1_000_001_000,
        };
        // snapshot_epoch == current_epoch → harus ditolak
        assert!(
            !pi.validate_cb_utxo_root_epoch(5, 5),
            "Spending dari epoch yang sama harus ditolak"
        );
    }

    #[test]
    fn test_scalar_public_inputs_has_utxo_set_root() {
        // ScalarPublicInputs harus punya utxo_set_root. Spec §4.2 v11.1-FINAL.
        let pi = ScalarPublicInputs {
            genesis_smt_root: 0,
            utxo_set_root: valid_utxo_root(),
            current_nullifier_smt_root: 1,
            fee_value: 40,
            timestamp: 1_000_060_000,
            entry_timestamp: 1_000_000_000,
            crypto_version: 0x01,
        };
        assert_eq!(
            pi.utxo_set_root,
            valid_utxo_root(),
            "utxo_set_root harus ada di ScalarPublicInputs"
        );
    }

    // ── Constraint counts ─────────────────────────────────────────────────────

    #[test]
    fn test_constraints_2_2_matches_spec() {
        let total = compute_total_constraints(2, 2);
        assert!(
            (40_450..=40_850).contains(&total),
            "2-in/2-out harus ~40_650, dapat {}",
            total
        );
    }

    #[test]
    fn test_constraints_10_10_matches_spec() {
        let total = compute_total_constraints(10, 10);
        assert!(
            (201_500..=202_500).contains(&total),
            "10-in/10-out harus ~202_000, dapat {}",
            total
        );
    }

    #[test]
    fn test_t_max_wait_is_30_minutes() {
        assert_eq!(T_MAX_WAIT_MS, 1_800_000);
    }

    #[test]
    fn test_public_input_v12_has_utxo_set_root_field() {
        // v11.1-FINAL: TransferCircuitPublicInput harus punya utxo_set_root.
        let pi = TransferCircuitPublicInput {
            utxo_set_root: [0xABu8; 32],
            crypto_version: 0x01,
            entry_timestamp: 1_680_000_000_000,
            current_timestamp: 1_680_000_100_000,
        };
        assert_eq!(pi.utxo_set_root, [0xABu8; 32]);
        assert_eq!(pi.crypto_version, 0x01);
    }
}
