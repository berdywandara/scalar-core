// File: crates/scalar-stark/src/air.rs
//
// Transfer Circuit Public Input v5.0 — Spec §4.2, §4.3, §4.4
// Delta dari v3.0:
//   + entry_timestamp : u64  — C10 censorship resistance
//   + crypto_version  : u8   — C9 version compatibility
// Constraint counts sesuai spec §4.4:
//   2-in/2-out  = ~40,650
//   10-in/10-out = ~202,000

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Constraint counts per komponen (OSSIFIED §4.4) ───────────────────
pub const CONSTRAINTS_C1_PER_INPUT: usize = 200;
pub const CONSTRAINTS_C2_PER_INPUT: usize = 200;
/// SMT depth-32 genesis membership. Spec §4.3 C3.
pub const CONSTRAINTS_C3_PER_INPUT: usize = 6_464;
/// SMT depth-32 non-membership. Spec §4.3 C4.
pub const CONSTRAINTS_C4_PER_INPUT: usize = 12_800;
pub const CONSTRAINTS_C5: usize = 10;
/// Range proof via bit decomposition. Spec §4.3 C6.
pub const CONSTRAINTS_C6_PER_VALUE: usize = 163;
pub const CONSTRAINTS_C7_PER_OUTPUT: usize = 200;
/// In-circuit authorization. Spec §4.3 C8.
pub const CONSTRAINTS_C8: usize = 200;
/// Version compatibility. Spec §4.3 C9.
pub const CONSTRAINTS_C9: usize = 10;
/// Censorship resistance. Spec §4.3 C10.
pub const CONSTRAINTS_C10: usize = 50;

/// T_MAX_WAIT = 30 menit dalam milidetik. Layer 2 CONSTRAINED. Spec §4.3 C10.
pub const T_MAX_WAIT_MS: u64 = 30 * 60 * 1_000; // 1_800_000 ms

pub const VALID_CRYPTO_VERSIONS: [u8; 1] = [0x01];

// ── Public Input Transfer Circuit v5.0 ───────────────────────────────
/// Public Input Transfer Circuit v5.0.
/// Spec §4.2 — dua field baru vs v3.0:
///   + entry_timestamp : C10 censorship resistance
///   + crypto_version  : C9 version compatibility
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferCircuitPublicInput {
    /// C9: versi kriptografi aktif. Harus ∈ valid_versions(current_epoch).
    pub crypto_version: u8,
    /// C10: waktu tx masuk pool (unix ms). Enforce T_MAX_WAIT.
    pub entry_timestamp: u64,
    /// Unix timestamp saat proving.
    pub current_timestamp: u64,
}

/// Public Input lengkap untuk verifier node — digunakan oleh scalar-node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarPublicInputs {
    pub genesis_smt_root: u64,
    pub current_nullifier_smt_root: u64,
    pub fee_value: u64,
    pub timestamp: u64,
    /// C10: waktu tx masuk pool
    pub entry_timestamp: u64,
    /// C9: versi kriptografi
    pub crypto_version: u8,
}

/// Private Witness — WAJIB di-zeroize dari RAM setelah digunakan.
/// Spec §2.4: immediate zeroize setelah signing.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TransferWitness {
    pub(crate) secret_key: [u8; 32],
}

// ── C9: Version Compatibility ─────────────────────────────────────────
/// Verifikasi crypto_version ∈ valid_versions. Spec §4.3 C9 (~10 constraints).
pub fn verify_c9_crypto_version(version: u8) -> Result<(), &'static str> {
    if VALID_CRYPTO_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err("Constraint C9 FAIL: crypto_version tidak valid atau sudah deprecated")
    }
}

// ── C10: Censorship Resistance ────────────────────────────────────────
/// C10: Tx harus diproses dalam T_MAX_WAIT dari entry_timestamp.
/// Spec §4.3 C10: T_MAX_WAIT = 30 menit (1_800_000 ms).
/// Returns true jika tx masih dalam window yang diizinkan.
pub fn verify_c10_tx_within_wait_window(entry_ts_ms: u64, current_ts_ms: u64) -> bool {
    if current_ts_ms < entry_ts_ms {
        return false;
    }
    (current_ts_ms - entry_ts_ms) <= T_MAX_WAIT_MS
}

/// C10: Cek apakah tx sudah expired — aggregator yang exclude tx expired melanggar C10.
pub fn is_tx_censorship_expired(entry_ts_ms: u64, current_ts_ms: u64) -> bool {
    if current_ts_ms < entry_ts_ms {
        return false;
    }
    (current_ts_ms - entry_ts_ms) > T_MAX_WAIT_MS
}

// ── Constraint count ──────────────────────────────────────────────────
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

    // ── C9 ────────────────────────────────────────────────────────────

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

    // ── C10 ───────────────────────────────────────────────────────────

    #[test]
    fn test_c10_within_window_accepted() {
        let entry = 1_000_000_000u64;
        let current = entry + 1_000_000; // 1000 detik
        assert!(verify_c10_tx_within_wait_window(entry, current));
    }

    #[test]
    fn test_c10_at_exact_boundary_accepted() {
        let entry = 1_000_000_000u64;
        let current = entry + T_MAX_WAIT_MS; // tepat 30 menit
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

    // ── Constraint counts ─────────────────────────────────────────────

    #[test]
    fn test_constraints_2_2_matches_spec() {
        // Spec §4.4: ~40,650 (tilde = approx, toleransi ±200)
        let total = compute_total_constraints(2, 2);
        assert!(
            (40_450..=40_850).contains(&total),
            "2-in/2-out harus ~40_650, dapat {}",
            total
        );
    }

    #[test]
    fn test_constraints_10_10_matches_spec() {
        // Spec §4.4: ~202,000 (tilde = approx, toleransi ±500)
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
    fn test_public_input_v5_has_entry_timestamp_and_crypto_version() {
        let pi = TransferCircuitPublicInput {
            crypto_version: 0x01,
            entry_timestamp: 1_680_000_000_000,
            current_timestamp: 1_680_000_100_000,
        };
        assert_eq!(pi.crypto_version, 0x01);
        assert!(pi.entry_timestamp > 0);
    }

    #[test]
    fn test_scalar_public_inputs_v5_fields() {
        let pi = ScalarPublicInputs {
            genesis_smt_root: 0,
            current_nullifier_smt_root: 1,
            fee_value: 40,
            timestamp: 1_000_060_000,
            entry_timestamp: 1_000_000_000,
            crypto_version: 0x01,
        };
        assert_eq!(pi.crypto_version, 0x01);
        assert_eq!(pi.entry_timestamp, 1_000_000_000);
    }
}
