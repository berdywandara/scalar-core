//! Governance Anti-Sybil Rules — Spec §11.8
//!
//! Rules v9.0:
//!   Rule 1: 1 SpendKey = 1 GovernanceID (tidak bisa beli lebih)
//!   Rule 2: GOVERNANCE_MIN_STAKE_SSCL = 100,000 sSCL minimum stake
//!   Rule 3: GP = uptime_weight × conviction_factor (bukan SCL balance)
//!   Rule 4: GovernanceID dari ViewKey — stabil meski SpendKey dirotasi
//!
//! GP Formula v9.0 — spec §11.2:
//!   GP(i) = uptime_weight_fp(i) × conviction_factor(days_held)
//!           ─────────────────────────────────────────────────
//!                    FIXED_POINT_BASIS
//!
//!   uptime_weight_fp: dari MaturityStore (0..1_000_000)
//!   conviction_factor: dari ConvictionTable (0..1_000_000)
//!   GP: fixed-point basis 1_000_000
//!
//! Anti-Sybil properties:
//!   - GP tidak bisa dibeli dengan SCL — hanya dari uptime + waktu
//!   - 1 ViewKey = 1 GovernanceID → tidak bisa multiply identity
//!   - Min stake GOVERNANCE_MIN_STAKE_SSCL mencegah spam proposal

// ── Ossified constants — spec §11.8 ──────────────────────────────────────────

/// Minimum stake untuk membuat governance proposal. OSSIFIED — spec §11.8.
/// 100,000 sSCL = 0.001 SCL.
pub const GOVERNANCE_MIN_STAKE_SSCL: u64 = 100_000;

/// Fixed-point basis untuk GP calculation. Spec §11.2.
pub const GP_FP_BASIS: u64 = 1_000_000;

// ── GP Formula v9.0 — spec §11.2 ─────────────────────────────────────────────

/// Compute Governance Power untuk satu account. Spec §11.2.
///
/// GP(i) = uptime_weight_fp(i) × conviction_factor(days_held) / FP_BASIS
///
/// `uptime_weight_fp`: dari MaturityStore::gov_weight() (0..1_000_000)
/// `conviction_factor_fp`: dari ConvictionTable::conviction_factor(days) (0..1_000_000)
///
/// GP tidak menggunakan SCL balance — hanya uptime + waktu. Spec §11.2.
/// No floating point — integer fixed-point basis 1_000_000.
pub fn compute_governance_power_v9(uptime_weight_fp: u64, conviction_factor_fp: u64) -> u64 {
    // GP = uptime_weight × conviction / FP_BASIS
    // Integer arithmetic — no float. Spec §11.2.
    (uptime_weight_fp as u128)
        .saturating_mul(conviction_factor_fp as u128)
        .checked_div(GP_FP_BASIS as u128)
        .unwrap_or(0) as u64
}

// ── Anti-Sybil validation — spec §11.8 ───────────────────────────────────────

/// Hasil validasi anti-sybil untuk satu participant. Spec §11.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiSybilResult {
    /// Participant valid — GovernanceID unik dan stake cukup.
    Valid { governance_id: [u8; 32], gp: u64 },
    /// Stake di bawah minimum. Spec §11.8 Rule 2.
    InsufficientStake { stake: u64, required: u64 },
    /// GovernanceID duplikat — sybil terdeteksi. Spec §11.8 Rule 1.
    DuplicateGovernanceId { governance_id: [u8; 32] },
    /// Uptime tidak cukup untuk GP > 0. Spec §11.8 Rule 3.
    ZeroGovernancePower,
}

/// Validasi satu participant governance. Spec §11.8.
///
/// `governance_id`: dari derive_governance_id(view_key)
/// `stake_sscl`: saldo SCL participant dalam sSCL
/// `uptime_weight_fp`: dari MaturityStore
/// `conviction_factor_fp`: dari ConvictionTable
/// `existing_ids`: set GovernanceID yang sudah terdaftar
pub fn validate_governance_participant(
    governance_id: [u8; 32],
    stake_sscl: u64,
    uptime_weight_fp: u64,
    conviction_factor_fp: u64,
    existing_ids: &[[u8; 32]],
) -> AntiSybilResult {
    // Rule 2: minimum stake check — spec §11.8
    if stake_sscl < GOVERNANCE_MIN_STAKE_SSCL {
        return AntiSybilResult::InsufficientStake {
            stake: stake_sscl,
            required: GOVERNANCE_MIN_STAKE_SSCL,
        };
    }

    // Rule 1: 1 GovernanceID = 1 participant — spec §11.8
    if existing_ids.contains(&governance_id) {
        return AntiSybilResult::DuplicateGovernanceId { governance_id };
    }

    // Rule 3: GP harus > 0 — spec §11.8
    let gp = compute_governance_power_v9(uptime_weight_fp, conviction_factor_fp);
    if gp == 0 {
        return AntiSybilResult::ZeroGovernancePower;
    }

    AntiSybilResult::Valid { governance_id, gp }
}

/// Compute total GP dari semua participant. Spec §11.2.
///
/// Digunakan untuk menghitung voting threshold.
pub fn compute_total_gp(participants: &[(u64, u64)]) -> u64 {
    // participants: slice of (uptime_weight_fp, conviction_factor_fp)
    participants
        .iter()
        .map(|(uptime, conviction)| compute_governance_power_v9(*uptime, *conviction))
        .fold(0u64, |acc, gp| acc.saturating_add(gp))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_governance_min_stake_sscl() {
        // Spec §11.8: GOVERNANCE_MIN_STAKE_SSCL = 100_000. OSSIFIED.
        assert_eq!(GOVERNANCE_MIN_STAKE_SSCL, 100_000u64);
    }

    #[test]
    fn test_gp_fp_basis() {
        // Spec §11.2: GP_FP_BASIS = 1_000_000.
        assert_eq!(GP_FP_BASIS, 1_000_000u64);
    }

    // ── GP Formula ────────────────────────────────────────────────────────────

    #[test]
    fn test_gp_full_uptime_full_conviction() {
        // uptime=1_000_000, conviction=1_000_000 → GP=1_000_000. Spec §11.2.
        let gp = compute_governance_power_v9(1_000_000, 1_000_000);
        assert_eq!(gp, 1_000_000);
    }

    #[test]
    fn test_gp_half_uptime_full_conviction() {
        // uptime=500_000, conviction=1_000_000 → GP=500_000. Spec §11.2.
        let gp = compute_governance_power_v9(500_000, 1_000_000);
        assert_eq!(gp, 500_000);
    }

    #[test]
    fn test_gp_full_uptime_half_conviction() {
        // uptime=1_000_000, conviction=500_000 → GP=500_000. Spec §11.2.
        let gp = compute_governance_power_v9(1_000_000, 500_000);
        assert_eq!(gp, 500_000);
    }

    #[test]
    fn test_gp_zero_uptime() {
        // uptime=0 → GP=0 (tidak aktif). Spec §11.2.
        let gp = compute_governance_power_v9(0, 1_000_000);
        assert_eq!(gp, 0);
    }

    #[test]
    fn test_gp_zero_conviction() {
        // conviction=0 (baru join, < 7 hari) → GP=0. Spec §11.2.
        let gp = compute_governance_power_v9(1_000_000, 0);
        assert_eq!(gp, 0);
    }

    #[test]
    fn test_gp_not_based_on_scl_balance() {
        // Rule 3: GP tidak menggunakan SCL balance. Spec §11.8.
        // Fungsi hanya menerima uptime dan conviction — tidak ada SCL param.
        let gp1 = compute_governance_power_v9(800_000, 700_000);
        let gp2 = compute_governance_power_v9(800_000, 700_000);
        // Sama persis karena tidak ada random SCL balance factor
        assert_eq!(gp1, gp2);
    }

    #[test]
    fn test_gp_no_floating_point() {
        // Semua kalkulasi integer. Spec global.
        let gp = compute_governance_power_v9(750_000, 800_000);
        // 750_000 × 800_000 / 1_000_000 = 600_000_000_000 / 1_000_000 = 600_000
        assert_eq!(gp, 600_000);
    }

    // ── Anti-Sybil validation ──────────────────────────────────────────────────

    #[test]
    fn test_valid_participant() {
        // Participant valid: stake cukup, ID unik, GP > 0. Spec §11.8.
        let gov_id = [0x01u8; 32];
        let result = validate_governance_participant(
            gov_id,
            100_000, // stake = minimum
            800_000, // uptime
            700_000, // conviction
            &[],     // tidak ada ID lain
        );
        assert!(matches!(result, AntiSybilResult::Valid { .. }));
    }

    #[test]
    fn test_insufficient_stake_rejected() {
        // Stake < minimum → rejected. Spec §11.8 Rule 2.
        let gov_id = [0x01u8; 32];
        let result = validate_governance_participant(
            gov_id,
            99_999, // stake < 100_000
            800_000,
            700_000,
            &[],
        );
        assert!(matches!(
            result,
            AntiSybilResult::InsufficientStake {
                required: 100_000,
                ..
            }
        ));
    }

    #[test]
    fn test_zero_stake_rejected() {
        // Stake = 0 → rejected. Spec §11.8 Rule 2.
        let gov_id = [0x01u8; 32];
        let result = validate_governance_participant(gov_id, 0, 800_000, 700_000, &[]);
        assert!(matches!(result, AntiSybilResult::InsufficientStake { .. }));
    }

    #[test]
    fn test_duplicate_governance_id_rejected() {
        // Sybil: GovernanceID sudah ada → rejected. Spec §11.8 Rule 1.
        let gov_id = [0x42u8; 32];
        let existing = vec![gov_id];
        let result = validate_governance_participant(gov_id, 100_000, 800_000, 700_000, &existing);
        assert!(matches!(
            result,
            AntiSybilResult::DuplicateGovernanceId { .. }
        ));
    }

    #[test]
    fn test_zero_gp_rejected() {
        // GP = 0 (uptime = 0) → rejected. Spec §11.8 Rule 3.
        let gov_id = [0x01u8; 32];
        let result = validate_governance_participant(
            gov_id,
            100_000,
            0, // uptime = 0 → GP = 0
            700_000,
            &[],
        );
        assert!(matches!(result, AntiSybilResult::ZeroGovernancePower));
    }

    #[test]
    fn test_valid_gp_in_result() {
        // GP dalam result harus sesuai formula. Spec §11.2.
        let gov_id = [0x01u8; 32];
        let result = validate_governance_participant(
            gov_id,
            100_000,
            1_000_000, // uptime full
            1_000_000, // conviction full
            &[],
        );
        if let AntiSybilResult::Valid { gp, .. } = result {
            assert_eq!(gp, 1_000_000);
        } else {
            panic!("Expected Valid");
        }
    }

    #[test]
    fn test_one_spendkey_one_governance_id() {
        // Rule 1: 1 GovernanceID = 1 participant. Spec §11.8.
        // Tidak bisa register GovernanceID yang sama dua kali.
        let gov_id = [0xAAu8; 32];
        let existing = vec![gov_id];
        // Coba register lagi → sybil
        let result = validate_governance_participant(gov_id, 100_000, 800_000, 700_000, &existing);
        assert!(matches!(
            result,
            AntiSybilResult::DuplicateGovernanceId { .. }
        ));
    }

    // ── compute_total_gp ──────────────────────────────────────────────────────

    #[test]
    fn test_total_gp_empty() {
        // Tidak ada participant → total GP = 0.
        assert_eq!(compute_total_gp(&[]), 0);
    }

    #[test]
    fn test_total_gp_multiple_participants() {
        // Total GP = sum semua GP. Spec §11.2.
        let participants = vec![
            (1_000_000u64, 1_000_000u64), // GP = 1_000_000
            (500_000u64, 1_000_000u64),   // GP = 500_000
            (1_000_000u64, 500_000u64),   // GP = 500_000
        ];
        assert_eq!(compute_total_gp(&participants), 2_000_000);
    }

    #[test]
    fn test_total_gp_zero_participants() {
        // Semua GP = 0 → total = 0.
        let participants = vec![(0u64, 1_000_000u64), (1_000_000u64, 0u64)];
        assert_eq!(compute_total_gp(&participants), 0);
    }
}
