// File: crates/scalar-governance/src/conviction.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Menghitung multiplier conviction berdasarkan durasi lock (hari).
/// Aturan v5.0:
/// - < 7 hari = 0 (Flash loan & AI Resistance cliff)
/// - 30 hari = 1.0x (1_000_000) (Full base power)
/// - > 30 hari = Skala linier hingga 365 hari (Max 3.0x)
pub fn compute_conviction_multiplier(locked_days: u64) -> u64 {
    if locked_days < 7 {
        return 0; // AI resistance cliff & flash loan immunity
    }
    if locked_days < 30 {
        return (locked_days * FIXED_POINT_BASIS) / 30;
    }
    let capped_days = locked_days.min(365);
    let extra_days = capped_days - 30;

    // (extra_days / 335) * 2.0x
    FIXED_POINT_BASIS + (extra_days * 2 * FIXED_POINT_BASIS) / 335
}

/// Menghitung final governance power.
/// Aturan v5.0: SALDO SCL DIHAPUS TOTAL dari kalkulasi Governance.
/// Kekuatan murni: 1 (Base) * Conviction Multiplier * GovID Multiplier
pub fn compute_governance_power(locked_days: u64, govid_multiplier_fp: u64) -> u64 {
    let conviction = compute_conviction_multiplier(locked_days);
    if conviction == 0 {
        return 0;
    }
    (conviction * govid_multiplier_fp) / FIXED_POINT_BASIS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_loan_immunity() {
        assert_eq!(compute_conviction_multiplier(0), 0);
    }

    #[test]
    fn test_ai_resistance_cliff_below_7_days() {
        assert_eq!(compute_conviction_multiplier(6), 0);
    }

    #[test]
    fn test_ai_resistance_full_power_at_30_days() {
        assert_eq!(compute_conviction_multiplier(30), FIXED_POINT_BASIS);
    }

    #[test]
    fn test_conviction_table_key_values() {
        assert_eq!(compute_conviction_multiplier(30), FIXED_POINT_BASIS);
        assert_eq!(compute_conviction_multiplier(365), 3 * FIXED_POINT_BASIS);
    }

    #[test]
    fn test_conviction_factor_monotonic_increasing() {
        let p1 = compute_conviction_multiplier(30);
        let p2 = compute_conviction_multiplier(60);
        let p3 = compute_conviction_multiplier(365);
        assert!(p1 < p2);
        assert!(p2 < p3);
    }

    #[test]
    fn test_governance_power_zero_before_conviction() {
        assert_eq!(compute_governance_power(0, 1_000_000), 0);
        assert_eq!(compute_governance_power(6, 2_000_000), 0);
    }

    #[test]
    fn test_scl_balance_not_used_in_governance() {
        let dummy_scl_balance_whale = 50_000_000_000_u64;
        let power = compute_governance_power(30, FIXED_POINT_BASIS);
        // Power ditentukan murni oleh conviction dan GovID (1_000_000), BUKAN saldo SCL
        assert_eq!(power, FIXED_POINT_BASIS);
        assert_ne!(power, dummy_scl_balance_whale);
    }
}
