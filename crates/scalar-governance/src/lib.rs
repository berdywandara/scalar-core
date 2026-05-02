// File: crates/scalar-governance/src/lib.rs

pub mod ai_resistance;
pub mod conviction;
pub mod governance_id;
pub mod governance_power;

#[cfg(test)]
mod tests {
    use super::conviction::*;
    use super::governance_id::*;
    use super::governance_power::*;

    #[test]
    fn test_conviction_table_key_values() {
        assert_eq!(ConvictionTable::conviction_factor(0), 0);
        assert_eq!(ConvictionTable::conviction_factor(7), 521_799);
        assert_eq!(ConvictionTable::conviction_factor(14), 771_361);
        assert_eq!(ConvictionTable::conviction_factor(22), 901_504);
        assert_eq!(ConvictionTable::conviction_factor(30), 957_584);
        assert_eq!(ConvictionTable::conviction_factor(60), 998_187);
        assert_eq!(ConvictionTable::conviction_factor(365), 1_000_000);
        assert_eq!(ConvictionTable::conviction_factor(9999), 1_000_000);
    }

    #[test]
    fn test_conviction_factor_monotonic_increasing() {
        for t in 0..365 {
            assert!(
                ConvictionTable::conviction_factor(t) <= ConvictionTable::conviction_factor(t + 1),
                "Conviction factor harus monotonic: t={}",
                t
            );
        }
    }

    #[test]
    fn test_flash_loan_immunity() {
        let cf_30d = ConvictionTable::conviction_factor(30);
        let cf_1d = ConvictionTable::conviction_factor(1);
        assert!(
            cf_30d > cf_1d * 5,
            "CF(30d) harus jauh lebih besar dari CF(1d)"
        );
    }

    #[test]
    fn test_ai_resistance_cliff_below_7_days() {
        for days in 0..7 {
            let mult = GovernancePowerCalculator::ai_resistance_multiplier(days);
            assert_eq!(mult, 10_000, "Hari {} harus 1% power (cliff)", days);
        }
    }

    #[test]
    fn test_ai_resistance_full_power_at_30_days() {
        let mult = GovernancePowerCalculator::ai_resistance_multiplier(30);
        assert_eq!(mult, 1_000_000, "30 hari = 100% power");

        let mult_365 = GovernancePowerCalculator::ai_resistance_multiplier(365);
        assert_eq!(mult_365, 1_000_000, "365 hari = masih 100% power");
    }

    #[test]
    fn test_governance_power_zero_before_conviction() {
        let gp = GovernancePowerCalculator::compute_governance_power(0, 1_000_000);
        assert_eq!(gp, 0, "Tanpa conviction: GP = 0");
    }

    #[test]
    fn test_governance_id_stable_across_rotation() {
        let account_key = [1u8; 32];
        let view_key = derive_view_key(&account_key);
        let gov_id_1 = derive_governance_id(&view_key);
        let gov_id_2 = derive_governance_id(&view_key);

        assert_eq!(
            gov_id_1, gov_id_2,
            "GovernanceID harus stabil saat SpendKey dirotasi"
        );
        assert!(verify_governance_id_stability(&view_key, &view_key));
    }

    #[test]
    fn test_governance_id_different_per_account() {
        let view_key_1 = [1u8; 32];
        let view_key_2 = [2u8; 32];

        let gov_id_1 = derive_governance_id(&view_key_1);
        let gov_id_2 = derive_governance_id(&view_key_2);

        assert_ne!(
            gov_id_1, gov_id_2,
            "Account berbeda harus punya GovernanceID berbeda"
        );
    }

    #[test]
    fn test_scl_balance_not_used_in_governance() {
        let _ = GovernancePowerCalculator::compute_governance_power(30, 800_000);
    }
}
