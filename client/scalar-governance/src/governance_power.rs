// File: crates/scalar-governance/src/governance_power.rs

use crate::conviction::ConvictionTable;

pub struct GovernancePowerCalculator;

impl GovernancePowerCalculator {
    /// GP(i, t) = conviction_factor(t_days)
    ///            × gov_weight(i)
    ///            × ai_resistance_multiplier(conviction_days)
    ///
    /// Semua dalam fixed-point basis 1,000,000
    pub fn compute_governance_power(
        conviction_days: u32,
        gov_weight: u64, // dari maturity, basis 1,000,000
    ) -> u64 {
        let cf = ConvictionTable::conviction_factor(conviction_days);
        let ai_mult = Self::ai_resistance_multiplier(conviction_days);

        // GP = CF × gov_weight × ai_mult / 1,000,000²
        // Hati-hati overflow: kalkulasi bertahap
        let intermediate = (cf * gov_weight) / 1_000_000;
        (intermediate * ai_mult) / 1_000_000
    }

    /// AI Resistance Multiplier (Safeguard 1: Conviction Cliff)
    /// conviction_days < 7:  → 1% power (10,000 / 1,000,000)
    /// 7 ≤ days < 30:        → Linear 1% ke 100%
    /// days ≥ 30:            → 100% power (1,000,000 / 1,000,000)
    pub fn ai_resistance_multiplier(conviction_days: u32) -> u64 {
        match conviction_days {
            0..=6 => 10_000,            // 1% — cliff period
            30..=u32::MAX => 1_000_000, // 100% — full power
            t => {
                // Linear dari 1% ke 100% antara hari 7-30
                let range = 30 - 7;
                let progress = t - 7;
                10_000 + (990_000 * progress as u64) / range as u64
            }
        }
    }
}
