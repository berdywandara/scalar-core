// File: crates/scalar-emission/src/longevity.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;
pub const MAX_LONGEVITY_YEARS: u64 = 50;

pub fn compute_longevity_multiplier(years: u64) -> u64 {
    let capped_years = years.min(MAX_LONGEVITY_YEARS);
    // 1 tahun = 1% bonus (10_000 dalam fixed point)
    let bonus = capped_years * 10_000;
    FIXED_POINT_BASIS + bonus
}

pub struct LongevityResult {
    pub base_reward: u64,
    pub longevity_bonus: u64,
    pub remaining_fee_pool: u64,
}

pub fn apply_longevity_bonus(base_reward: u64, fee_pool: u64, years: u64) -> LongevityResult {
    let multiplier = compute_longevity_multiplier(years);
    let bonus_ratio = multiplier.saturating_sub(FIXED_POINT_BASIS);

    let target_bonus = (base_reward * bonus_ratio) / FIXED_POINT_BASIS;
    let actual_bonus = target_bonus.min(fee_pool); // ensure derived from fee pool

    let remaining_fee_pool = fee_pool.saturating_sub(actual_bonus);

    LongevityResult {
        base_reward,
        longevity_bonus: actual_bonus,
        remaining_fee_pool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longevity_5_years_gives_5_percent() {
        let multiplier = compute_longevity_multiplier(5);
        assert_eq!(multiplier, 1_050_000); // 1.05x (5%)
    }

    #[test]
    fn test_longevity_50_years_capped_at_50_percent() {
        let multiplier_50 = compute_longevity_multiplier(50);
        let multiplier_100 = compute_longevity_multiplier(100);

        assert_eq!(multiplier_50, 1_500_000); // 1.50x
        assert_eq!(multiplier_100, 1_500_000); // Capped at 1.50x
    }

    #[test]
    fn test_longevity_from_fee_pool_not_new_supply() {
        let base_reward = 100_000;
        let fee_pool = 2_000; // Fee pool insufficient for bayar seluruh bonus (target 5_000)
        let years = 5; // 5% bonus target

        let result = apply_longevity_bonus(base_reward, fee_pool, years);

        assert_eq!(result.base_reward, 100_000);
        // Bonus harus mentok di sisa fee_pool agar tidak mencetak token baru
        assert_eq!(result.longevity_bonus, 2_000);
        assert_eq!(result.remaining_fee_pool, 0);
    }
}
