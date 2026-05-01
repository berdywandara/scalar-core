// File: crates/scalar-emission/src/longevity.rs

pub struct LongevityCalculator {
    epochs_per_year: u64,
    max_boost_fp: u64,
}

impl LongevityCalculator {
    pub fn new() -> Self {
        Self {
            epochs_per_year: 12,
            max_boost_fp: 500_000, // 50%
        }
    }

    pub fn compute_longevity_years(&self, current_epoch: u64, registration_epoch: u64) -> u64 {
        if current_epoch < registration_epoch {
            return 0;
        }
        (current_epoch - registration_epoch) / self.epochs_per_year
    }

    pub fn compute_longevity_boost_factor(&self, longevity_years: u64) -> u64 {
        let boost = longevity_years * 10_000;
        boost.min(self.max_boost_fp)
    }

    pub fn compute_longevity_boost_sscl(&self, base_pou_sscl: u64, longevity_years: u64) -> u64 {
        let boost_factor = self.compute_longevity_boost_factor(longevity_years);
        (base_pou_sscl * boost_factor) / 1_000_000
    }
}

impl Default for LongevityCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longevity_5_years_gives_5_percent() {
        let calc = LongevityCalculator::new();
        let boost_factor = calc.compute_longevity_boost_factor(5);
        assert_eq!(boost_factor, 50_000);
    }

    #[test]
    fn test_longevity_50_years_capped_at_50_percent() {
        let calc = LongevityCalculator::new();
        let boost_50 = calc.compute_longevity_boost_factor(50);
        let boost_100 = calc.compute_longevity_boost_factor(100);
        assert_eq!(boost_50, 500_000);
        assert_eq!(boost_100, 500_000);
    }

    #[test]
    fn test_longevity_from_fee_pool_not_new_supply() {
        let base_pou = 1_000_000u64;
        let calc = LongevityCalculator::new();
        let boost = calc.compute_longevity_boost_sscl(base_pou, 50);
        assert_eq!(boost, 500_000);
    }
}
