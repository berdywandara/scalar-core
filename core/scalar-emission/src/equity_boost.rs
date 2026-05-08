// File: crates/scalar-emission/src/equity_boost.rs

pub struct EquityBoostCalculator;

impl EquityBoostCalculator {
    pub fn compute_gini(rewards: &[u64]) -> u64 {
        if rewards.is_empty() {
            return 0;
        }

        let n = rewards.len() as u64;
        let mut sorted = rewards.to_vec();
        sorted.sort_unstable();

        let sum_total: u64 = sorted.iter().sum();
        if sum_total == 0 {
            return 0;
        }

        let weighted_sum: u64 = sorted
            .iter()
            .enumerate()
            .map(|(i, &x)| (i as u64 + 1) * x)
            .sum();

        let numerator = 2 * weighted_sum * 1_000_000;
        let denominator = n * sum_total;
        let term1 = numerator / denominator;
        let term2 = ((n + 1) * 1_000_000) / n;

        if term1 > term2 {
            term1.saturating_sub(term2)
        } else {
            0
        }
    }

    pub fn compute_uptime_rank_percentile(node_weight: u64, all_weights: &[u64]) -> u64 {
        if all_weights.is_empty() {
            return 0;
        }
        let lower_count = all_weights.iter().filter(|&&w| w <= node_weight).count() as u64;

        (lower_count * 1_000_000) / (all_weights.len() as u64)
    }

    pub fn compute_equity_boost(gini_coefficient: u64, uptime_rank_percentile: u64) -> u64 {
        let half = 500_000u64; // 0.5 × 1,000,000
        let ur_above_half = if uptime_rank_percentile > half {
            uptime_rank_percentile.saturating_sub(half)
        } else {
            0
        };

        let boost_component = (gini_coefficient * ur_above_half * 2) / 1_000_000;
        1_000_000 + boost_component
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gini_zero_for_equal_distribution() {
        let rewards = vec![100u64, 100, 100, 100, 100];
        let gini = EquityBoostCalculator::compute_gini(&rewards);
        assert_eq!(gini, 0, "Distribusi merata = Gini 0");
    }

    #[test]
    fn test_equity_boost_sybil_gets_no_bonus() {
        let boost = EquityBoostCalculator::compute_equity_boost(500_000, 0);
        assert_eq!(boost, 1_000_000, "Sybil: boost = 1.0");
    }

    #[test]
    fn test_equity_boost_high_uptime_gets_bonus() {
        let gini = 500_000u64;
        let ur = 1_000_000u64;
        let boost = EquityBoostCalculator::compute_equity_boost(gini, ur);
        assert_eq!(boost, 1_500_000u64, "High uptime = boost 1.5x");
    }
}
