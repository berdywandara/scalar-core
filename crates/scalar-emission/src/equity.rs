// File: crates/scalar-emission/src/equity.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;

pub fn compute_gini(distributions: &[u64]) -> u64 {
    if distributions.is_empty() {
        return 0;
    }

    let mut dists = distributions.to_vec();
    dists.sort_unstable();
    let n = dists.len() as u64;

    let mut sum_of_absolute_differences = 0;
    let mut total = 0;

    for i in 0..n {
        total += dists[i as usize];
        for j in 0..n {
            sum_of_absolute_differences += dists[i as usize].abs_diff(dists[j as usize]);
        }
    }

    if total == 0 {
        return 0;
    }

    let denominator = 2 * n * total;
    (sum_of_absolute_differences * FIXED_POINT_BASIS) / denominator
}

pub fn compute_equity_boost(uptime_rank_percentile: u64, is_sybil: bool) -> u64 {
    if is_sybil {
        return FIXED_POINT_BASIS; // Sybil tidak mendapatkan bonus (1.0x)
    }

    let half = FIXED_POINT_BASIS / 2;
    let bonus = if uptime_rank_percentile > half {
        // Bonus didapatkan jika percentile > 50%
        uptime_rank_percentile.saturating_sub(half) / 2
    } else {
        0
    };

    FIXED_POINT_BASIS + bonus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gini_zero_for_equal_distribution() {
        let dist = vec![100, 100, 100, 100];
        assert_eq!(compute_gini(&dist), 0);
    }

    #[test]
    fn test_equity_boost_sybil_gets_no_bonus() {
        // Meskipun uptime tinggi (100%), jika sybil, bonus = 0
        let boost = compute_equity_boost(1_000_000, true);
        assert_eq!(boost, FIXED_POINT_BASIS);
    }

    #[test]
    fn test_equity_boost_high_uptime_gets_bonus() {
        // Bukan sybil, uptime tinggi (100%) -> Dapat bonus
        let boost = compute_equity_boost(1_000_000, false);
        assert!(boost > FIXED_POINT_BASIS);
    }
}
