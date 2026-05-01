// File: crates/scalar-governance/src/conviction.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;
pub const MAX_CONVICTION_DAYS: u64 = 365;

/// Menghitung kekuatan voting berdasarkan staking SCL, durasi lock (Conviction),
/// serta pengali GovID. Menggunakan 100% fixed-point, zero floating point.
pub fn compute_conviction_power(
    staked_amount: u64,
    locked_days: u64,
    govid_multiplier_fp: u64,
) -> u64 {
    let capped_days = locked_days.min(MAX_CONVICTION_DAYS);

    // time_multiplier = 1.0x + (capped_days / 365) -> Maksimum 2.0x
    let time_multiplier =
        FIXED_POINT_BASIS + ((capped_days * FIXED_POINT_BASIS) / MAX_CONVICTION_DAYS);

    // total_multiplier = time_multiplier * govid_multiplier
    let total_multiplier = (time_multiplier * govid_multiplier_fp) / FIXED_POINT_BASIS;

    (staked_amount * total_multiplier) / FIXED_POINT_BASIS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conviction_power_zero_floating_point() {
        let amount = 1000;
        // 365 hari = 2.0x time_multiplier. GovID 1.5x (1_500_000). Total = 3.0x
        let power = compute_conviction_power(amount, 365, 1_500_000);
        assert_eq!(power, 3000);
    }

    #[test]
    fn test_conviction_power_no_lock() {
        let amount = 1000;
        // 0 hari = 1.0x time_multiplier. GovID 1.0x (1_000_000). Total = 1.0x
        let power = compute_conviction_power(amount, 0, 1_000_000);
        assert_eq!(power, 1000);
    }
}
