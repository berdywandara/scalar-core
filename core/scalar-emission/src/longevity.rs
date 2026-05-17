//! Longevity Boost — Spec §7.9
//!
//! longevity_boost: +0.1% per epoch partisipasi, meluruh 0.4% per epoch non-partisipasi, cap 50%.
//!
//! Dalam fixed-point basis 1_000_000:
//!   - Gain per epoch aktif   : +1_000 fp (= 0.1%)
//!   - Decay per epoch absen  : -4_000 fp (= 0.4%)
//!   - Cap                    : 500_000 fp (= 50%)
//!   - Floor                  : 0 fp
//!
//! Bonus diambil dari fee pool, bukan mencetak token baru. Spec §7.9.

/// Fixed-point basis. OSSIFIED — spec §7.9.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Gain longevity per epoch partisipasi: +0.1% = 1_000 fp. OSSIFIED — spec §7.9.
pub const LONGEVITY_GAIN_PER_EPOCH_FP: u64 = 1_000;

/// Decay longevity per epoch non-partisipasi: -0.4% = 4_000 fp. OSSIFIED — spec §7.9.
pub const LONGEVITY_DECAY_PER_EPOCH_FP: u64 = 4_000;

/// Cap longevity boost: 50% = 500_000 fp. OSSIFIED — spec §7.9.
pub const LONGEVITY_CAP_FP: u64 = 500_000;

/// Hitung longevity_boost baru setelah satu epoch.
///
/// `current_boost_fp`: nilai longevity_boost sebelumnya (0..=500_000).
/// `participated`: true jika node aktif pada epoch ini (heartbeat valid diterima).
///
/// Returns: longevity_boost_fp baru, clamped ke [0, LONGEVITY_CAP_FP].
pub fn update_longevity_boost(current_boost_fp: u64, participated: bool) -> u64 {
    if participated {
        (current_boost_fp + LONGEVITY_GAIN_PER_EPOCH_FP).min(LONGEVITY_CAP_FP)
    } else {
        current_boost_fp.saturating_sub(LONGEVITY_DECAY_PER_EPOCH_FP)
    }
}

/// Hitung longevity boost setelah N epoch dengan pola partisipasi tertentu.
///
/// `epochs_participated`: jumlah epoch di mana node aktif.
/// `epochs_absent`: jumlah epoch di mana node tidak aktif.
/// Asumsi: seluruh epoch aktif datang lebih dulu, lalu epoch absen.
/// Untuk simulasi yang lebih akurat, gunakan `update_longevity_boost` per epoch.
pub fn compute_longevity_boost(epochs_participated: u64, epochs_absent: u64) -> u64 {
    let after_gain = (epochs_participated * LONGEVITY_GAIN_PER_EPOCH_FP).min(LONGEVITY_CAP_FP);
    after_gain.saturating_sub(epochs_absent * LONGEVITY_DECAY_PER_EPOCH_FP)
}

/// Hasil apply longevity bonus ke reward. Spec §7.9.
pub struct LongevityResult {
    pub base_reward: u64,
    pub longevity_bonus: u64,
    pub remaining_fee_pool: u64,
}

/// Apply longevity bonus ke base_reward dari fee pool. Spec §7.9.
///
/// `base_reward`: reward dasar sebelum bonus.
/// `fee_pool`: pool fee yang tersedia untuk bonus.
/// `longevity_boost_fp`: nilai boost saat ini (0..=500_000 fp).
///
/// Bonus = base_reward x longevity_boost_fp / FIXED_POINT_BASIS.
/// Diambil dari fee_pool — tidak mencetak token baru.
pub fn apply_longevity_bonus(
    base_reward: u64,
    fee_pool: u64,
    longevity_boost_fp: u64,
) -> LongevityResult {
    let capped_boost = longevity_boost_fp.min(LONGEVITY_CAP_FP);
    let target_bonus = (base_reward as u128)
        .saturating_mul(capped_boost as u128)
        .checked_div(FIXED_POINT_BASIS as u128)
        .unwrap_or(0) as u64;
    let actual_bonus = target_bonus.min(fee_pool);
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
    fn test_longevity_gain_per_epoch_is_1000_fp() {
        // +0.1% per epoch = 1_000 fp. OSSIFIED — spec §7.9.
        assert_eq!(LONGEVITY_GAIN_PER_EPOCH_FP, 1_000u64);
    }

    #[test]
    fn test_longevity_decay_per_epoch_is_4000_fp() {
        // -0.4% per epoch = 4_000 fp. OSSIFIED — spec §7.9.
        assert_eq!(LONGEVITY_DECAY_PER_EPOCH_FP, 4_000u64);
    }

    #[test]
    fn test_longevity_cap_is_500000_fp() {
        // Cap 50% = 500_000 fp. OSSIFIED — spec §7.9.
        assert_eq!(LONGEVITY_CAP_FP, 500_000u64);
    }

    #[test]
    fn test_update_gain_per_active_epoch() {
        // Satu epoch aktif: +1_000 fp. Spec §7.9.
        let boost = update_longevity_boost(0, true);
        assert_eq!(boost, 1_000);
    }

    #[test]
    fn test_update_decay_per_absent_epoch() {
        // Satu epoch absen: -4_000 fp. Spec §7.9.
        let boost = update_longevity_boost(10_000, false);
        assert_eq!(boost, 6_000);
    }

    #[test]
    fn test_update_decay_floor_at_zero() {
        // Decay tidak boleh negatif. Spec §7.9.
        let boost = update_longevity_boost(1_000, false);
        assert_eq!(boost, 0);
    }

    #[test]
    fn test_update_cap_at_500000_fp() {
        // Cap 50% = 500_000 fp. Spec §7.9.
        let boost = update_longevity_boost(499_500, true);
        assert_eq!(boost, 500_000);
        let boost2 = update_longevity_boost(500_000, true);
        assert_eq!(boost2, 500_000);
    }

    #[test]
    fn test_reach_cap_after_500_active_epochs() {
        // 500 epoch aktif x 1_000 fp = 500_000 fp = cap. Spec §7.9.
        let mut boost = 0u64;
        for _ in 0..500 {
            boost = update_longevity_boost(boost, true);
        }
        assert_eq!(boost, 500_000);
        boost = update_longevity_boost(boost, true);
        assert_eq!(boost, 500_000);
    }

    #[test]
    fn test_decay_from_cap_after_absent_epoch() {
        // Dari cap, 1 epoch absen: 500_000 - 4_000 = 496_000. Spec §7.9.
        let boost = update_longevity_boost(500_000, false);
        assert_eq!(boost, 496_000);
    }

    #[test]
    fn test_bonus_zero_boost_gives_zero_bonus() {
        // boost=0 -> bonus=0. Spec §7.9.
        let result = apply_longevity_bonus(1_000_000, 500_000, 0);
        assert_eq!(result.longevity_bonus, 0);
        assert_eq!(result.remaining_fee_pool, 500_000);
    }

    #[test]
    fn test_bonus_at_cap_gives_50_percent() {
        // boost=500_000 fp (50%) -> bonus = 50% of base_reward. Spec §7.9.
        let result = apply_longevity_bonus(1_000_000, 1_000_000, 500_000);
        assert_eq!(result.longevity_bonus, 500_000);
        assert_eq!(result.base_reward, 1_000_000);
        assert_eq!(result.remaining_fee_pool, 500_000);
    }

    #[test]
    fn test_bonus_capped_by_fee_pool() {
        // Fee pool tidak cukup — bonus dibatasi fee pool. Spec §7.9.
        let result = apply_longevity_bonus(1_000_000, 100, 500_000);
        assert_eq!(result.longevity_bonus, 100);
        assert_eq!(result.remaining_fee_pool, 0);
    }

    #[test]
    fn test_bonus_from_fee_pool_not_new_supply() {
        // Bonus tidak mencetak token baru. Spec §7.9.
        let result = apply_longevity_bonus(100_000, 50_000, 100_000);
        assert_eq!(result.longevity_bonus, 10_000); // 10% of 100_000
        assert_eq!(result.remaining_fee_pool, 40_000);
        assert_eq!(result.base_reward, 100_000);
    }

    #[test]
    fn test_longevity_boost_cap_enforced_in_apply() {
        // Boost > cap -> clamp ke 500_000. Spec §7.9.
        let result = apply_longevity_bonus(1_000_000, 1_000_000, 999_999);
        assert_eq!(result.longevity_bonus, 500_000);
    }
}
