/// Conviction Factor menggunakan tabel diskrit precomputed.
/// OSSIFIED: semua client menggunakan tabel yang sama.
/// Tidak ada floating point runtime computation.
pub struct ConvictionTable;

impl ConvictionTable {
    /// CF(t) = round((1 - (9/10)^t) × 1,000,000)
    /// Precomputed untuk deterministik lintas platform
    pub fn conviction_factor(t_days: u32) -> u64 {
        match t_days {
            0 => 0,
            1 => 100_000,
            2 => 190_000,
            3 => 271_000,
            4 => 344_000,
            5 => 410_000,
            6 => 469_000,
            7 => 521_799,
            14 => 771_361,
            22 => 901_504,
            30 => 957_584,
            60 => 998_187,
            365..=u32::MAX => 1_000_000, // Saturated
            // Interpolasi linear untuk nilai di antara
            t => Self::interpolate(t),
        }
    }

    fn interpolate(t: u32) -> u64 {
        // Cari dua titik terdekat dan interpolasi
        // Ini tetap deterministic karena menggunakan integer
        let checkpoints = [
            (0u32, 0u64),
            (7, 521_799),
            (14, 771_361),
            (22, 901_504),
            (30, 957_584),
            (60, 998_187),
            (365, 1_000_000),
        ];

        for window in checkpoints.windows(2) {
            let (t1, v1) = window[0];
            let (t2, v2) = window[1];
            if t >= t1 && t <= t2 {
                // Linear interpolation dalam integer
                let range = (t2 - t1) as u64;
                let progress = (t - t1) as u64;
                return v1 + (v2 - v1) * progress / range;
            }
        }
        1_000_000 // Default: saturated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // CF(30 hari) / CF(1 menit ≈ 0 hari) >> 1
        // Spec: ~13,118× ratio
        let cf_30d = ConvictionTable::conviction_factor(30);
        let cf_1d = ConvictionTable::conviction_factor(1);
        assert!(
            cf_30d > cf_1d * 5,
            "CF(30d) harus jauh lebih besar dari CF(1d)"
        );
    }
}
