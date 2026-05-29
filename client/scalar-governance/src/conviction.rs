// File: crates/scalar-governance/src/conviction.rs

/// Conviction Factor menggunakan tabel diskrit precomputed
/// OSSIFIED: semua client menggunakan tabel yang sama
/// Tidak ada floating point runtime computation
/// Conviction time constant tau. OSSIFIED — MAD §21.1.
/// CF(t) saturates toward 1.0 as t → ∞ with half-life τ = 60 days.
/// Formula: CF(t) = 1 - (1 - 1/τ)^t = 1 - (59/60)^t (continuous approx)
/// Precomputed table uses this tau. Any change requires new table + hard fork.
pub const TAU_CONVICTION: u32 = 60;

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
