//! denomination Tetap Scalar Network — Spec §3.3
//!
//! 17 denomination fixed in onean sSCL (sub-Scalar).
//! 1 SCL = 100_000_000 sSCL (10^8).
//!
//! Koin in denomination the same not dapat atbedwill satu same lain.
//! Fungibility adalah property matematika, openn policy. — Spec §3.3
//!
//! OSSIFIED: daftar and value denomination not dapat changed without hard fork.

// ── Konstanta d1–d17 dalam sSCL ──────────────────────────────────────────────

/// d1 = 1 sSCL = 0.00000001 SCL. OSSIFIED — spec §3.3.
pub const D1_SSCL: u64 = 1;
/// d2 = 5 sSCL = 0.00000005 SCL. OSSIFIED — spec §3.3.
pub const D2_SSCL: u64 = 5;
/// d3 = 10 sSCL = 0.0000001 SCL. OSSIFIED — spec §3.3.
pub const D3_SSCL: u64 = 10;
/// d4 = 50 sSCL = 0.0000005 SCL. OSSIFIED — spec §3.3.
pub const D4_SSCL: u64 = 50;
/// d5 = 100 sSCL = 0.000001 SCL. OSSIFIED — spec §3.3.
pub const D5_SSCL: u64 = 100;
/// d6 = 500 sSCL = 0.000005 SCL. OSSIFIED — spec §3.3.
pub const D6_SSCL: u64 = 500;
/// d7 = 1_000 sSCL = 0.00001 SCL. OSSIFIED — spec §3.3.
pub const D7_SSCL: u64 = 1_000;
/// d8 = 5_000 sSCL = 0.00005 SCL. OSSIFIED — spec §3.3.
pub const D8_SSCL: u64 = 5_000;
/// d9 = 10_000 sSCL = 0.0001 SCL. OSSIFIED — spec §3.3.
pub const D9_SSCL: u64 = 10_000;
/// d10 = 50_000 sSCL = 0.0005 SCL. OSSIFIED — spec §3.3.
pub const D10_SSCL: u64 = 50_000;
/// d11 = 100_000 sSCL = 0.001 SCL. OSSIFIED — spec §3.3.
pub const D11_SSCL: u64 = 100_000;
/// d12 = 500_000 sSCL = 0.005 SCL. OSSIFIED — spec §3.3.
pub const D12_SSCL: u64 = 500_000;
/// d13 = 1_000_000 sSCL = 0.01 SCL. OSSIFIED — spec §3.3.
pub const D13_SSCL: u64 = 1_000_000;
/// d14 = 5_000_000 sSCL = 0.05 SCL. OSSIFIED — spec §3.3.
pub const D14_SSCL: u64 = 5_000_000;
/// d15 = 10_000_000 sSCL = 0.1 SCL. OSSIFIED — spec §3.3.
pub const D15_SSCL: u64 = 10_000_000;
/// d16 = 50_000_000 sSCL = 0.5 SCL. OSSIFIED — spec §3.3.
pub const D16_SSCL: u64 = 50_000_000;
/// d17 = 100_000_000 sSCL = 1.0 SCL. OSSIFIED — spec §3.3.
pub const D17_SSCL: u64 = 100_000_000;

/// Jumlah denomination. OSSIFIED — spec §3.3.
pub const DENOMINATION_COUNT: usize = 17;

/// Array all denomination ascenatng d1..d17. OSSIFIED — spec §3.3.
/// used for coin selection, validation, and atsplay.
pub const ALL_DENOMINATIONS: [u64; DENOMINATION_COUNT] = [
    D1_SSCL, D2_SSCL, D3_SSCL, D4_SSCL, D5_SSCL, D6_SSCL, D7_SSCL, D8_SSCL, D9_SSCL, D10_SSCL,
    D11_SSCL, D12_SSCL, D13_SSCL, D14_SSCL, D15_SSCL, D16_SSCL, D17_SSCL,
];

/// Konversion: 1 SCL in SSCL. OSSIFIED — spec §3.2.
pub const SCL_TO_SSCL: u64 = 100_000_000;

// ── Enum Denomination ────────────────────────────────────────────────────────

/// Enum all 17 denomination valid. Spec §3.3.
/// only value from enum this that valid as coin denomination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum Denomination {
    D1 = D1_SSCL,
    D2 = D2_SSCL,
    D3 = D3_SSCL,
    D4 = D4_SSCL,
    D5 = D5_SSCL,
    D6 = D6_SSCL,
    D7 = D7_SSCL,
    D8 = D8_SSCL,
    D9 = D9_SSCL,
    D10 = D10_SSCL,
    D11 = D11_SSCL,
    D12 = D12_SSCL,
    D13 = D13_SSCL,
    D14 = D14_SSCL,
    D15 = D15_SSCL,
    D16 = D16_SSCL,
    D17 = D17_SSCL,
}

impl Denomination {
    /// value denomination in SSCL.
    pub fn value_sscl(self) -> u64 {
        self as u64
    }

    /// Konversion from u64 sSCL to Denomination.
    /// Return None if value openn wrong satu from 17 denomination valid.
    pub fn from_sscl(value: u64) -> Option<Self> {
        match value {
            D1_SSCL => Some(Self::D1),
            D2_SSCL => Some(Self::D2),
            D3_SSCL => Some(Self::D3),
            D4_SSCL => Some(Self::D4),
            D5_SSCL => Some(Self::D5),
            D6_SSCL => Some(Self::D6),
            D7_SSCL => Some(Self::D7),
            D8_SSCL => Some(Self::D8),
            D9_SSCL => Some(Self::D9),
            D10_SSCL => Some(Self::D10),
            D11_SSCL => Some(Self::D11),
            D12_SSCL => Some(Self::D12),
            D13_SSCL => Some(Self::D13),
            D14_SSCL => Some(Self::D14),
            D15_SSCL => Some(Self::D15),
            D16_SSCL => Some(Self::D16),
            D17_SSCL => Some(Self::D17),
            _ => None,
        }
    }

    /// Return all denomination ascenatng. Spec §3.3.
    pub fn all() -> &'static [u64; DENOMINATION_COUNT] {
        &ALL_DENOMINATIONS
    }

    /// check whether value sSCL adalah denomination valid. Spec §3.3.
    pub fn is_valid(value: u64) -> bool {
        Self::from_sscl(value).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constant values §3.3 ─────────────────────────────────────────────────

    #[test]
    fn test_d1_is_1() {
        assert_eq!(D1_SSCL, 1u64);
    }

    #[test]
    fn test_d17_is_100_000_000() {
        // Spec §3.3: d17 = 100_000_000 sSCL = 1.0 SCL. OSSIFIED.
        assert_eq!(D17_SSCL, 100_000_000u64);
    }

    #[test]
    fn test_scl_to_sscl_conversion() {
        // Spec §3.2: 1 SCL = 10^8 sSCL. OSSIFIED.
        assert_eq!(SCL_TO_SSCL, 100_000_000u64);
        assert_eq!(D17_SSCL, SCL_TO_SSCL);
    }

    #[test]
    fn test_denomination_count_is_17() {
        // Spec §3.3: tepat 17 denominasi. OSSIFIED.
        assert_eq!(DENOMINATION_COUNT, 17usize);
        assert_eq!(ALL_DENOMINATIONS.len(), 17);
    }

    #[test]
    fn test_all_denominations_ascending() {
        // Spec §3.3: d1 < d2 < ... < d17.
        for i in 1..ALL_DENOMINATIONS.len() {
            assert!(
                ALL_DENOMINATIONS[i] > ALL_DENOMINATIONS[i - 1],
                "Denominasi harus ascending: index {} = {} tidak lebih besar dari {} di index {}",
                i,
                ALL_DENOMINATIONS[i],
                ALL_DENOMINATIONS[i - 1],
                i - 1
            );
        }
    }

    #[test]
    fn test_all_denominations_exact_values() {
        // Spec §3.3: verifikasi seluruh 17 nilai secara eksplisit.
        let expected: [u64; 17] = [
            1,
            5,
            10,
            50,
            100,
            500,
            1_000,
            5_000,
            10_000,
            50_000,
            100_000,
            500_000,
            1_000_000,
            5_000_000,
            10_000_000,
            50_000_000,
            100_000_000,
        ];
        assert_eq!(ALL_DENOMINATIONS, expected);
    }

    // ── Denomination enum ────────────────────────────────────────────────────

    #[test]
    fn test_enum_d1_value() {
        assert_eq!(Denomination::D1.value_sscl(), 1u64);
    }

    #[test]
    fn test_enum_d17_value() {
        assert_eq!(Denomination::D17.value_sscl(), 100_000_000u64);
    }

    #[test]
    fn test_from_sscl_valid() {
        assert_eq!(Denomination::from_sscl(1), Some(Denomination::D1));
        assert_eq!(Denomination::from_sscl(5), Some(Denomination::D2));
        assert_eq!(
            Denomination::from_sscl(100_000_000),
            Some(Denomination::D17)
        );
    }

    #[test]
    fn test_from_sscl_invalid() {
        // Nilai yang bukan denominasi valid → None
        assert_eq!(Denomination::from_sscl(0), None);
        assert_eq!(Denomination::from_sscl(2), None);
        assert_eq!(Denomination::from_sscl(99), None);
        assert_eq!(Denomination::from_sscl(999_999), None);
        assert_eq!(Denomination::from_sscl(100_000_001), None);
    }

    #[test]
    fn test_is_valid_all_17() {
        // Semua 17 denominasi harus valid.
        for &denom in ALL_DENOMINATIONS.iter() {
            assert!(
                Denomination::is_valid(denom),
                "{denom} harus valid sebagai denominasi"
            );
        }
    }

    #[test]
    fn test_is_valid_rejects_non_denominations() {
        assert!(!Denomination::is_valid(0));
        assert!(!Denomination::is_valid(2));
        assert!(!Denomination::is_valid(7));
        assert!(!Denomination::is_valid(999));
        assert!(!Denomination::is_valid(u64::MAX));
    }

    #[test]
    fn test_from_sscl_roundtrip_all() {
        // from_sscl(d.value_sscl()) == Some(d) untuk semua d.
        let all_enums = [
            Denomination::D1,
            Denomination::D2,
            Denomination::D3,
            Denomination::D4,
            Denomination::D5,
            Denomination::D6,
            Denomination::D7,
            Denomination::D8,
            Denomination::D9,
            Denomination::D10,
            Denomination::D11,
            Denomination::D12,
            Denomination::D13,
            Denomination::D14,
            Denomination::D15,
            Denomination::D16,
            Denomination::D17,
        ];
        for d in all_enums {
            assert_eq!(
                Denomination::from_sscl(d.value_sscl()),
                Some(d),
                "Roundtrip gagal untuk {:?}",
                d
            );
        }
    }

    #[test]
    fn test_no_floating_point() {
        // Semua nilai dan operasi murni integer.
        let total: u64 = ALL_DENOMINATIONS.iter().sum();
        assert!(total > 0);
        assert_eq!(total, 166_666_666u64);
    }
}
