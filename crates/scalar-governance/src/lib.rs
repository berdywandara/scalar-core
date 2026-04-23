//! Modul Tata Kelola Berbasis Matematika

// Layer 1 Ossified Constraints: Total Supply 21 Juta SCL
pub const MAX_TOTAL_SUPPLY_SCL: u64 = 21_000_000;
pub const SCL_TO_SSCL_MULTIPLIER: u64 = 100_000_000;
pub const MAX_TOTAL_SUPPLY_SSCL: u64 = 2_100_000_000_000_000; // 2.1 x 10^15 SSCL
pub const MAX_VOTING_POWER_PERCENTAGE: f64 = 0.001; // Capped 0.1%

pub fn calculate_effective_weight(account_balance_sscl: u64) -> u64 {
    let raw_weight = account_balance_sscl as f64;
    let max_allowed_weight = (MAX_TOTAL_SUPPLY_SSCL as f64) * MAX_VOTING_POWER_PERCENTAGE;

    if raw_weight > max_allowed_weight {
        max_allowed_weight as u64
    } else {
        account_balance_sscl
    }
}
