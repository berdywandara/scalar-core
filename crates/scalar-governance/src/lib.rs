//! GAP C-005: Governance Circuit Enforcement
//! "Truth by Mathematics, Not by Majority" (Kecuali Mayoritas Matematis)

pub mod circuit;

/// Kuadratik Voting dengan Cap (Anti-Whale)
/// 21M SCL total supply. Cap di 144.9 weight.
pub fn calculate_effective_weight(scl_held: u64) -> f64 {
    let cap = 144.9;
    let weight = (scl_held as f64).sqrt();
    if weight > cap {
        cap
    } else {
        weight
    }
}
