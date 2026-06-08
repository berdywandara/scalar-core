//! Governance Power — NodeScore-based Cap — SCALAR-PROTOCOL §11.2
//!
//! GP(i,t) = min(BaseGP(i,t), gov_max_fp(node_score_prev_epoch))
//!
//! gov_max_fp(node_score_prev_epoch):
//! - score >= 800_000: NODESCORE_GP_HIGH_CAP (1_000_000)
//! - score <  800_000: NODESCORE_GP_LOW_CAP  (200_000)
//!
//! GP cap ditentukan oleh NodeScore epoch k-1 — bukan hardware tier.
//! Threshold 800_000 sama dengan aggregator/NMT threshold (operational bar).
//! SCALAR-PROTOCOL §11.2, §3.1.

// ── Constants — SCALAR-PROTOCOL §11.2 ─────────────────────────────────────────

/// NodeScore threshold untuk GP cap tinggi. OSSIFIED — SCALAR-PROTOCOL §11.2.
/// Sama dengan NMT_SCORE_THRESHOLD dan AGGREGATOR_MIN_NODESCORE (800_000).
pub const NODESCORE_HIGH_THRESHOLD: u32 = 800_000;

/// GP cap untuk node dengan NodeScore >= NODESCORE_HIGH_THRESHOLD. OSSIFIED — SCALAR-PROTOCOL §11.2.
pub const NODESCORE_GP_HIGH_CAP: u64 = 1_000_000;

/// GP cap untuk node dengan NodeScore < NODESCORE_HIGH_THRESHOLD. OSSIFIED — SCALAR-PROTOCOL §11.2.
pub const NODESCORE_GP_LOW_CAP: u64 = 200_000;

/// Fixed-point basis. Spec §18.1.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

// ── gov_max_fp — SCALAR-PROTOCOL §11.2 ───────────────────────────────────────

/// GP cap berdasarkan NodeScore epoch sebelumnya. SCALAR-PROTOCOL §11.2.
///
/// gov_max_fp(node_score_prev_epoch):
/// - score >= 800_000: NODESCORE_GP_HIGH_CAP (1_000_000)
/// - score <  800_000: NODESCORE_GP_LOW_CAP  (200_000)
///
/// Dipanggil dengan NodeScore dari epoch k-1 (bukan epoch berjalan).
pub fn gov_max_fp(node_score_prev_epoch: u32) -> u64 {
    if node_score_prev_epoch >= NODESCORE_HIGH_THRESHOLD {
        NODESCORE_GP_HIGH_CAP
    } else {
        NODESCORE_GP_LOW_CAP
    }
}

// ── GP Formula — SCALAR-PROTOCOL §11.2 ───────────────────────────────────────

/// Hitung BaseGP sebelum NodeScore cap. SCALAR-PROTOCOL §11.2.
///
/// BaseGP(i,t) = conviction_factor_fp × maturity_fp / 1_000_000
///
/// `conviction_factor_fp`: dari ConvictionTable (0..1_000_000)
/// `maturity_fp`: dari MaturityStore::gov_weight() (0..1_000_000)
pub fn compute_base_gp(conviction_factor_fp: u64, maturity_fp: u64) -> u64 {
    (conviction_factor_fp as u128)
        .saturating_mul(maturity_fp as u128)
        .checked_div(FIXED_POINT_BASIS as u128)
        .unwrap_or(0) as u64
}

/// Hitung GP dengan NodeScore-based cap. SCALAR-PROTOCOL §11.2.
///
/// GP(i,t) = min(BaseGP(i,t), gov_max_fp(node_score_prev_epoch))
///
/// `node_score_prev_epoch`: NodeScore node dari epoch k-1 (u32, range 0..=1_000_000).
/// `conviction_factor_fp`: dari ConvictionTable (0..1_000_000).
/// `maturity_fp`: dari MaturityStore::gov_weight() (0..1_000_000).
pub fn compute_governance_power_v12(
    node_score_prev_epoch: u32,
    conviction_factor_fp: u64,
    maturity_fp: u64,
) -> u64 {
    let base_gp = compute_base_gp(conviction_factor_fp, maturity_fp);
    base_gp.min(gov_max_fp(node_score_prev_epoch))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── test_gov_max_fp ───────────────────────────────────────────────────────

    #[test]
    fn test_gov_max_fp_for_tier_c() {
        // NodeScore < 800_000 → NODESCORE_GP_LOW_CAP. SCALAR-PROTOCOL §11.2.
        assert_eq!(gov_max_fp(799_999), NODESCORE_GP_LOW_CAP);
        assert_eq!(gov_max_fp(0), NODESCORE_GP_LOW_CAP);
    }

    #[test]
    fn test_gov_max_fp_for_tier_a() {
        // NodeScore >= 800_000 → NODESCORE_GP_HIGH_CAP. SCALAR-PROTOCOL §11.2.
        assert_eq!(gov_max_fp(800_000), NODESCORE_GP_HIGH_CAP);
        assert_eq!(gov_max_fp(1_000_000), NODESCORE_GP_HIGH_CAP);
    }

    // ── test GP cap — TEST VECTOR 3 dari spec change doc ─────────────────────

    #[test]
    fn test_gov_power_formula_with_cap() {
        // TEST VECTOR 3 — GP Cap:
        //   NodeScore = 900_000 → cap = 1_000_000
        //   NodeScore = 800_000 → cap = 1_000_000
        //   NodeScore = 799_999 → cap = 200_000
        //   NodeScore = 0       → cap = 200_000
        assert_eq!(gov_max_fp(900_000), 1_000_000);
        assert_eq!(gov_max_fp(800_000), 1_000_000);
        assert_eq!(gov_max_fp(799_999), 200_000);
        assert_eq!(gov_max_fp(0), 200_000);
    }

    // ── test compute_governance_power_v12 ─────────────────────────────────────

    #[test]
    fn test_tier_c_gov_power_cap_200k() {
        // Node dengan NodeScore < 800_000 → GP max 200_000. SCALAR-PROTOCOL §11.2.
        let gp = compute_governance_power_v12(
            700_000, // node_score_prev_epoch < 800_000
            1_000_000, 1_000_000,
        );
        assert_eq!(gp, NODESCORE_GP_LOW_CAP);
    }

    #[test]
    fn test_tier_c_gov_power_cap_even_at_max_inputs() {
        // Low NodeScore dengan inputs maksimum tetap dibatasi NODESCORE_GP_LOW_CAP.
        let gp = compute_governance_power_v12(0, 1_000_000, 1_000_000);
        assert_eq!(gp, NODESCORE_GP_LOW_CAP);
    }

    #[test]
    fn test_tier_a_full_gov_power() {
        // Node dengan NodeScore >= 800_000 → GP bisa mencapai 1_000_000. SCALAR-PROTOCOL §11.2.
        let gp = compute_governance_power_v12(1_000_000, 1_000_000, 1_000_000);
        assert_eq!(gp, NODESCORE_GP_HIGH_CAP);
    }

    #[test]
    fn test_tier_a_partial_gp() {
        // Node dengan NodeScore tinggi, conviction/maturity parsial. SCALAR-PROTOCOL §11.2.
        let gp = compute_governance_power_v12(
            900_000, // high score
            500_000, // conviction 50%
            800_000, // maturity 80%
        );
        // BaseGP = 500_000 × 800_000 / 1_000_000 = 400_000
        // cap = 1_000_000 (high score)
        assert_eq!(gp, 400_000);
    }

    // ── test_sybil_attack_simulation ─────────────────────────────────────────

    #[test]
    fn test_sybil_attack_simulation() {
        // 1000 node dengan NodeScore rendah vs 10 node dengan NodeScore tinggi.
        // GP per low-score node = 200_000, total = 200_000_000
        let gp_low_node = gov_max_fp(700_000);
        let total_low = gp_low_node.saturating_mul(1_000);

        // GP per high-score node = 1_000_000, total = 10_000_000
        let gp_high_node = gov_max_fp(900_000);
        let total_high = gp_high_node.saturating_mul(10);

        assert_eq!(total_low, 200_000 * 1_000);
        assert_eq!(total_high, 1_000_000 * 10);
        assert_eq!(total_low / total_high, 20);
    }

    #[test]
    fn test_100_tier_c_vs_1_tier_a_majority() {
        // 100 low-score node vs 1 high-score node.
        let total_low = gov_max_fp(700_000).saturating_mul(100);
        let total_high = gov_max_fp(900_000).saturating_mul(1);
        assert_eq!(total_low, 20_000_000);
        assert_eq!(total_high, 1_000_000);
    }

    // ── test constants ────────────────────────────────────────────────────────

    #[test]
    fn test_tier_c_max_gov_power_constant() {
        // NODESCORE_GP_LOW_CAP = 200_000. OSSIFIED — SCALAR-PROTOCOL §11.2.
        assert_eq!(NODESCORE_GP_LOW_CAP, 200_000u64);
    }

    #[test]
    fn test_tier_ab_max_gov_power_constant() {
        // NODESCORE_GP_HIGH_CAP = 1_000_000. SCALAR-PROTOCOL §11.2.
        assert_eq!(NODESCORE_GP_HIGH_CAP, 1_000_000u64);
    }

    #[test]
    fn test_is_tier_c_node_detection() {
        // gov_max_fp boundary. SCALAR-PROTOCOL §11.2.
        assert_eq!(gov_max_fp(800_000), NODESCORE_GP_HIGH_CAP); // at threshold → HIGH
        assert_eq!(gov_max_fp(799_999), NODESCORE_GP_LOW_CAP); // below → LOW
    }

    #[test]
    fn test_zero_conviction_gives_zero_gp() {
        // Zero conviction → GP = 0. SCALAR-PROTOCOL §11.2.
        let gp = compute_governance_power_v12(900_000, 0, 1_000_000);
        assert_eq!(gp, 0);
    }

    #[test]
    fn test_zero_maturity_gives_zero_gp() {
        // Zero maturity → GP = 0. SCALAR-PROTOCOL §11.2.
        let gp = compute_governance_power_v12(900_000, 1_000_000, 0);
        assert_eq!(gp, 0);
    }
}
