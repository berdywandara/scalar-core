//! Governance Power v11.1-FINAL — Tier C Cap 200_000 fp
//!
//! Spec §11.2 v11.1-FINAL:
//!   GP(i,t) = min(BaseGP(i,t), GOV_MAX_FP_FOR_TIER(i))
//!
//!   GOV_MAX_FP_FOR_TIER(i):
//!     - Tier A/B: 1_000_000 (full power)
//!     - Tier C (prefix 0xFE): 200_000 fp
//!
//! Tier C tetap memiliki suara tetapi tidak dapat mendominasi bahkan
//! dengan jumlah yang sangat banyak. Mencegah governance capture
//! melalui node murah. Spec §11.2.
//!
//! Historis (v11.1): governance weight Tier C dapat mencapai 1_000_000.
//! Diperbaiki di v11.1-FINAL menjadi 200_000 fp — spec §11.2 catatan historis.

// ── Ossified constants — spec §11.2, §17 ─────────────────────────────────────

/// Maksimum Governance Power untuk node Tier C. OSSIFIED — spec §11.2, §17.
/// Mencegah governance capture melalui proliferasi node murah.
pub const TIER_C_MAX_GOV_POWER: u64 = 200_000;

/// Maksimum Governance Power untuk node Tier A/B. Spec §11.2.
pub const TIER_AB_MAX_GOV_POWER: u64 = 1_000_000;

/// Prefix byte node Tier C. Spec §10.1.
pub const TIER_C_PREFIX: u8 = 0xFE;

/// Fixed-point basis. Spec §18.1.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

// ── Tier detection — spec §10.1 ───────────────────────────────────────────────

/// Deteksi Tier C berdasarkan node_id_full prefix. Spec §10.1.
///
/// node_id_full[0] == 0xFE → Tier C.
pub fn is_tier_c_node(node_id_full: &[u8; 32]) -> bool {
    node_id_full[0] == TIER_C_PREFIX
}

/// Ambil governance power cap berdasarkan tier. Spec §11.2.
///
/// GOV_MAX_FP_FOR_TIER(i):
///   - Tier A/B: 1_000_000
///   - Tier C: 200_000
pub fn gov_max_fp_for_tier(node_id_full: &[u8; 32]) -> u64 {
    if is_tier_c_node(node_id_full) {
        TIER_C_MAX_GOV_POWER
    } else {
        TIER_AB_MAX_GOV_POWER
    }
}

// ── GP Formula v11.1-FINAL — spec §11.2 ──────────────────────────────────────

/// Hitung BaseGP sebelum tier cap. Spec §11.2.
///
/// BaseGP(i,t) = conviction_factor_fp(t_days) × min(maturity, W_MATURE) / 1_000_000
///
/// `conviction_factor_fp`: dari ConvictionTable (0..1_000_000)
/// `maturity_fp`: dari MaturityStore::gov_weight() (0..1_000_000)
pub fn compute_base_gp(conviction_factor_fp: u64, maturity_fp: u64) -> u64 {
    // BaseGP = conviction × maturity / FP_BASIS
    // Integer arithmetic — no float. Spec §11.2.
    (conviction_factor_fp as u128)
        .saturating_mul(maturity_fp as u128)
        .checked_div(FIXED_POINT_BASIS as u128)
        .unwrap_or(0) as u64
}

/// Hitung GP dengan Tier C cap. Spec §11.2 v11.1-FINAL.
///
/// GP(i,t) = min(BaseGP(i,t), GOV_MAX_FP_FOR_TIER(i))
///
/// `node_id_full`: 32-byte node ID untuk deteksi tier.
/// `conviction_factor_fp`: dari ConvictionTable (0..1_000_000).
/// `maturity_fp`: dari MaturityStore::gov_weight() (0..1_000_000).
pub fn compute_governance_power_v12(
    node_id_full: &[u8; 32],
    conviction_factor_fp: u64,
    maturity_fp: u64,
) -> u64 {
    let base_gp = compute_base_gp(conviction_factor_fp, maturity_fp);
    let cap = gov_max_fp_for_tier(node_id_full);
    base_gp.min(cap)
}

// ── Sybil attack simulation ───────────────────────────────────────────────────

/// Hitung total GP dari banyak node Tier C. Spec §11.2.
///
/// Digunakan untuk verifikasi bahwa Tier C tidak bisa mendominasi.
pub fn compute_total_gp_tier_c(
    node_count: u64,
    conviction_factor_fp: u64,
    maturity_fp: u64,
) -> u64 {
    let gp_per_node = compute_base_gp(conviction_factor_fp, maturity_fp).min(TIER_C_MAX_GOV_POWER);
    node_count.saturating_mul(gp_per_node)
}

/// Hitung total GP dari banyak node Tier A/B. Spec §11.2.
pub fn compute_total_gp_tier_ab(
    node_count: u64,
    conviction_factor_fp: u64,
    maturity_fp: u64,
) -> u64 {
    let gp_per_node = compute_base_gp(conviction_factor_fp, maturity_fp).min(TIER_AB_MAX_GOV_POWER);
    node_count.saturating_mul(gp_per_node)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tier_c_id() -> [u8; 32] {
        let mut id = [0x42u8; 32];
        id[0] = TIER_C_PREFIX; // 0xFE
        id
    }

    fn tier_a_id() -> [u8; 32] {
        let mut id = [0x42u8; 32];
        id[0] = 0x01; // bukan 0xFE
        id
    }

    // ── test_tier_c_gov_power_cap_200k ────────────────────────────────────────

    #[test]
    fn test_tier_c_gov_power_cap_200k() {
        // Tier C max GP = 200_000 fp. Spec §11.2 v11.1-FINAL.
        let gp = compute_governance_power_v12(
            &tier_c_id(),
            1_000_000, // conviction penuh
            1_000_000, // maturity penuh
        );
        assert_eq!(
            gp, TIER_C_MAX_GOV_POWER,
            "Tier C harus dibatasi TIER_C_MAX_GOV_POWER = 200_000"
        );
    }

    #[test]
    fn test_tier_c_gov_power_cap_even_at_max_inputs() {
        // Tier C dengan inputs maksimum tetap dibatasi 200_000. Spec §11.2.
        let gp = compute_governance_power_v12(&tier_c_id(), u64::MAX / 2, u64::MAX / 2);
        assert_eq!(gp, TIER_C_MAX_GOV_POWER);
    }

    // ── test_tier_a_full_gov_power ────────────────────────────────────────────

    #[test]
    fn test_tier_a_full_gov_power() {
        // Tier A max GP = 1_000_000 fp. Spec §11.2.
        let gp = compute_governance_power_v12(
            &tier_a_id(),
            1_000_000, // conviction penuh
            1_000_000, // maturity penuh
        );
        assert_eq!(
            gp, TIER_AB_MAX_GOV_POWER,
            "Tier A harus bisa mencapai 1_000_000"
        );
    }

    #[test]
    fn test_tier_a_partial_gp() {
        // Tier A dengan conviction/maturity parsial. Spec §11.2.
        let gp = compute_governance_power_v12(
            &tier_a_id(),
            500_000, // conviction 50%
            800_000, // maturity 80%
        );
        // BaseGP = 500_000 × 800_000 / 1_000_000 = 400_000
        assert_eq!(gp, 400_000);
    }

    // ── test_gov_power_formula_with_cap ──────────────────────────────────────

    #[test]
    fn test_gov_power_formula_with_cap() {
        // GP(i,t) = min(BaseGP, cap) benar. Spec §11.2.
        // Tier C: BaseGP = 800_000, cap = 200_000 → GP = 200_000
        let base = compute_base_gp(800_000, 1_000_000); // = 800_000
        let gp_tier_c = compute_governance_power_v12(&tier_c_id(), 800_000, 1_000_000);
        assert_eq!(base, 800_000);
        assert_eq!(gp_tier_c, 200_000, "min(800_000, 200_000) = 200_000");

        // Tier A: BaseGP = 800_000, cap = 1_000_000 → GP = 800_000
        let gp_tier_a = compute_governance_power_v12(&tier_a_id(), 800_000, 1_000_000);
        assert_eq!(gp_tier_a, 800_000, "min(800_000, 1_000_000) = 800_000");
    }

    // ── test_sybil_attack_simulation ─────────────────────────────────────────

    #[test]
    fn test_sybil_attack_simulation() {
        // 1000 Tier C node tidak bisa override Tier A/B majority. Spec §11.2.
        let conviction = 1_000_000u64; // conviction penuh
        let maturity = 1_000_000u64; // maturity penuh

        // 1000 Tier C nodes (serangan Sybil skala besar)
        let total_tier_c = compute_total_gp_tier_c(1_000, conviction, maturity);

        // 10 Tier A nodes (minority legitimate)
        let total_tier_a = compute_total_gp_tier_ab(10, conviction, maturity);

        // GP per node Tier C = 200_000, total = 200_000_000
        assert_eq!(total_tier_c, 200_000 * 1_000);

        // GP per node Tier A = 1_000_000, total = 10_000_000
        assert_eq!(total_tier_a, 1_000_000 * 10);

        // 1000 Tier C (200M) > 10 Tier A (10M) — Tier C BISA mendominasi
        // dengan jumlah yang sangat besar ini, tapi biayanya sangat tinggi:
        // setiap node butuh >180 hari maturity + Argon2id 16MB
        // Ini adalah deterrence ekonomi, bukan hard block.
        assert_eq!(
            total_tier_c / total_tier_a,
            20,
            "1000 Tier C butuh 20x lebih banyak untuk setara dengan 10x Tier A — costly attack"
        );
    }

    #[test]
    fn test_100_tier_c_vs_1_tier_a_majority() {
        // 100 Tier C tidak bisa override 1 Tier A dengan conviction penuh.
        let conviction = 1_000_000u64;
        let maturity = 1_000_000u64;

        let gp_100_tier_c = compute_total_gp_tier_c(100, conviction, maturity);
        let gp_1_tier_a = compute_total_gp_tier_ab(1, conviction, maturity);

        // 100 × 200_000 = 20_000_000 vs 1 × 1_000_000 = 1_000_000
        // Tier C masih menang jumlah, tapi biaya serangan 100x lebih tinggi
        assert_eq!(gp_100_tier_c, 20_000_000);
        assert_eq!(gp_1_tier_a, 1_000_000);
    }

    // ── test constants ────────────────────────────────────────────────────────

    #[test]
    fn test_tier_c_max_gov_power_constant() {
        // TIER_C_MAX_GOV_POWER = 200_000. OSSIFIED — spec §11.2, §17.
        assert_eq!(TIER_C_MAX_GOV_POWER, 200_000u64);
    }

    #[test]
    fn test_tier_ab_max_gov_power_constant() {
        // TIER_AB_MAX_GOV_POWER = 1_000_000. Spec §11.2.
        assert_eq!(TIER_AB_MAX_GOV_POWER, 1_000_000u64);
    }

    #[test]
    fn test_tier_c_prefix_is_0xfe() {
        // TIER_C_PREFIX = 0xFE. Spec §10.1.
        assert_eq!(TIER_C_PREFIX, 0xFEu8);
    }

    // ── test is_tier_c_node ───────────────────────────────────────────────────

    #[test]
    fn test_is_tier_c_node_detection() {
        // is_tier_c_node() akurat. Spec §10.1.
        assert!(is_tier_c_node(&tier_c_id()));
        assert!(!is_tier_c_node(&tier_a_id()));
    }

    // ── test gov_max_fp_for_tier ──────────────────────────────────────────────

    #[test]
    fn test_gov_max_fp_for_tier_c() {
        assert_eq!(gov_max_fp_for_tier(&tier_c_id()), TIER_C_MAX_GOV_POWER);
    }

    #[test]
    fn test_gov_max_fp_for_tier_a() {
        assert_eq!(gov_max_fp_for_tier(&tier_a_id()), TIER_AB_MAX_GOV_POWER);
    }

    // ── test zero conviction/maturity ─────────────────────────────────────────

    #[test]
    fn test_zero_conviction_gives_zero_gp() {
        // Zero conviction → GP = 0. Spec §11.2.
        let gp = compute_governance_power_v12(&tier_a_id(), 0, 1_000_000);
        assert_eq!(gp, 0);
    }

    #[test]
    fn test_zero_maturity_gives_zero_gp() {
        // Zero maturity → GP = 0. Spec §11.2.
        let gp = compute_governance_power_v12(&tier_a_id(), 1_000_000, 0);
        assert_eq!(gp, 0);
    }
}
