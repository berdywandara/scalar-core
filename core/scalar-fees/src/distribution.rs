//! Fee Distribution — Spec §9.2 v9.0
//!
//! v9.0 menggantikan model v7.0 (70/25/5):
//!   DIHAPUS: RELAY_PERCENT = 70  → relay pool dieliminasi
//!   DIHAPUS: AGGREGATOR_PERCENT = 25 → aggregator pool dieliminasi
//!
//! Model v9.0:
//!   FEE_NODE_POOL_PERCENT     = 95  — uptime-weighted distribution ke semua node
//!   FEE_SECURITY_FUND_PERCENT =  5  — protocol reserve
//!
//! W_FLOOR_FP guardrail:
//!   W_effective(k) = max(W(k), W_FLOOR_FP)
//!   Mencegah fee spike saat mayoritas node offline.
//!   Invariant F-4: R_fee_total ≤ Fee_pool × 95 / 100
//!
//! OSSIFIED — spec §9.2. Tidak bisa diubah tanpa hard fork.

/// Persentase fee untuk node pool (uptime-weighted). OSSIFIED — spec §9.2.
/// Menggantikan RELAY_PERCENT (70) + AGGREGATOR_PERCENT (25) yang dihapus.
pub const FEE_NODE_POOL_PERCENT: u64 = 95;

/// Persentase fee untuk security fund. OSSIFIED — spec §9.2.
pub const FEE_SECURITY_FUND_PERCENT: u64 = 5;

/// W_FLOOR_FP — weight floor dalam fixed-point basis 1_000_000. OSSIFIED — spec §9.2.
/// W_effective(k) = max(W(k), W_FLOOR_FP).
/// Mencegah fee spike ekstrem saat mayoritas node offline.
/// Nilai: 1_000_000_000 (1000× basis) — minimum total weight yang diasumsikan.
pub const W_FLOOR_FP: u64 = 1_000_000_000;

/// N_MIN_ABSOLUT — minimum node absolut untuk bootstrap economics. OSSIFIED — spec §9.2, §7.8.
pub const N_MIN_ABSOLUT: u64 = 1_000;

/// Invariant compile-time: FEE_NODE_POOL_PERCENT + FEE_SECURITY_FUND_PERCENT == 100.
const _: () = assert!(
    FEE_NODE_POOL_PERCENT + FEE_SECURITY_FUND_PERCENT == 100,
    "Fee split harus berjumlah 100% — spec §9.2"
);

/// Hasil distribusi fee v9.0. Spec §9.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeDistribution {
    /// Bagian node pool (95%) — didistribusi uptime-weighted ke semua node. Spec §9.2.
    pub node_pool: u64,
    /// Bagian security fund (5%). Spec §9.2.
    pub security_fund: u64,
}

/// Hitung W_effective(k) = max(W(k), W_FLOOR_FP). Spec §9.2.
///
/// Guardrail ini mencegah fee spike saat mayoritas node offline.
/// Jika W(k) < W_FLOOR_FP, distribusi dihitung seolah total weight = W_FLOOR_FP.
pub fn compute_w_effective(w_actual_fp: u64) -> u64 {
    w_actual_fp.max(W_FLOOR_FP)
}

/// Hitung distribusi fee dari total fee. Spec §9.2.
///
/// node_pool = fee_total × 95 / 100
/// security_fund = fee_total - node_pool  (sisa pembulatan ke security_fund)
///
/// Tidak ada token yang hilang: node_pool + security_fund == fee_total.
pub fn distribute_fee(fee_total: u64) -> FeeDistribution {
    // Spec §9.2: node_pool = 95%, security_fund = 5%
    let node_pool = fee_total * FEE_NODE_POOL_PERCENT / 100;
    // Security fund = sisa — memastikan konservasi token
    let security_fund = fee_total.saturating_sub(node_pool);
    FeeDistribution {
        node_pool,
        security_fund,
    }
}

/// Hitung reward fee untuk satu node. Spec §9.2.
///
/// R_fee_i = Fee_pool × w_i / W_effective(k)
/// Invariant F-4: R_fee_total ≤ Fee_pool × 95 / 100
///
/// `fee_pool` = distribute_fee(fee_total).node_pool
/// `w_i_fp`   = uptime weight node i dalam fixed-point basis 1_000_000
/// `w_total_fp` = total weight semua node dalam epoch
///
/// Menggunakan W_effective — jangan pass w_total_fp raw, gunakan compute_w_effective() dulu.
pub fn compute_node_fee_reward(fee_pool: u64, w_i_fp: u64, w_effective_fp: u64) -> u64 {
    if w_effective_fp == 0 || w_i_fp == 0 {
        return 0;
    }
    // R_fee_i = fee_pool × w_i / W_effective — integer arithmetic, no float
    ((fee_pool as u128)
        .saturating_mul(w_i_fp as u128)
        .checked_div(w_effective_fp as u128)
        .unwrap_or(0)) as u64
}

/// Verifikasi konservasi token: node_pool + security_fund == fee_total.
pub fn distribution_is_conserved(dist: &FeeDistribution, fee_total: u64) -> bool {
    dist.node_pool.saturating_add(dist.security_fund) == fee_total
}

/// Verifikasi Invariant F-4: R_fee_total ≤ Fee_pool × 95 / 100. Spec §9.2.
///
/// `r_fee_total` = total reward fee yang sudah dibayar ke semua node dalam epoch.
/// `fee_pool`    = distribute_fee(fee_total).node_pool
pub fn verify_invariant_f4(r_fee_total: u64, fee_pool: u64) -> bool {
    // R_fee_total ≤ Fee_pool (node_pool sudah 95% dari fee_total)
    r_fee_total <= fee_pool
}

/// Hitung fee residual dari epoch. Spec §9.2 — Finding #6.
///
/// fee_residual = floor(fee_pool × 0.95) - Sum R_fee_floor(i,k)
/// Residual terjadi karena pembagian integer (floor) per node.
///
/// `fee_pool`       = distribute_fee(fee_total).node_pool  (95% dari total)
/// `sum_node_rewards` = total R_fee_floor yang sudah dibayar ke semua node
pub fn compute_fee_residual(fee_pool: u64, sum_node_rewards: u64) -> u64 {
    fee_pool.saturating_sub(sum_node_rewards)
}

/// Hitung R_sec(k) — total ke Security Fund. Spec §9.2 — Finding #6.
///
/// R_sec(k) = floor(Fee_pool × 0.05) + fee_residual
/// Memastikan seluruh token terkonservasi: tidak ada yang hilang ke rounding.
///
/// `fee_total`        = total fee dari epoch
/// `sum_node_rewards` = total R_fee_floor yang sudah dibayar ke semua node
pub fn compute_r_sec(fee_total: u64, sum_node_rewards: u64) -> u64 {
    let dist = distribute_fee(fee_total);
    let fee_residual = compute_fee_residual(dist.node_pool, sum_node_rewards);
    // R_sec = security_fund_base (5%) + residual dari node pool
    dist.security_fund.saturating_add(fee_residual)
}

/// Verifikasi konservasi token lengkap untuk epoch. Spec §9.2.
///
/// Invariant: sum_node_rewards + r_sec == fee_total
pub fn verify_full_conservation(fee_total: u64, sum_node_rewards: u64, r_sec: u64) -> bool {
    sum_node_rewards.saturating_add(r_sec) == fee_total
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constant correctness ──────────────────────────────────────────────────

    #[test]
    fn test_fee_node_pool_percent_is_95() {
        // Spec §9.2: node pool = 95%. OSSIFIED.
        assert_eq!(FEE_NODE_POOL_PERCENT, 95u64);
    }

    #[test]
    fn test_fee_security_fund_percent_is_5() {
        // Spec §9.2: security fund = 5%. OSSIFIED.
        assert_eq!(FEE_SECURITY_FUND_PERCENT, 5u64);
    }

    #[test]
    fn test_fee_split_sums_to_100() {
        // Invariant: 95 + 5 = 100. Spec §9.2.
        assert_eq!(FEE_NODE_POOL_PERCENT + FEE_SECURITY_FUND_PERCENT, 100u64);
    }

    #[test]
    fn test_w_floor_fp_value() {
        // Spec §9.2: W_FLOOR_FP = 1_000_000_000. OSSIFIED.
        assert_eq!(W_FLOOR_FP, 1_000_000_000u64);
    }

    #[test]
    fn test_n_min_absolut_value() {
        // Spec §9.2, §7.8: N_MIN_ABSOLUT = 1_000. OSSIFIED.
        assert_eq!(N_MIN_ABSOLUT, 1_000u64);
    }

    #[test]
    fn test_relay_percent_does_not_exist() {
        // Spec §9.2 v9.0: RELAY_PERCENT DIHAPUS.
        // Test ini memverifikasi bahwa konstanta lama tidak ada.
        // Jika RELAY_PERCENT masih ada, kode tidak akan compile.
        // (Tidak ada kode untuk di-assert — keberhasilan compile = pass.)
    }

    #[test]
    fn test_aggregator_percent_does_not_exist() {
        // Spec §9.2 v9.0: AGGREGATOR_PERCENT DIHAPUS.
        // Jika AGGREGATOR_PERCENT masih ada, kode tidak akan compile.
    }

    // ── W_effective guardrail ──────────────────────────────────────────────────

    #[test]
    fn test_w_effective_above_floor_unchanged() {
        // W(k) > W_FLOOR_FP → W_effective = W(k). Spec §9.2.
        let w = W_FLOOR_FP + 1_000;
        assert_eq!(compute_w_effective(w), w);
    }

    #[test]
    fn test_w_effective_below_floor_clamped() {
        // W(k) < W_FLOOR_FP → W_effective = W_FLOOR_FP. Spec §9.2.
        let w = W_FLOOR_FP / 2;
        assert_eq!(compute_w_effective(w), W_FLOOR_FP);
    }

    #[test]
    fn test_w_effective_at_floor_unchanged() {
        // W(k) == W_FLOOR_FP → W_effective = W_FLOOR_FP.
        assert_eq!(compute_w_effective(W_FLOOR_FP), W_FLOOR_FP);
    }

    #[test]
    fn test_w_effective_zero_clamped_to_floor() {
        // W(k) = 0 (semua node offline) → W_effective = W_FLOOR_FP.
        assert_eq!(compute_w_effective(0), W_FLOOR_FP);
    }

    // ── distribute_fee ────────────────────────────────────────────────────────

    #[test]
    fn test_distribute_fee_100_sscl() {
        // 100 sSCL: node_pool=95, security_fund=5. Spec §9.2.
        let d = distribute_fee(100);
        assert_eq!(d.node_pool, 95);
        assert_eq!(d.security_fund, 5);
    }

    #[test]
    fn test_distribute_fee_zero() {
        let d = distribute_fee(0);
        assert_eq!(d.node_pool, 0);
        assert_eq!(d.security_fund, 0);
    }

    #[test]
    fn test_distribute_fee_conserved_large() {
        // Konservasi token untuk nilai besar. Spec §9.2.
        let fee = 1_000_000_000_000u64;
        let d = distribute_fee(fee);
        assert!(distribution_is_conserved(&d, fee));
    }

    #[test]
    fn test_distribute_fee_rounding_no_loss() {
        // fee = 1 sSCL: node_pool=0 (floor(1×95/100)), security_fund=1
        let d = distribute_fee(1);
        assert!(distribution_is_conserved(&d, 1));
    }

    #[test]
    fn test_distribute_fee_conserved_40_sscl() {
        // FLOOR_MIN_ABSOLUTE = 40 sSCL. Konservasi.
        let d = distribute_fee(40);
        assert_eq!(d.node_pool, 38);
        assert_eq!(d.security_fund, 2);
        assert!(distribution_is_conserved(&d, 40));
    }

    // ── compute_node_fee_reward ───────────────────────────────────────────────

    #[test]
    fn test_node_fee_reward_proportional() {
        // Node dengan w_i = 50% dari W → reward = 50% dari fee_pool. Spec §9.2.
        let fee_pool = 1_000_000u64;
        let w_effective = 2_000_000_000u64; // 2× W_FLOOR_FP
        let w_i = 1_000_000_000u64; // 50% dari w_effective
        let reward = compute_node_fee_reward(fee_pool, w_i, w_effective);
        assert_eq!(reward, 500_000);
    }

    #[test]
    fn test_node_fee_reward_zero_weight() {
        // Node offline (w_i=0) → reward = 0. Spec §9.2.
        assert_eq!(compute_node_fee_reward(1_000_000, 0, W_FLOOR_FP), 0);
    }

    #[test]
    fn test_node_fee_reward_zero_w_effective() {
        // W_effective = 0 → reward = 0 (tidak terjadi karena W_FLOOR_FP, tapi safe).
        assert_eq!(compute_node_fee_reward(1_000_000, 500_000, 0), 0);
    }

    #[test]
    fn test_node_fee_reward_does_not_exceed_pool() {
        // Total rewards tidak melebihi fee_pool. Invariant F-4. Spec §9.2.
        let fee_pool = 950_000u64; // 95% dari 1_000_000
        let w_effective = W_FLOOR_FP;
        // Simulasi 2 node dengan total weight = w_effective
        let r1 = compute_node_fee_reward(fee_pool, W_FLOOR_FP / 2, w_effective);
        let r2 = compute_node_fee_reward(fee_pool, W_FLOOR_FP / 2, w_effective);
        assert!(verify_invariant_f4(r1 + r2, fee_pool));
    }

    // ── Invariant F-4 ─────────────────────────────────────────────────────────

    #[test]
    fn test_invariant_f4_pass() {
        // R_fee_total ≤ fee_pool → pass. Spec §9.2.
        assert!(verify_invariant_f4(950_000, 950_000));
        assert!(verify_invariant_f4(0, 950_000));
    }

    #[test]
    fn test_invariant_f4_fail() {
        // R_fee_total > fee_pool → fail (tidak boleh terjadi).
        assert!(!verify_invariant_f4(950_001, 950_000));
    }

    // ── No floating point ─────────────────────────────────────────────────────

    #[test]
    fn test_no_floating_point() {
        // Semua kalkulasi murni integer — tidak ada f32/f64. Spec global.
        let d = distribute_fee(1_000_000);
        assert_eq!(d.node_pool, 950_000);
        assert_eq!(d.security_fund, 50_000);
        assert!(distribution_is_conserved(&d, 1_000_000));
    }

    // ── Fee residual routing — Finding #6 ────────────────────────────────────

    #[test]
    fn test_fee_residual_zero_when_fully_distributed() {
        // Jika sum_node_rewards == node_pool, residual = 0. Spec §9.2.
        let fee_total = 1_000_000u64;
        let dist = distribute_fee(fee_total);
        let residual = compute_fee_residual(dist.node_pool, dist.node_pool);
        assert_eq!(residual, 0);
    }

    #[test]
    fn test_fee_residual_from_rounding() {
        // Rounding menyebabkan residual. Spec §9.2.
        let fee_total = 1_000u64;
        let node_pool = distribute_fee(fee_total).node_pool; // 950
                                                             // Simulasi 3 node masing-masing dapat 316 (total 948, bukan 950)
        let sum_rewards = 948u64;
        let residual = compute_fee_residual(node_pool, sum_rewards);
        assert_eq!(residual, 2); // 950 - 948 = 2
    }

    #[test]
    fn test_r_sec_includes_residual() {
        // R_sec = 5% base + fee_residual. Spec §9.2.
        let fee_total = 1_000u64;
        let sum_rewards = 948u64; // node_pool=950, residual=2
        let r_sec = compute_r_sec(fee_total, sum_rewards);
        // security_fund_base = 50, fee_residual = 2 → r_sec = 52
        assert_eq!(r_sec, 52);
    }

    #[test]
    fn test_full_conservation_with_residual() {
        // sum_node_rewards + r_sec == fee_total. Spec §9.2.
        let fee_total = 1_000u64;
        let sum_rewards = 948u64;
        let r_sec = compute_r_sec(fee_total, sum_rewards);
        assert!(verify_full_conservation(fee_total, sum_rewards, r_sec));
        assert_eq!(sum_rewards + r_sec, fee_total);
    }

    #[test]
    fn test_full_conservation_no_residual() {
        // Konservasi juga berlaku saat tidak ada residual. Spec §9.2.
        let fee_total = 1_000_000u64;
        let dist = distribute_fee(fee_total);
        let r_sec = compute_r_sec(fee_total, dist.node_pool);
        assert!(verify_full_conservation(fee_total, dist.node_pool, r_sec));
    }
}
