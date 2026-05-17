//! EmissionAccumulator dan FeeAccumulator
//!
//! Spec §3.2, §7.1, §9.2 v9.0.
//!
//! Semua nilai dalam sSCL (1 SCL = 100_000_000 sSCL).
//!
//! Konstanta ossified:
//! - S_E   = 18_900_000 SCL = 1_890_000_000_000_000 sSCL  §3.2
//! - E₀    = 126_000 SCL/epoch = 12_600_000_000_000 sSCL  §7.1
//! - S_MAX = 21_000_000 SCL = 2_100_000_000_000_000 sSCL  §3.2

use crate::EmissionError;

/// S_E dalam sSCL. OSSIFIED — spec §3.2.
pub const S_E_SSCL: u64 = 18_900_000 * 100_000_000;
/// E₀ dalam sSCL. OSSIFIED — spec §7.1.
pub const E0_SSCL: u64 = 126_000 * 100_000_000;
/// S_MAX dalam sSCL. OSSIFIED — spec §3.2.
pub const S_MAX_SSCL: u64 = 21_000_000 * 100_000_000;

// ── EmissionAccumulator ───────────────────────────────────────────────────────

/// Tracking total PoU minted M_E. Digunakan MC3 untuk enforce S_E cap.
pub struct EmissionAccumulator {
    pub total_minted: u64,
}

impl EmissionAccumulator {
    pub fn new() -> Self {
        Self { total_minted: 0 }
    }

    /// ρ(k) = M_E(k) / S_E dalam fixed-point basis 10^9.
    pub fn rho_fp(&self) -> u128 {
        (self.total_minted as u128)
            .saturating_mul(1_000_000_000)
            .checked_div(S_E_SSCL as u128)
            .unwrap_or(1_000_000_000)
    }

    /// E(k) = E₀ × (1 − ρ(k))² — full integer arithmetic. OSSIFIED — spec §7.1.
    pub fn emission_this_epoch(&self) -> u64 {
        let rho_fp = self.rho_fp();
        let one_minus_rho = 1_000_000_000u128.saturating_sub(rho_fp);
        let omr_sq = one_minus_rho
            .saturating_mul(one_minus_rho)
            .checked_div(1_000_000_000)
            .unwrap_or(0);
        ((E0_SSCL as u128)
            .saturating_mul(omr_sq)
            .checked_div(1_000_000_000)
            .unwrap_or(0)) as u64
    }

    /// Verifikasi supply cap sebelum mint — spec §B.2.2 MC3.
    pub fn check_supply_cap(&self, reward: u64) -> Result<(), EmissionError> {
        let new_total = self
            .total_minted
            .checked_add(reward)
            .ok_or(EmissionError::Overflow)?;
        if new_total > S_E_SSCL {
            return Err(EmissionError::SupplyCapExceeded {
                minted: self.total_minted,
                reward,
                cap: S_E_SSCL,
            });
        }
        Ok(())
    }

    /// Update M_E setelah epoch dikonfirmasi.
    /// Jika epoch DEFERRED: JANGAN panggil fungsi ini — spec §B.5.2.
    pub fn commit_epoch(&mut self, emission_amount: u64) -> Result<(), EmissionError> {
        self.check_supply_cap(emission_amount)?;
        self.total_minted = self
            .total_minted
            .checked_add(emission_amount)
            .ok_or(EmissionError::Overflow)?;
        Ok(())
    }

    /// R_i(k) = E(k) × w_i / W(k). Spec §7.
    /// w_i dan W dalam fixed-point basis 1_000_000.
    pub fn reward_for_node(e_k: u64, w_i_fp: u64, w_total_fp: u64) -> Result<u64, EmissionError> {
        if w_total_fp == 0 {
            return Err(EmissionError::ZeroTotalWeight);
        }
        if w_i_fp == 0 {
            return Err(EmissionError::BelowUptimeThreshold);
        }
        Ok(((e_k as u128)
            .saturating_mul(w_i_fp as u128)
            .checked_div(w_total_fp as u128)
            .unwrap_or(0)) as u64)
    }
}

impl Default for EmissionAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

// ── FeeAccumulator ────────────────────────────────────────────────────────────

/// Total fee per epoch. Distribusi 95/5 sesuai spec §9.2 v9.0.
///
/// v9.0: RELAY_PERCENT (70) dan AGGREGATOR_PERCENT (25) DIHAPUS.
/// Diganti: FEE_NODE_POOL_PERCENT (95) + FEE_SECURITY_FUND_PERCENT (5).
pub struct FeeAccumulator {
    pub total_fee: u64,
}

impl FeeAccumulator {
    pub fn new() -> Self {
        Self { total_fee: 0 }
    }

    pub fn add_fee(&mut self, fee: u64) -> Result<(), EmissionError> {
        self.total_fee = self
            .total_fee
            .checked_add(fee)
            .ok_or(EmissionError::Overflow)?;
        Ok(())
    }

    /// Return (node_pool=95%, security_fund=5%). Spec §9.2 v9.0.
    ///
    /// node_pool = uptime-weighted distribution ke semua node.
    /// security_fund = protocol reserve.
    /// Sisa pembulatan integer masuk ke security_fund.
    /// Invariant: node_pool + security_fund == total_fee.
    pub fn distribution(&self) -> (u64, u64) {
        let t = self.total_fee as u128;
        let node_pool = (t * 95 / 100) as u64;
        let security_fund = self.total_fee.saturating_sub(node_pool);
        (node_pool, security_fund)
    }

    pub fn reset(&mut self) {
        self.total_fee = 0;
    }
}

impl Default for FeeAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── EmissionAccumulator ───────────────────────────────────────────────────

    #[test]
    fn test_initial_emission_equals_e0() {
        assert_eq!(EmissionAccumulator::new().emission_this_epoch(), E0_SSCL);
    }

    #[test]
    fn test_rho_zero_at_start() {
        assert_eq!(EmissionAccumulator::new().rho_fp(), 0);
    }

    #[test]
    fn test_emission_zero_when_pool_exhausted() {
        let mut acc = EmissionAccumulator::new();
        acc.total_minted = S_E_SSCL;
        assert_eq!(acc.emission_this_epoch(), 0);
    }

    #[test]
    fn test_emission_decreases_monotonically() {
        let mut acc = EmissionAccumulator::new();
        let e0 = acc.emission_this_epoch();
        acc.total_minted = S_E_SSCL / 2;
        let e_half = acc.emission_this_epoch();
        acc.total_minted = S_E_SSCL * 9 / 10;
        let e_90 = acc.emission_this_epoch();
        assert!(e0 > e_half && e_half > e_90);
    }

    #[test]
    fn test_supply_cap_exceeded() {
        let mut acc = EmissionAccumulator::new();
        acc.total_minted = S_E_SSCL - 500;
        assert!(matches!(
            acc.check_supply_cap(1000),
            Err(EmissionError::SupplyCapExceeded { .. })
        ));
    }

    #[test]
    fn test_commit_epoch_updates_total() {
        let mut acc = EmissionAccumulator::new();
        let e_k = acc.emission_this_epoch();
        acc.commit_epoch(e_k).unwrap();
        assert_eq!(acc.total_minted, e_k);
    }

    #[test]
    fn test_reward_proportional() {
        let e_k = 1_000_000_000_000u64;
        let r_full = EmissionAccumulator::reward_for_node(e_k, 1_000_000, 1_700_000).unwrap();
        let r_70 = EmissionAccumulator::reward_for_node(e_k, 700_000, 1_700_000).unwrap();
        assert!(r_full > r_70);
        assert!(r_full + r_70 <= e_k);
    }

    #[test]
    fn test_reward_zero_weight_error() {
        assert!(matches!(
            EmissionAccumulator::reward_for_node(1000, 0, 1000),
            Err(EmissionError::BelowUptimeThreshold)
        ));
    }

    // ── FeeAccumulator v9.0 ───────────────────────────────────────────────────

    #[test]
    fn test_distribution_sums_to_total() {
        // Spec §9.2: node_pool + security_fund == total_fee. Konservasi token.
        let mut fa = FeeAccumulator::new();
        fa.add_fee(10_000).unwrap();
        fa.add_fee(5_000).unwrap();
        let (node_pool, security_fund) = fa.distribution();
        assert_eq!(node_pool + security_fund, fa.total_fee);
    }

    #[test]
    fn test_distribution_correct_ratios_v9() {
        // Spec §9.2 v9.0: 95/5. BUKAN 70/25/5.
        let mut fa = FeeAccumulator::new();
        fa.add_fee(10_000).unwrap();
        let (node_pool, security_fund) = fa.distribution();
        assert_eq!(node_pool, 9_500);
        assert_eq!(security_fund, 500);
    }

    #[test]
    fn test_distribution_100_sscl() {
        // 100 sSCL: node_pool=95, security_fund=5.
        let mut fa = FeeAccumulator::new();
        fa.add_fee(100).unwrap();
        let (node_pool, security_fund) = fa.distribution();
        assert_eq!(node_pool, 95);
        assert_eq!(security_fund, 5);
    }

    #[test]
    fn test_distribution_rounding_no_loss() {
        // fee=1: node_pool=0 (floor(1*95/100)), security_fund=1. Konservasi.
        let mut fa = FeeAccumulator::new();
        fa.add_fee(1).unwrap();
        let (node_pool, security_fund) = fa.distribution();
        assert_eq!(node_pool + security_fund, 1);
    }

    #[test]
    fn test_reset() {
        let mut fa = FeeAccumulator::new();
        fa.add_fee(99_999).unwrap();
        fa.reset();
        assert_eq!(fa.total_fee, 0);
    }
}

// ── E_TAIL Backstop — spec §7.1, §7.7 ────────────────────────────────────────

/// E_TAIL = 1,000 SCL/epoch = 100,000,000,000 sSCL. OSSIFIED — spec §7.7.
///
/// Tail emission backstop — minimum emission per epoch.
/// Ketika E(k) < E_TAIL, S_R (reserve) digunakan sebagai backstop.
/// E_active(k) = max(E(k), E_TAIL) — digunakan di seluruh reward calculation.
pub const E_TAIL_SSCL: u64 = 1_000 * 100_000_000;

/// S_R — Reserve pool untuk tail emission backstop. Spec §7.7, §3.2.
/// S_R = S_MAX - S_E = 21,000,000 - 18,900,000 = 2,100,000 SCL.
/// S_R bukan time-locked governance reserve — ini adalah tail emission backstop.
/// Aktif ketika E(k) < E_TAIL_SSCL.
pub const S_R_SSCL: u64 = S_MAX_SSCL - S_E_SSCL;

/// Compute E_active(k) = max(E(k), E_TAIL). Spec §7.1, §7.7.
///
/// E_active digunakan di seluruh reward calculation dan MC4 circuit.
/// E(k) murni hanya digunakan untuk menentukan kapan S_R perlu digunakan.
///
/// Ketika E(k) < E_TAIL_SSCL:
///   - E_active = E_TAIL_SSCL (backstop aktif)
///   - S_R digunakan sebagai sumber funding
pub fn compute_e_active(e_k: u64) -> u64 {
    // Spec §7.1: E_active(k) = max(E(k), E_TAIL). OSSIFIED.
    e_k.max(E_TAIL_SSCL)
}

/// Cek apakah S_R (backstop) sedang aktif untuk epoch ini. Spec §7.7.
///
/// S_R aktif jika E(k) < E_TAIL_SSCL.
/// Saat S_R aktif: reward dibayar dari S_R, bukan dari emission pool S_E.
pub fn is_backstop_active(e_k: u64) -> bool {
    // Spec §7.7: S_R digunakan ketika E(k) < E_TAIL
    e_k < E_TAIL_SSCL
}

#[cfg(test)]
mod e_tail_tests {
    use super::*;

    #[test]
    fn test_e_tail_sscl_value() {
        // Spec §7.7: E_TAIL = 1,000 SCL = 100,000,000,000 sSCL. OSSIFIED.
        assert_eq!(E_TAIL_SSCL, 100_000_000_000u64);
    }

    #[test]
    fn test_s_r_sscl_value() {
        // Spec §3.2: S_R = S_MAX - S_E = 2,100,000 SCL = 210,000,000,000,000 sSCL.
        assert_eq!(S_R_SSCL, S_MAX_SSCL - S_E_SSCL);
        assert_eq!(S_R_SSCL, 2_100_000 * 100_000_000);
    }

    #[test]
    fn test_compute_e_active_above_tail() {
        // E(k) > E_TAIL → E_active = E(k). Spec §7.1.
        let e_k = E_TAIL_SSCL + 1_000;
        assert_eq!(compute_e_active(e_k), e_k);
    }

    #[test]
    fn test_compute_e_active_below_tail() {
        // E(k) < E_TAIL → E_active = E_TAIL. Spec §7.1.
        let e_k = E_TAIL_SSCL - 1;
        assert_eq!(compute_e_active(e_k), E_TAIL_SSCL);
    }

    #[test]
    fn test_compute_e_active_at_tail() {
        // E(k) = E_TAIL → E_active = E_TAIL. Spec §7.1.
        assert_eq!(compute_e_active(E_TAIL_SSCL), E_TAIL_SSCL);
    }

    #[test]
    fn test_compute_e_active_zero() {
        // E(k) = 0 (pool exhausted) → E_active = E_TAIL. Spec §7.1.
        assert_eq!(compute_e_active(0), E_TAIL_SSCL);
    }

    #[test]
    fn test_compute_e_active_at_e0() {
        // E(k) = E0 (epoch 0) → E_active = E0 (jauh > E_TAIL). Spec §7.1.
        assert_eq!(compute_e_active(E0_SSCL), E0_SSCL);
        const { assert!(E0_SSCL > E_TAIL_SSCL) };
    }

    #[test]
    fn test_backstop_active_below_tail() {
        // E(k) < E_TAIL → backstop aktif. Spec §7.7.
        assert!(is_backstop_active(E_TAIL_SSCL - 1));
        assert!(is_backstop_active(0));
    }

    #[test]
    fn test_backstop_not_active_at_tail() {
        // E(k) = E_TAIL → backstop TIDAK aktif. Spec §7.7.
        assert!(!is_backstop_active(E_TAIL_SSCL));
    }

    #[test]
    fn test_backstop_not_active_above_tail() {
        // E(k) > E_TAIL → backstop tidak aktif. Spec §7.7.
        assert!(!is_backstop_active(E_TAIL_SSCL + 1));
        assert!(!is_backstop_active(E0_SSCL));
    }

    #[test]
    fn test_e_tail_less_than_e0() {
        // E_TAIL << E0. Spec §7.7.
        const { assert!(E_TAIL_SSCL < E0_SSCL) };
        // E0/E_TAIL ≈ 126 — tail adalah 1/126 dari initial emission
        const { assert!(E0_SSCL / E_TAIL_SSCL >= 100) };
    }

    #[test]
    fn test_s_r_is_tail_backstop_not_governance() {
        // Spec §3.2, §7.7: S_R adalah tail backstop, BUKAN governance reserve.
        // S_R > 0 memastikan tail emission bisa dibayar.
        const { assert!(S_R_SSCL > 0) };
        // S_R = 2,100,000 SCL — cukup besar untuk backstop jangka panjang.
        assert_eq!(S_R_SSCL, 210_000_000_000_000u64);
    }

    #[test]
    fn test_e_active_always_at_least_e_tail() {
        // Invariant: E_active(k) ≥ E_TAIL untuk semua E(k). Spec §7.1.
        for e_k in [
            0u64,
            1,
            E_TAIL_SSCL / 2,
            E_TAIL_SSCL - 1,
            E_TAIL_SSCL,
            E0_SSCL,
        ] {
            assert!(
                compute_e_active(e_k) >= E_TAIL_SSCL,
                "E_active harus ≥ E_TAIL untuk e_k={}",
                e_k
            );
        }
    }
}
