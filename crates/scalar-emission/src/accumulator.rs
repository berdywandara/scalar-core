//! EmissionAccumulator dan FeeAccumulator
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.3 + §B.1 + §B.4.2
//!
//! Semua nilai dalam sSCL (1 SCL = 100_000_000 sSCL).
//!
//! Konstanta ossified (§B.6 Layer 1):
//! - S_E  = 18_900_000 SCL = 1_890_000_000_000_000 sSCL
//! - E₀   = 126_000 SCL/epoch = 12_600_000_000_000 sSCL/epoch
//! - S_max = 21_000_000 SCL

use crate::EmissionError;

/// S_E dalam sSCL. OSSIFIED.
pub const S_E_SSCL: u64 = 18_900_000 * 100_000_000;
/// E₀ dalam sSCL. OSSIFIED.
pub const E0_SSCL:  u64 = 126_000    * 100_000_000;
/// S_max dalam sSCL. OSSIFIED.
pub const S_MAX_SSCL: u64 = 21_000_000 * 100_000_000;

// ── EmissionAccumulator ──────────────────────────────────────────────

/// Tracking total PoU minted M_E. Digunakan MC3 untuk enforce S_E cap.
pub struct EmissionAccumulator {
    pub total_minted: u64,
}

impl EmissionAccumulator {
    pub fn new() -> Self { Self { total_minted: 0 } }

    /// ρ(k) = M_E(k) / S_E dalam fixed-point basis 10^9.
    pub fn rho_fp(&self) -> u128 {
        (self.total_minted as u128)
            .saturating_mul(1_000_000_000)
            .checked_div(S_E_SSCL as u128)
            .unwrap_or(1_000_000_000)
    }

    /// E(k) = E₀ × (1 − ρ(k))² — full integer arithmetic. OSSIFIED.
    pub fn emission_this_epoch(&self) -> u64 {
        let rho_fp         = self.rho_fp();
        let one_minus_rho  = 1_000_000_000u128.saturating_sub(rho_fp);
        let omr_sq         = one_minus_rho
            .saturating_mul(one_minus_rho)
            .checked_div(1_000_000_000)
            .unwrap_or(0);
        ((E0_SSCL as u128).saturating_mul(omr_sq)
            .checked_div(1_000_000_000)
            .unwrap_or(0)) as u64
    }

    /// Verifikasi supply cap sebelum mint (§B.2.2 MC3).
    pub fn check_supply_cap(&self, reward: u64) -> Result<(), EmissionError> {
        let new_total = self.total_minted.checked_add(reward)
            .ok_or(EmissionError::Overflow)?;
        if new_total > S_E_SSCL {
            return Err(EmissionError::SupplyCapExceeded {
                minted: self.total_minted, reward, cap: S_E_SSCL,
            });
        }
        Ok(())
    }

    /// Update M_E setelah epoch dikonfirmasi ≥67%.
    /// Jika epoch DEFERRED: JANGAN panggil fungsi ini (§B.5.2).
    pub fn commit_epoch(&mut self, emission_amount: u64) -> Result<(), EmissionError> {
        self.check_supply_cap(emission_amount)?;
        self.total_minted = self.total_minted
            .checked_add(emission_amount)
            .ok_or(EmissionError::Overflow)?;
        Ok(())
    }

    /// R_i(k) = E(k) × w_i / W(k). Sesuai §B.1.4.
    /// w_i dan W dalam fixed-point basis 1_000_000.
    pub fn reward_for_node(e_k: u64, w_i_fp: u64, w_total_fp: u64)
        -> Result<u64, EmissionError>
    {
        if w_total_fp == 0 { return Err(EmissionError::ZeroTotalWeight); }
        if w_i_fp     == 0 { return Err(EmissionError::BelowUptimeThreshold); }
        Ok(((e_k as u128)
            .saturating_mul(w_i_fp as u128)
            .checked_div(w_total_fp as u128)
            .unwrap_or(0)) as u64)
    }
}

impl Default for EmissionAccumulator {
    fn default() -> Self { Self::new() }
}

// ── FeeAccumulator ───────────────────────────────────────────────────

/// Total fee per epoch. Distribusi 70/25/5 sesuai §B.4.2.
pub struct FeeAccumulator {
    pub total_fee: u64,
}

impl FeeAccumulator {
    pub fn new() -> Self { Self { total_fee: 0 } }

    pub fn add_fee(&mut self, fee: u64) -> Result<(), EmissionError> {
        self.total_fee = self.total_fee.checked_add(fee)
            .ok_or(EmissionError::Overflow)?;
        Ok(())
    }

    /// Return (relay=70%, aggregator=25%, security=5%).
    /// Sisa pembulatan masuk ke relay.
    pub fn distribution(&self) -> (u64, u64, u64) {
        let t   = self.total_fee as u128;
        let agg = (t * 25 / 100) as u64;
        let sec = (t *  5 / 100) as u64;
        let rel = self.total_fee.saturating_sub(agg).saturating_sub(sec);
        (rel, agg, sec)
    }

    pub fn reset(&mut self) { self.total_fee = 0; }
}

impl Default for FeeAccumulator {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── EmissionAccumulator ───────────────────────────────────────────

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
        let r_70   = EmissionAccumulator::reward_for_node(e_k,   700_000, 1_700_000).unwrap();
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

    // ── FeeAccumulator ────────────────────────────────────────────────

    #[test]
    fn test_distribution_sums_to_total() {
        let mut fa = FeeAccumulator::new();
        fa.add_fee(10_000).unwrap();
        fa.add_fee(5_000).unwrap();
        let (r, a, s) = fa.distribution();
        assert_eq!(r + a + s, fa.total_fee);
    }

    #[test]
    fn test_distribution_correct_ratios() {
        let mut fa = FeeAccumulator::new();
        fa.add_fee(10_000).unwrap();
        let (r, a, s) = fa.distribution();
        assert_eq!(s, 500);
        assert_eq!(a, 2_500);
        assert_eq!(r, 7_000);
    }

    #[test]
    fn test_reset() {
        let mut fa = FeeAccumulator::new();
        fa.add_fee(99_999).unwrap();
        fa.reset();
        assert_eq!(fa.total_fee, 0);
    }
}
