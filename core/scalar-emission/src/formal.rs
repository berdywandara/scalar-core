//! Formal Verification Runtime Assertions — Deferred Emission Pool
//!
//! Spec §15.5 v11.1-FINAL: runtime assertions untuk 5 invariant Deferred Pool.
//!
//! File TLA+: verification/deferred_pool.tla
//!
//! Runtime assertions ini berjalan dalam debug builds sebagai defense-in-depth.

use crate::accumulator::{E0_SSCL, S_E_SSCL};

// ── Constants dari spec §15.5 ─────────────────────────────────────────────────

/// Maksimum release per epoch = 10% × E₀. Spec §15.5.
pub const DEFERRED_POOL_MAX_RELEASE: u64 = E0_SSCL / 10;

/// Maksimum epoch sejak defer. Spec §15.5.
pub const DEFERRED_POOL_MAX_EPOCHS: u64 = 12;

// ── Deferred Pool State ───────────────────────────────────────────────────────

/// State Deferred Emission Pool. Spec §15.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredPoolState {
    /// D(k): saldo pool saat ini. Spec §15.5 Inv1, Inv2.
    pub balance_sscl: u64,
    /// Σ residual yang masuk pool. Spec §15.5 Inv5.
    pub total_residual_sscl: u64,
    /// Σ yang sudah direlease. Spec §15.5 Inv5.
    pub total_released_sscl: u64,
    /// Epoch sejak defer terakhir. Spec §15.5 Inv4.
    pub epochs_since_defer: u64,
}

impl DeferredPoolState {
    pub fn new() -> Self {
        Self {
            balance_sscl: 0,
            total_residual_sscl: 0,
            total_released_sscl: 0,
            epochs_since_defer: 0,
        }
    }
}

impl Default for DeferredPoolState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Invariant violations ──────────────────────────────────────────────────────

/// Pelanggaran invariant Deferred Pool. Spec §15.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferredPoolViolation {
    /// Inv1: D(k) < 0 (tidak mungkin dengan u64, tapi disertakan untuk kelengkapan).
    NegativeBalance,
    /// Inv2: D(k) > S_E.
    ExceedsSupplyCap { balance: u64, cap: u64 },
    /// Inv3: release > 10% × E₀.
    ExceedsMaxRelease { release: u64, max: u64 },
    /// Inv4: epoch sejak defer > 12.
    ExceedsMaxDeferEpochs { epochs: u64, max: u64 },
    /// Inv5: Σ release > Σ residual (conservation violation).
    ConservationViolation { released: u64, residual: u64 },
}

impl core::fmt::Display for DeferredPoolViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NegativeBalance => write!(f, "Inv1: D(k) < 0 — spec §15.5"),
            Self::ExceedsSupplyCap { balance, cap } => {
                write!(f, "Inv2: D(k)={balance} > S_E={cap} — spec §15.5")
            }
            Self::ExceedsMaxRelease { release, max } => {
                write!(f, "Inv3: release={release} > 10%×E₀={max} — spec §15.5")
            }
            Self::ExceedsMaxDeferEpochs { epochs, max } => {
                write!(f, "Inv4: epochs_since_defer={epochs} > {max} — spec §15.5")
            }
            Self::ConservationViolation { released, residual } => write!(
                f,
                "Inv5: Σreleased={released} > Σresidual={residual} — spec §15.5"
            ),
        }
    }
}

// ── Runtime assertions ────────────────────────────────────────────────────────

/// Verifikasi semua 5 invariant Deferred Pool. Spec §15.5.
///
/// Dipanggil setiap epoch setelah pemrosesan reward.
pub fn assert_deferred_pool_invariants(
    state: &DeferredPoolState,
    release_this_epoch: u64,
) -> Result<(), DeferredPoolViolation> {
    // Inv2: D(k) ≤ S_E
    if state.balance_sscl > S_E_SSCL {
        return Err(DeferredPoolViolation::ExceedsSupplyCap {
            balance: state.balance_sscl,
            cap: S_E_SSCL,
        });
    }

    // Inv3: release ≤ 10% × E₀
    if release_this_epoch > DEFERRED_POOL_MAX_RELEASE {
        return Err(DeferredPoolViolation::ExceedsMaxRelease {
            release: release_this_epoch,
            max: DEFERRED_POOL_MAX_RELEASE,
        });
    }

    // Inv4: epochs_since_defer ≤ 12
    if state.epochs_since_defer > DEFERRED_POOL_MAX_EPOCHS {
        return Err(DeferredPoolViolation::ExceedsMaxDeferEpochs {
            epochs: state.epochs_since_defer,
            max: DEFERRED_POOL_MAX_EPOCHS,
        });
    }

    // Inv5: Σ release ≤ Σ residual (conservation)
    if state.total_released_sscl > state.total_residual_sscl {
        return Err(DeferredPoolViolation::ConservationViolation {
            released: state.total_released_sscl,
            residual: state.total_residual_sscl,
        });
    }

    Ok(())
}

// ── Benchmark scaffold — spec §15.6 ──────────────────────────────────────────

/// Target proving time 2-in/2-out. Spec §15.6.
pub const PROVING_TIME_2IN2OUT_TARGET_MS: u64 = 500;

/// Target proving time 10-in/10-out. Spec §15.6.
pub const PROVING_TIME_10IN10OUT_TARGET_MS: u64 = 500;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_state() -> DeferredPoolState {
        DeferredPoolState {
            balance_sscl: 1_000_000,
            total_residual_sscl: 2_000_000,
            total_released_sscl: 500_000,
            epochs_since_defer: 3,
        }
    }

    // ── runtime_assert_deferred_pool ──────────────────────────────────────────

    #[test]
    fn runtime_assert_deferred_pool_valid() {
        // State valid → semua invariant pass. Spec §15.5.
        let state = valid_state();
        let result = assert_deferred_pool_invariants(&state, 100_000);
        assert!(result.is_ok(), "State valid harus pass semua invariant");
    }

    #[test]
    fn runtime_assert_deferred_pool_inv2_balance_exceeds_se() {
        // Inv2: balance > S_E → violation. Spec §15.5.
        let mut state = valid_state();
        state.balance_sscl = S_E_SSCL + 1;
        let result = assert_deferred_pool_invariants(&state, 0);
        assert!(matches!(
            result,
            Err(DeferredPoolViolation::ExceedsSupplyCap { .. })
        ));
    }

    #[test]
    fn runtime_assert_deferred_pool_inv3_release_too_large() {
        // Inv3: release > 10% × E₀ → violation. Spec §15.5.
        let state = valid_state();
        let too_large = DEFERRED_POOL_MAX_RELEASE + 1;
        let result = assert_deferred_pool_invariants(&state, too_large);
        assert!(matches!(
            result,
            Err(DeferredPoolViolation::ExceedsMaxRelease { .. })
        ));
    }

    #[test]
    fn runtime_assert_deferred_pool_inv4_too_many_epochs() {
        // Inv4: epochs_since_defer > 12 → violation. Spec §15.5.
        let mut state = valid_state();
        state.epochs_since_defer = DEFERRED_POOL_MAX_EPOCHS + 1;
        let result = assert_deferred_pool_invariants(&state, 0);
        assert!(matches!(
            result,
            Err(DeferredPoolViolation::ExceedsMaxDeferEpochs { .. })
        ));
    }

    #[test]
    fn runtime_assert_deferred_pool_inv5_conservation_violation() {
        // Inv5: released > residual → violation. Spec §15.5.
        let mut state = valid_state();
        state.total_released_sscl = state.total_residual_sscl + 1;
        let result = assert_deferred_pool_invariants(&state, 0);
        assert!(matches!(
            result,
            Err(DeferredPoolViolation::ConservationViolation { .. })
        ));
    }

    #[test]
    fn runtime_assert_deferred_pool_inv3_exact_max_ok() {
        // Inv3: release == 10% × E₀ → valid (boundary). Spec §15.5.
        let state = valid_state();
        let result = assert_deferred_pool_invariants(&state, DEFERRED_POOL_MAX_RELEASE);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deferred_pool_constants() {
        // DEFERRED_POOL_MAX_RELEASE = 10% × E₀. Spec §15.5.
        assert_eq!(DEFERRED_POOL_MAX_RELEASE, E0_SSCL / 10);
        // DEFERRED_POOL_MAX_EPOCHS = 12. Spec §15.5.
        assert_eq!(DEFERRED_POOL_MAX_EPOCHS, 12u64);
        // Proving time targets. Spec §15.6.
        assert_eq!(PROVING_TIME_2IN2OUT_TARGET_MS, 500u64);
        assert_eq!(PROVING_TIME_10IN10OUT_TARGET_MS, 500u64);
    }
}
