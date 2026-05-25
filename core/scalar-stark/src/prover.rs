//! Transfer Circuit Prover — Spec §4.1, §4.4, §15.6
//!
//! Bridges legacy ScalarPublicInputs interface to real Winterfell AIR.
//! The real AIR implementation is in transfer_air.rs.
//!
//! Timing test gated behind `bench-hardware` feature per §15.6 decision:
//! benchmark must run on hardware spec (8GB RAM, server CPU), not CI.

pub use crate::transfer_air::{
    TransferProveError, TransferProver, TransferPublicInputs, TransferVerifyError, TRANSFER_BLOWUP,
    TRANSFER_FOLDING, TRANSFER_GRINDING, TRANSFER_NUM_QUERIES,
};

/// Target proving time in ms. OSSIFIED — spec §4.4.
pub const PROVING_TIME_TARGET_MS: u64 = 500;
/// Tolerance ±10ms. OSSIFIED — spec §4.4.
pub const PROVING_TIME_TOLERANCE_MS: u64 = 10;
/// Lower bound: 490ms. Spec §4.4.
pub const PROVING_TIME_MIN_MS: u64 = PROVING_TIME_TARGET_MS - PROVING_TIME_TOLERANCE_MS;
/// Upper bound: 510ms. Spec §4.4.
pub const PROVING_TIME_MAX_MS: u64 = PROVING_TIME_TARGET_MS + PROVING_TIME_TOLERANCE_MS;
/// Hardware variance limit: 700ms. Spec §4.4, §15.6.
pub const PROVING_TIME_HARDWARE_MAX_MS: u64 = 700;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proving_time_constants_match_spec() {
        assert_eq!(PROVING_TIME_TARGET_MS, 500);
        assert_eq!(PROVING_TIME_TOLERANCE_MS, 10);
        assert_eq!(PROVING_TIME_MIN_MS, 490);
        assert_eq!(PROVING_TIME_MAX_MS, 510);
        assert_eq!(PROVING_TIME_HARDWARE_MAX_MS, 700);
    }

    /// Hardware benchmark — skip in CI, run on spec hardware §15.6.
    /// To run: cargo test -p scalar-stark --features bench-hardware -- bench_proving
    #[test]
    #[cfg_attr(not(feature = "bench-hardware"), ignore)]
    fn bench_proving_time_within_hardware_limit() {
        use crate::transfer_air::TransferPublicInputs;
        use std::time::Instant;

        let pi = TransferPublicInputs {
            fee_total_sscl: 40,
            sum_inputs_sscl: 1_000_000_040,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0u8; 32],
            nullifier_active_root: [0u8; 32],
            nullifier_archived_root: [0u8; 32],
            cb_membership_verified: true,
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
        };

        let prover = TransferProver::new();
        let start = Instant::now();
        let _ = prover.prove_transfer(&pi).unwrap();
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Spec §4.4: 490-510ms target normalization (OSSIFIED).
        // Spec §15.6: <=500ms on hardware spec. Hard limit 700ms.
        assert!(
            elapsed_ms <= PROVING_TIME_HARDWARE_MAX_MS,
            "Proving time {}ms exceeds hardware limit {}ms — spec §15.6",
            elapsed_ms,
            PROVING_TIME_HARDWARE_MAX_MS
        );
        println!(
            "Hardware proving time: {}ms (target {}ms ±{}ms, limit {}ms)",
            elapsed_ms,
            PROVING_TIME_TARGET_MS,
            PROVING_TIME_TOLERANCE_MS,
            PROVING_TIME_HARDWARE_MAX_MS
        );
    }
}
