// File: crates/scalar-compliance/src/v5_parameters.rs

//! Kumpulan parameter OSSIFIED v5.0 berdasarkan Scalar_Master_Technical_Spec v5.0.
//! Parameter ini bersifat final dan tidak dapat diubah tanpa hard fork.

pub const V5_FIXED_POINT_BASIS: u64 = 1_000_000;
pub const V5_MAX_FANOUT: usize = 15;
pub const V5_PROVING_TIME_TARGET_MS: u64 = 300;
pub const V5_PROVING_TIME_TOLERANCE_MS: u64 = 10;
pub const V5_MAX_ROOT_CANDIDATES: usize = 100;
pub const V5_CRYPTO_VERSION: u8 = 0x01;
pub const V5_EXPECTED_HEARTBEATS_PER_EPOCH: u32 = 4320;
pub const V5_TRANSITION_WINDOW_EPOCHS: u64 = 10;

#[cfg(test)]
mod tests_v5_ossified_parameters {
    use super::*;

    #[test]
    fn test_v5_ossified_fixed_point_basis() {
        assert_eq!(
            V5_FIXED_POINT_BASIS, 1_000_000,
            "OSSIFIED MUTLAK: Zero Floating Point beroperasi pada basis 1.000.000"
        );
    }

    #[test]
    fn test_v5_ossified_max_fanout() {
        assert_eq!(
            V5_MAX_FANOUT, 15,
            "OSSIFIED MUTLAK: Max fanout Kuramoto Gossip tidak boleh melebihi 15"
        );
    }

    #[test]
    fn test_v5_ossified_proving_time() {
        assert_eq!(
            V5_PROVING_TIME_TARGET_MS, 300,
            "OSSIFIED MUTLAK: Target Proving Time harus 300ms (Anti Timing Side-Channel)"
        );
        assert_eq!(
            V5_PROVING_TIME_TOLERANCE_MS, 10,
            "OSSIFIED MUTLAK: Toleransi padding Proving Time harus 10ms"
        );
    }

    #[test]
    fn test_v5_ossified_max_root_candidates() {
        assert_eq!(
            V5_MAX_ROOT_CANDIDATES, 100,
            "OSSIFIED MUTLAK: Max Root Candidates di Pheromone Reconciliation adalah 100"
        );
    }

    #[test]
    fn test_v5_ossified_crypto_version() {
        assert_eq!(
            V5_CRYPTO_VERSION, 0x01,
            "OSSIFIED MUTLAK: Crypto Version awal v5.0 harus 0x01"
        );
    }

    #[test]
    fn test_v5_ossified_heartbeats() {
        assert_eq!(
            V5_EXPECTED_HEARTBEATS_PER_EPOCH, 4320,
            "OSSIFIED MUTLAK: Expected heartbeats per epoch harus 4320"
        );
    }

    #[test]
    fn test_v5_ossified_transition_window() {
        assert_eq!(
            V5_TRANSITION_WINDOW_EPOCHS, 10,
            "OSSIFIED MUTLAK: Transition Window untuk Crypto Version Upgrade harus 10 Epochs"
        );
    }
}
