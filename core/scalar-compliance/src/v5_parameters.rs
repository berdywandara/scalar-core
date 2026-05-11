// File: crates/scalar-compliance/src/v5_parameters.rs
//
// Parameter OSSIFIED v5.0 berdasarkan Scalar_Master_Technical_Spec v5.0.
// Parameter ini bersifat final dan tidak dapat diubah tanpa hard fork.
// Sumber kebenaran: §2.6, §4.4, §6, §7, §9, §12, §18.1

// ── §2.6 CryptoVersion Registry ─────────────────────────────────────
/// T_TRANSITION_EPOCHS: selama 2 epoch, kedua versi (lama+baru) valid.
/// Spec §2.6: "T_TRANSITION_EPOCHS = 2 epoch (60 hari)"
pub const V5_TRANSITION_WINDOW_EPOCHS: u64 = 2;

pub const V5_CRYPTO_VERSION: u8 = 0x01;

// ── §4.4 Transfer Circuit ────────────────────────────────────────────
/// Total constraints 2-in/2-out termasuk C9+C10. Spec §4.4.
pub const V5_TRANSFER_CONSTRAINTS_2_2: usize = 52_088;
/// Total constraints 10-in/10-out. Spec §4.4.
pub const V5_TRANSFER_CONSTRAINTS_10_10: usize = 260_000;
/// Max inputs/outputs per tx. OSSIFIED §4.4.
pub const V5_MAX_IO: u32 = 10;

// ── §7 PoU Emission ──────────────────────────────────────────────────
pub const V5_FIXED_POINT_BASIS: u64 = 1_000_000;
/// E₀ = 126_000 SCL/epoch = 12_600_000_000_000 sSCL
pub const V5_E0_SSCL: u64 = 126_000 * 100_000_000;
/// S_E = 18_900_000 SCL = 1_890_000_000_000_000 sSCL
pub const V5_S_E_SSCL: u64 = 18_900_000 * 100_000_000;
/// Expected heartbeats per epoch (30 hari × 144 blok/hari).
pub const V5_EXPECTED_HEARTBEATS_PER_EPOCH: u32 = 4320;

// ── §9 Fee Model ──────────────────────────────────────────────────────
/// FLOOR_MIN_ABSOLUTE = 40 sSCL. OSSIFIED §9.
pub const V5_FLOOR_MIN_ABSOLUTE: u64 = 40;
/// Score formula intra-batch: PREMIUM / (1 + (io) × 0.1). OSSIFIED.
pub const V5_MAX_FANOUT: usize = 15;
/// MAX_ROOT_CANDIDATES. OSSIFIED §12.
pub const V5_MAX_ROOT_CANDIDATES: usize = 100;

// ── §2.5 Proving Time ─────────────────────────────────────────────────
pub const V5_PROVING_TIME_TARGET_MS: u64 = 500;
pub const V5_PROVING_TIME_TOLERANCE_MS: u64 = 10;

// ── §7.3 PoU Mint Domain ─────────────────────────────────────────────
/// POU_MINT_DOMAIN = 0x706f755f6d696e74. OSSIFIED §5.2 MC2.
pub const V5_POU_MINT_DOMAIN: u64 = 0x706f755f6d696e74;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v5_transition_window_is_2_epochs() {
        // Spec §2.6: T_TRANSITION_EPOCHS = 2 epoch (60 hari)
        assert_eq!(
            V5_TRANSITION_WINDOW_EPOCHS, 2,
            "OSSIFIED: T_TRANSITION_EPOCHS harus 2, bukan 10"
        );
    }

    #[test]
    fn test_v5_crypto_version_is_0x01() {
        assert_eq!(V5_CRYPTO_VERSION, 0x01);
    }

    #[test]
    fn test_v5_transfer_constraints_2_2() {
        // Spec §4.4: ~40,650 constraints untuk 2-in/2-out
        assert_eq!(V5_TRANSFER_CONSTRAINTS_2_2, 52_088);
    }

    #[test]
    fn test_v5_transfer_constraints_10_10() {
        assert_eq!(V5_TRANSFER_CONSTRAINTS_10_10, 260_000);
    }

    #[test]
    fn test_v5_max_io_is_10() {
        // OSSIFIED §4.4
        assert_eq!(V5_MAX_IO, 10);
    }

    #[test]
    fn test_v5_floor_min_absolute_is_40() {
        assert_eq!(V5_FLOOR_MIN_ABSOLUTE, 40);
    }

    #[test]
    fn test_v5_max_fanout_ossified_at_15() {
        assert_eq!(V5_MAX_FANOUT, 15);
    }

    #[test]
    fn test_v5_proving_time_constants() {
        assert_eq!(V5_PROVING_TIME_TARGET_MS, 500);
        assert_eq!(V5_PROVING_TIME_TOLERANCE_MS, 10);
    }

    #[test]
    fn test_v5_pou_mint_domain() {
        assert_eq!(V5_POU_MINT_DOMAIN, 0x706f755f6d696e74);
    }

    #[test]
    fn test_v5_s_e_sscl() {
        assert_eq!(V5_S_E_SSCL, 1_890_000_000_000_000u64);
    }

    #[test]
    fn test_v5_e0_sscl() {
        assert_eq!(V5_E0_SSCL, 12_600_000_000_000u64);
    }
}

#[cfg(test)]
mod tests_compliance {
    use scalar_emission::liveness::{W_MATURE, W_MATURE_EPOCHS};

    // ── §7.4 Maturity Constants ───────────────────────────────────────────

    #[test]
    fn test_w_mature_epochs_ossified() {
        assert_eq!(W_MATURE_EPOCHS, 6u64);
    }

    #[test]
    fn test_w_mature_value_ossified() {
        assert_eq!(W_MATURE, 25_920_000_000u64);
    }

    // ── §9.2 Fee Distribution Constants v9.0 ─────────────────────────────
    #[test]
    fn test_fee_node_pool_percent_ossified() {
        // Spec §9.2 v9.0: node pool = 95%. RELAY_PERCENT (70) DIHAPUS.
        assert_eq!(scalar_fees::distribution::FEE_NODE_POOL_PERCENT, 95u64);
    }
    #[test]
    fn test_fee_security_fund_percent_ossified() {
        // Spec §9.2: security fund = 5%. OSSIFIED.
        assert_eq!(scalar_fees::distribution::FEE_SECURITY_FUND_PERCENT, 5u64);
    }
    #[test]
    fn test_fee_split_sums_to_100_ossified() {
        // Spec §9.2: 95 + 5 = 100. OSSIFIED.
        assert_eq!(
            scalar_fees::distribution::FEE_NODE_POOL_PERCENT
                + scalar_fees::distribution::FEE_SECURITY_FUND_PERCENT,
            100u64
        );
    }
    #[test]
    fn test_w_floor_fp_ossified() {
        // Spec §9.2: W_FLOOR_FP = 1_000_000_000. OSSIFIED.
        assert_eq!(scalar_fees::distribution::W_FLOOR_FP, 1_000_000_000u64);
    }

    // ── §3.3 Denomination Constants ───────────────────────────────────────

    #[test]
    fn test_denomination_count_ossified() {
        assert_eq!(
            scalar_wallet_core::denomination::DENOMINATION_COUNT,
            17usize
        );
    }

    #[test]
    fn test_d1_ossified() {
        assert_eq!(scalar_wallet_core::denomination::D1_SSCL, 1u64);
    }

    #[test]
    fn test_d17_ossified() {
        assert_eq!(scalar_wallet_core::denomination::D17_SSCL, 100_000_000u64);
    }

    #[test]
    fn test_scl_to_sscl_ossified() {
        assert_eq!(
            scalar_wallet_core::denomination::SCL_TO_SSCL,
            100_000_000u64
        );
    }
}
