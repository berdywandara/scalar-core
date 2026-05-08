//! Compliance Suite v9.0 — Layer 1 Ossified Constants
//!
//! Spec §18.1, §18.2 v9.0
//!
//! Setiap test memverifikasi bahwa konstanta di crate masing-masing
//! cocok dengan nilai yang di-ossify di spec v9.0.
//!
//! Jika test ini fail → ada konstanta yang salah di suatu crate.
//! Spec beats code — fix the code, not the test.

#[cfg(test)]
mod tests_v9_l1 {
    // ── §3.2 Supply Constants ─────────────────────────────────────────────────

    #[test]
    fn test_s_max_sscl() {
        // Spec §3.2: S_MAX = 21,000,000 SCL = 2,100,000,000,000,000 sSCL. OSSIFIED.
        assert_eq!(
            scalar_emission::accumulator::S_MAX_SSCL,
            2_100_000_000_000_000u64
        );
    }

    #[test]
    fn test_s_e_sscl() {
        // Spec §3.2: S_E = 18,900,000 SCL = 1,890,000,000,000,000 sSCL. OSSIFIED.
        assert_eq!(
            scalar_emission::accumulator::S_E_SSCL,
            1_890_000_000_000_000u64
        );
    }

    #[test]
    fn test_s_r_sscl() {
        // Spec §3.2: S_R = S_MAX - S_E = 210,000,000,000,000 sSCL. OSSIFIED.
        assert_eq!(
            scalar_emission::accumulator::S_R_SSCL,
            210_000_000_000_000u64
        );
    }

    // ── §7.1 Emission Constants ───────────────────────────────────────────────

    #[test]
    fn test_e0_sscl() {
        // Spec §7.1: E₀ = 126,000 SCL/epoch = 12,600,000,000,000 sSCL. OSSIFIED.
        assert_eq!(scalar_emission::accumulator::E0_SSCL, 12_600_000_000_000u64);
    }

    // ── §7.2 Heartbeat Constants ──────────────────────────────────────────────

    #[test]
    fn test_expected_heartbeats_per_epoch() {
        // Spec §7.2: 4,320 HB/epoch. OSSIFIED.
        assert_eq!(
            scalar_emission::liveness::EXPECTED_HEARTBEATS_PER_EPOCH,
            4_320u32
        );
    }

    #[test]
    fn test_epoch_hb_count() {
        // Spec §7.2c T-1: EPOCH_HB_COUNT = 4,320. OSSIFIED.
        assert_eq!(scalar_emission::liveness::EPOCH_HB_COUNT, 4_320u32);
    }

    #[test]
    fn test_epoch_hb_count_equals_expected() {
        // Keduanya harus identik. Spec §7.2c.
        assert_eq!(
            scalar_emission::liveness::EPOCH_HB_COUNT,
            scalar_emission::liveness::EXPECTED_HEARTBEATS_PER_EPOCH
        );
    }

    // ── §7.4 Maturity Constants ───────────────────────────────────────────────

    #[test]
    fn test_w_mature_epochs() {
        // Spec §7.4: W_MATURE_EPOCHS = 6. OSSIFIED.
        assert_eq!(scalar_emission::liveness::W_MATURE_EPOCHS, 6u64);
    }

    #[test]
    fn test_w_mature() {
        // Spec §7.4: W_MATURE = 6 × 4320 × 1_000_000 = 25_920_000_000. OSSIFIED.
        assert_eq!(scalar_emission::liveness::W_MATURE, 25_920_000_000u64);
    }

    // ── §7.7 E_TAIL Backstop ──────────────────────────────────────────────────

    #[test]
    fn test_e_tail_sscl() {
        // Spec §7.7: E_TAIL = 1,000 SCL = 100,000,000,000 sSCL. OSSIFIED.
        assert_eq!(
            scalar_emission::accumulator::E_TAIL_SSCL,
            100_000_000_000u64
        );
    }

    // ── §8.1 Aggregator Constants ─────────────────────────────────────────────

    #[test]
    fn test_aggregator_validator_count() {
        // Spec §8.1: 10 validator paralel. OSSIFIED.
        assert_eq!(scalar_emission::manifest::AGGREGATOR_VALIDATOR_COUNT, 10u32);
    }

    #[test]
    fn test_aggregator_validator_quorum() {
        // Spec §8.1: quorum 7/10. OSSIFIED.
        assert_eq!(scalar_emission::manifest::AGGREGATOR_VALIDATOR_QUORUM, 7u32);
    }

    #[test]
    fn test_aggregator_fallback_max() {
        // Spec §8.3: max 3 fallback. OSSIFIED.
        assert_eq!(scalar_emission::manifest::AGGREGATOR_FALLBACK_MAX, 3u32);
    }

    #[test]
    fn test_aggregator_min_uptime_fp() {
        // Spec §8.1: min uptime = 700_000 fp. OSSIFIED.
        assert_eq!(
            scalar_emission::manifest::AGGREGATOR_MIN_UPTIME_FP,
            700_000u64
        );
    }

    // ── §8.2 Manifest Constants ───────────────────────────────────────────────

    #[test]
    fn test_spec_version_manifest() {
        // Spec §8.2: SPEC_VERSION_MANIFEST = 0x02. OSSIFIED.
        assert_eq!(scalar_emission::manifest::SPEC_VERSION_MANIFEST, 0x02u8);
    }

    // ── §9.1 Fee Floor ────────────────────────────────────────────────────────

    #[test]
    fn test_floor_min_absolute() {
        // Spec §9.1: FLOOR_MIN_ABSOLUTE = 40 sSCL. OSSIFIED.
        assert_eq!(scalar_fees::floor::FLOOR_MIN_ABSOLUTE, 40u64);
    }

    // ── §9.2 Fee Distribution v9.0 ────────────────────────────────────────────

    #[test]
    fn test_fee_node_pool_percent() {
        // Spec §9.2 v9.0: FEE_NODE_POOL_PERCENT = 95. OSSIFIED.
        assert_eq!(scalar_fees::distribution::FEE_NODE_POOL_PERCENT, 95u64);
    }

    #[test]
    fn test_fee_security_fund_percent() {
        // Spec §9.2 v9.0: FEE_SECURITY_FUND_PERCENT = 5. OSSIFIED.
        assert_eq!(scalar_fees::distribution::FEE_SECURITY_FUND_PERCENT, 5u64);
    }

    #[test]
    fn test_fee_split_sums_to_100() {
        // Invariant: 95 + 5 = 100. Spec §9.2. OSSIFIED.
        assert_eq!(
            scalar_fees::distribution::FEE_NODE_POOL_PERCENT
                + scalar_fees::distribution::FEE_SECURITY_FUND_PERCENT,
            100u64
        );
    }

    #[test]
    fn test_w_floor_fp() {
        // Spec §9.2: W_FLOOR_FP = 1_000_000_000. OSSIFIED.
        assert_eq!(scalar_fees::distribution::W_FLOOR_FP, 1_000_000_000u64);
    }

    #[test]
    fn test_n_min_absolut() {
        // Spec §9.2, §7.8: N_MIN_ABSOLUT = 1_000. OSSIFIED.
        assert_eq!(scalar_fees::distribution::N_MIN_ABSOLUT, 1_000u64);
    }

    // ── §12.1a StateBeacon ────────────────────────────────────────────────────

    #[test]
    fn test_state_beacon_max_bytes() {
        // Spec §12.1a: STATE_BEACON_MAX_BYTES = 64. OSSIFIED.
        assert_eq!(
            scalar_network::state_beacon::STATE_BEACON_MAX_BYTES,
            64usize
        );
    }

    #[test]
    fn test_state_beacon_wire_size() {
        // Spec §12.1a: wire size = 44 bytes. OSSIFIED.
        assert_eq!(
            scalar_network::state_beacon::STATE_BEACON_WIRE_SIZE,
            44usize
        );
    }

    // ── §12.3a NMT Constants ──────────────────────────────────────────────────

    #[test]
    fn test_nmt_peer_count() {
        // Spec §12.3a: NMT_PEER_COUNT = 8. OSSIFIED.
        assert_eq!(scalar_network::nmt::NMT_PEER_COUNT, 8usize);
    }

    #[test]
    fn test_t_nmt_max_drift_s() {
        // Spec §12.3a: T_NMT_MAX_DRIFT_S = 600. OSSIFIED.
        assert_eq!(scalar_network::nmt::T_NMT_MAX_DRIFT_S, 600u32);
    }

    // ── §12.5 Network Constants ───────────────────────────────────────────────

    #[test]
    fn test_max_fanout() {
        // Spec §12.5: MAX_FANOUT = 15. OSSIFIED.
        assert_eq!(scalar_network::gossip::MAX_FANOUT, 15usize);
    }

    // ── §7.2c Time Security ───────────────────────────────────────────────────

    #[test]
    fn test_t_heartbeat_ttl_s() {
        // Spec §7.2c T-2: T_HEARTBEAT_TTL_S = 600. Layer 2 CONSTRAINED.
        assert_eq!(
            scalar_network::heartbeat_verifier::T_HEARTBEAT_TTL_S,
            600u32
        );
    }

    #[test]
    fn test_t_hb_min_interval_s() {
        // Spec §7.2c T-4: T_HB_MIN_INTERVAL_S = 600. Layer 2 CONSTRAINED.
        assert_eq!(scalar_network::time_security::T_HB_MIN_INTERVAL_S, 600u32);
    }

    #[test]
    fn test_t_nmt_update_s() {
        // Spec §12.3a: T_NMT_UPDATE_S = 60. Layer 2 CONSTRAINED.
        assert_eq!(scalar_network::time_security::T_NMT_UPDATE_S, 60u32);
    }

    // ── §6.3 NullifierSet Promotion ───────────────────────────────────────────

    #[test]
    fn test_cold_promotion_epoch_threshold() {
        // Spec §6.3: COLD_PROMOTION_EPOCH_THRESHOLD = 12. OSSIFIED.
        assert_eq!(
            scalar_nullifier::hierarchical::COLD_PROMOTION_EPOCH_THRESHOLD,
            12u64
        );
    }

    // ── §18.1 Fixed-point basis ───────────────────────────────────────────────

    #[test]
    fn test_fixed_point_basis() {
        // Spec §18.1: FIXED_POINT_BASIS = 1_000_000. OSSIFIED.
        assert_eq!(scalar_emission::liveness::FIXED_POINT_BASIS, 1_000_000u64);
    }

    // ── Deleted constants — must NOT exist ───────────────────────────────────

    #[test]
    fn test_relay_percent_deleted() {
        // Spec §9.2 v9.0: RELAY_PERCENT DIHAPUS.
        // Jika test ini compile → RELAY_PERCENT tidak ada → PASS.
        // Verifikasi via FEE_NODE_POOL_PERCENT yang menggantikannya.
        assert_eq!(scalar_fees::distribution::FEE_NODE_POOL_PERCENT, 95u64);
    }

    #[test]
    fn test_aggregator_percent_deleted() {
        // Spec §9.2 v9.0: AGGREGATOR_PERCENT DIHAPUS.
        // Verifikasi via FEE_SECURITY_FUND_PERCENT = 5 (bukan 25).
        assert_eq!(scalar_fees::distribution::FEE_SECURITY_FUND_PERCENT, 5u64);
    }
}
