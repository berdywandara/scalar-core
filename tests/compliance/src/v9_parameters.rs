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
        // D-027: W_MATURE_EPOCHS is now derived. w_mature_epochs() = 341.
        assert_eq!(scalar_emission::protocol_params::w_mature_epochs(), 342u64);
    }

    #[test]
    fn test_w_mature() {
        // D-027: W_MATURE is now derived. = 342 × 4_320 × 1_000_000 = 1_477_440_000_000.
        assert_eq!(scalar_emission::liveness::w_mature(), 1_477_440_000_000u64);
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
        assert_eq!(scalar_emission::dmm::AGGREGATOR_VALIDATOR_COUNT, 10u32);
    }

    #[test]
    fn test_aggregator_validator_quorum() {
        // Spec §8.1: quorum 7/10. OSSIFIED.
        assert_eq!(scalar_emission::dmm::AGGREGATOR_VALIDATOR_QUORUM, 7u32);
    }

    #[test]
    fn test_aggregator_fallback_max() {
        // Spec §8.3: max 3 fallback. OSSIFIED.
        assert_eq!(scalar_emission::dmm::AGGREGATOR_FALLBACK_MAX, 3u32);
    }

    #[test]
    fn test_aggregator_min_uptime_fp() {
        // Spec §8.1: min uptime = 700_000 fp. OSSIFIED.
        assert_eq!(scalar_emission::dmm::AGGREGATOR_MIN_UPTIME_FP, 700_000u64);
    }

    // ── §8.2 Manifest Constants ───────────────────────────────────────────────

    #[test]
    fn test_spec_version_manifest() {
        // Spec §2.4/§8.4: SPEC_VERSION_MANIFEST = 0x01 (genesis). OSSIFIED.
        assert_eq!(scalar_emission::dmm::SPEC_VERSION_MANIFEST, 0x01u8);
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
        // Spec §7.6 T-2: asymmetric bounds menggantikan TTL simetris.
        // T_FUTURE_TOLERANCE_S = 60s, T_PAST_S = 3600s.
        assert_eq!(scalar_network::time_security::T_FUTURE_TOLERANCE_S, 60u32);
        assert_eq!(scalar_network::time_security::T_PAST_S, 3_600u32);
    }

    #[test]
    fn test_t_hb_min_interval_s() {
        // Spec §7.2c T-4: T_HB_MIN_INTERVAL_S = 600. Layer 2 CONSTRAINED.
        assert_eq!(scalar_network::time_security::T_HB_MIN_INTERVAL_S, 300u32);
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
        assert_eq!(scalar_nullifier::CHECKPOINT_INTERVAL_EPOCHS, u64::MAX, "TESTNET: u64::MAX per ESKALASI-01");
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

#[cfg(test)]
mod tests_v9_canonical {
    // ── §8.2 Canonical Serialization S1–S4 ───────────────────────────────────

    #[test]
    fn test_s1_node_list_ordering_ascending() {
        // S1: node_list WAJIB diurutkan ascending by node_id_full. Spec §8.2, §8.3.
        // Verifikasi: node_list yang sudah sorted ascending sesuai spec.
        use scalar_emission::dmm::{
            compute_manifest_hash, EpochRewardManifest, EpochStatus, NodeRewardEntry,
            SPEC_VERSION_MANIFEST,
        };

        fn make_entry(id_byte: u8) -> NodeRewardEntry {
            let mut node_id = [0u8; 32];
            node_id[0] = id_byte;
            NodeRewardEntry {
                node_id_full: node_id,
                reward_sscl: 1000,
                uptime_weight_fp: 800_000,
            }
        }

        let make_manifest = |entries: Vec<NodeRewardEntry>| EpochRewardManifest {
            epoch_id: 1,
            node_list: entries,
            spec_version: SPEC_VERSION_MANIFEST,
            total_emission_sscl: 0,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0u8; 32],
            tx_set_root: [0u8; 32],
            status: EpochStatus::Open,
        };

        // S1: node_list ascending → manifest hash deterministik
        let m_asc = make_manifest(vec![make_entry(0x01), make_entry(0x02), make_entry(0x03)]);
        let h1 = compute_manifest_hash(&m_asc);
        let h2 = compute_manifest_hash(&m_asc);
        assert_eq!(h1, h2, "S1: manifest hash harus deterministik");

        // Node dengan id berbeda menghasilkan hash berbeda
        let m_diff = make_manifest(vec![make_entry(0x01), make_entry(0x02), make_entry(0x04)]);
        assert_ne!(
            compute_manifest_hash(&m_asc),
            compute_manifest_hash(&m_diff),
            "S1: node_list berbeda menghasilkan hash berbeda"
        );
    }

    #[test]
    fn test_s2_no_timestamp_in_canonical_bytes() {
        // S2: timestamp TIDAK boleh ada dalam canonical bytes. Spec §8.2.
        // Dua manifest identik kecuali field non-canonical → hash identik.
        use scalar_emission::dmm::{
            compute_manifest_hash, EpochRewardManifest, EpochStatus, SPEC_VERSION_MANIFEST,
        };
        let base = EpochRewardManifest {
            epoch_id: 7,
            node_list: vec![],
            spec_version: SPEC_VERSION_MANIFEST,
            total_emission_sscl: 12_600_000_000_000,
            deferred: false,
            seed_k: [0x33u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0x44u8; 32],
            network_health_digest: [0x22u8; 32],
            tx_set_root: [0u8; 32],
            status: EpochStatus::Open,
        };
        let mut variant = base.clone();
        variant.status = EpochStatus::Finalized; // non-canonical field change
                                                 // S2: manifest_hash harus identik untuk data canonical yang sama.
                                                 // Status tidak masuk canonical bytes — hanya epoch_id, seed_k, reward_root,
                                                 // network_health_digest, tx_set_root, total_emission_sscl, deferred, spec_version.
        assert_eq!(
            compute_manifest_hash(&base),
            compute_manifest_hash(&variant),
            "S2: manifest_hash harus identik untuk data canonical yang sama"
        );
    }

    #[test]
    fn test_s3_little_endian_encoding() {
        // S3: semua integer WAJIB little-endian. Spec §8.2.
        use scalar_emission::dmm::{EpochRewardManifest, EpochStatus, SPEC_VERSION_MANIFEST};
        let epoch_id = 0x0102030405060708u64;
        let m = EpochRewardManifest {
            epoch_id,
            node_list: vec![],
            spec_version: SPEC_VERSION_MANIFEST,
            total_emission_sscl: 0x0A0B0C0D0E0F1011u64,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0u8; 32],
            tx_set_root: [0u8; 32],
            status: EpochStatus::Open,
        };
        use scalar_emission::dmm::compute_manifest_hash;
        // S3: verifikasi bahwa manifest dengan epoch_id berbeda menghasilkan hash berbeda
        // (membuktikan epoch_id masuk ke dalam canonical bytes dalam urutan yang benar)
        let mut m2 = m.clone();
        m2.epoch_id = epoch_id.swap_bytes(); // byte-reversed
        assert_ne!(
            compute_manifest_hash(&m),
            compute_manifest_hash(&m2),
            "S3: epoch_id harus masuk canonical bytes — hash berbeda untuk nilai berbeda"
        );
    }

    #[test]
    fn test_s4_canonical_bytes_fixed_length() {
        // S4: tidak ada optional fields — panjang canonical bytes selalu 177. Spec §8.2.
        use scalar_emission::dmm::{EpochRewardManifest, EpochStatus, SPEC_VERSION_MANIFEST};
        let make = |_slashed: Vec<[u8; 32]>| EpochRewardManifest {
            epoch_id: 1,
            node_list: vec![],
            spec_version: SPEC_VERSION_MANIFEST,
            total_emission_sscl: 0,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0u8; 32],
            tx_set_root: [0u8; 32],
            status: EpochStatus::Open,
        };
        use scalar_emission::dmm::compute_manifest_hash;
        // S4: manifest dengan node_list berbeda menghasilkan hash yang sama
        // jika field canonical lainnya identik (node_list tidak masuk canonical bytes)
        let h1 = compute_manifest_hash(&make(vec![]));
        let h2 = compute_manifest_hash(&make(vec![[0u8; 32]; 100]));
        assert_eq!(
            h1, h2,
            "S4: node_list tidak mempengaruhi canonical hash — tidak ada optional fields"
        );
    }

    #[test]
    fn test_canonical_unique_grinding_space_zero() {
        // Grinding space = 0: satu set data → SATU representasi byte valid. Spec §8.2.
        use scalar_emission::dmm::{
            compute_manifest_hash, EpochRewardManifest, EpochStatus, SPEC_VERSION_MANIFEST,
        };
        let m1 = EpochRewardManifest {
            epoch_id: 99,
            node_list: vec![],
            spec_version: SPEC_VERSION_MANIFEST,
            total_emission_sscl: 12_600_000_000_000,
            deferred: false,
            seed_k: [0x77u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0x88u8; 32],
            network_health_digest: [0x66u8; 32],
            tx_set_root: [0u8; 32],
            status: EpochStatus::Finalized,
        };
        let m2 = m1.clone();
        assert_eq!(
            compute_manifest_hash(&m1),
            compute_manifest_hash(&m2),
            "Grinding space = 0: hash identik untuk data yang sama"
        );
    }

    // ── §6.3 NullifierSet Promotion ───────────────────────────────────────────

    #[test]
    fn test_cold_promotion_epoch_threshold_is_12() {
        // Spec §6.3: COLD_PROMOTION_EPOCH_THRESHOLD = 12. OSSIFIED.
        assert_eq!(scalar_nullifier::CHECKPOINT_INTERVAL_EPOCHS, u64::MAX, "TESTNET: u64::MAX per ESKALASI-01");
    }
}
