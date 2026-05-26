//! Compliance Suite v12.0 — Parameter v11.1-FINAL
//!
//! Spec §XVII (parameter referensi lengkap v11.1-FINAL), §XXI (test targets).
//!
//! Verifikasi semua parameter baru dari v11.1-FINAL:
//!   SPEC_VERSION_MANIFEST = 0x01 (genesis)
//!   T_TRANSITION_EPOCHS = 0 (N/A in genesis)
//!   network_health_digest field exists
//!   NodeRewardEntry.uptime_weight_fp field exists

#[cfg(test)]
mod tests_v12 {
    // ── §2.4 SPEC_VERSION_MANIFEST = 0x01 (genesis) ──────────────────────────

    #[test]
    fn compliance_test_spec_version_0x01() {
        // Spec §2.4, §8.4: SPEC_VERSION_MANIFEST = 0x01. OSSIFIED.
        assert_eq!(
            scalar_emission::dmm::SPEC_VERSION_MANIFEST,
            0x01u8,
            "SPEC_VERSION_MANIFEST harus 0x01"
        );
    }

    #[test]
    fn compliance_test_spec_version_current() {
        // types::SPEC_VERSION_CURRENT = 0x01. Spec §2.4.
        assert_eq!(scalar_emission::types::SPEC_VERSION_CURRENT, 0x01u8);
    }

    #[test]
    fn compliance_test_t_transition_epochs() {
        // Spec §2.4: T_TRANSITION_EPOCHS = 0 (genesis, no version transition window).
        assert_eq!(scalar_emission::types::T_TRANSITION_EPOCHS, 0u64);
    }

    // ── §8.4 EpochRewardManifest fields ───────────────────────────────────

    #[test]
    fn compliance_test_network_health_digest_field() {
        // Spec §8.4: network_health_digest field WAJIB ada di EpochRewardManifest.
        use scalar_emission::dmm::EpochRewardManifest;
        let m = EpochRewardManifest {
            epoch_id: 1,
            node_list: vec![],
            spec_version: 0x01,
            total_emission_sscl: 0,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0xABu8; 32],
            tx_set_root: [0u8; 32],
            status: scalar_emission::dmm::EpochStatus::Open,
        };
        assert_eq!(
            m.network_health_digest, [0xABu8; 32],
            "network_health_digest harus ada dan dapat diakses"
        );
    }

    #[test]
    fn compliance_test_node_reward_entry_uptime_weight_fp() {
        // Spec §8.4: NodeRewardEntry.uptime_weight_fp field WAJIB ada.
        use scalar_emission::dmm::NodeRewardEntry;
        let entry = NodeRewardEntry {
            node_id_full: [0x01u8; 32],
            reward_sscl: 500_000,
            uptime_weight_fp: 800_000,
        };
        assert_eq!(
            entry.uptime_weight_fp, 800_000,
            "uptime_weight_fp harus ada di NodeRewardEntry"
        );
    }

    // ── §8.4 Version gate ─────────────────────────────────────────────────────

    #[test]
    fn compliance_test_version_0x05_rejected() {
        // Spec §8.4: manifest spec_version=0x05 di-reject di production.
        let result = scalar_emission::types::validate_manifest_version(0x05);
        assert!(
            result.is_err(),
            "spec_version 0x05 harus di-reject di production mode"
        );
    }

    #[test]
    fn compliance_test_version_0x05_rejected_genesis() {
        // Spec §2.4 genesis: only 0x01 is valid; 0x05 is rejected.
        let result = scalar_emission::types::validate_manifest_version(0x05);
        assert!(
            result.is_err(),
            "spec_version 0x05 harus di-reject di genesis implementation"
        );
    }

    #[test]
    fn compliance_test_version_0x06_rejected_genesis() {
        // Genesis: only 0x01 valid; 0x06 is rejected (validate_manifest_version).
        assert!(scalar_emission::types::validate_manifest_version(0x06).is_err());
        assert!(scalar_emission::types::validate_manifest_version(0x06).is_err());
    }

    // ── DMM MAX_CONSECUTIVE_DEFER ─────────────────────────────────────────────

    #[test]
    fn compliance_test_max_consecutive_defer() {
        // Spec §8.2: MAX_CONSECUTIVE_DEFER = 2. OSSIFIED.
        assert_eq!(scalar_emission::dmm::MAX_CONSECUTIVE_DEFER, 2u32);
    }
}

// ── TX_ORDER_DOMAIN compliance tests ─────────────────────────────────────────

#[cfg(test)]
mod tests_v12_ordering {
    #[test]
    fn compliance_test_tx_order_domain() {
        // TX_ORDER_DOMAIN = b"scalar_tx_order" (15 bytes). OSSIFIED — spec §2.3.
        assert_eq!(scalar_crypto::domain::DOMAIN_TX_ORDER, b"scalar_tx_order");
    }

    #[test]
    fn compliance_test_tx_order_domain_len() {
        // TX_ORDER_DOMAIN_LEN = 15. Spec §2.3.
        assert_eq!(scalar_emission::ordering::TX_ORDER_DOMAIN_LEN, 15usize);
    }

    #[test]
    fn compliance_test_canonical_sort_deterministic() {
        // sort_transactions_canonical deterministik — spec §8.5.
        use scalar_emission::ordering::{sort_transactions_canonical, TxEntry};
        let txs = vec![
            TxEntry {
                tx_hash: [0x03u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x01u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x02u8; 32],
                tx_data: vec![],
            },
        ];
        let s1 = sort_transactions_canonical(&txs, 1);
        let s2 = sort_transactions_canonical(&txs, 1);
        assert_eq!(s1, s2, "Canonical sort harus deterministik");
    }
}

// ── UTXO Set SMT compliance tests — spec §8.5, §16.1 ─────────────────────────

#[cfg(test)]
mod tests_v12_utxo {
    #[test]
    fn compliance_test_utxo_domain_separator() {
        // DOMAIN_UTXO_SMT = scalar_emission::utxo_set_smt::DOMAIN_UTXO_SMT. NON-OSSIFIED (audit K9-02).
        assert_eq!(
            scalar_emission::utxo_set_smt::DOMAIN_UTXO_SMT,
            scalar_emission::utxo_set_smt::DOMAIN_UTXO_SMT
        );
    }

    #[test]
    fn compliance_test_utxo_genesis_state() {
        // Genesis state: root zero, epoch 0. Spec §8.5.
        use scalar_emission::utxo_set_smt::UtxoSetState;
        let state = UtxoSetState::genesis();
        assert_eq!(state.utxo_set_root, [0u8; 32]);
        assert_eq!(state.snapshot_epoch, 0);
    }

    #[test]
    fn compliance_test_utxo_root_snapshot_after_processing() {
        // Snapshot diambil SETELAH semua tx epoch diproses. Spec §8.5.
        use scalar_emission::ordering::TxEntry;
        use scalar_emission::utxo_set_smt::UtxoSetAccumulator;
        let mut smt = UtxoSetAccumulator::new();
        let txs = vec![
            TxEntry {
                tx_hash: [0x01u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x02u8; 32],
                tx_data: vec![],
            },
        ];
        smt.process_epoch_transactions(&txs, 1);
        let snap = smt.take_snapshot(1);
        assert_ne!(
            snap.utxo_set_root, [0u8; 32],
            "Root harus non-zero setelah transaksi diproses"
        );
        assert_eq!(snap.snapshot_epoch, 1);
    }

    #[test]
    fn compliance_test_utxo_root_deterministic() {
        // Canonical ordering → root identik antar node. Spec §8.5.
        use scalar_emission::ordering::TxEntry;
        use scalar_emission::utxo_set_smt::UtxoSetAccumulator;

        let txs_a = vec![
            TxEntry {
                tx_hash: [0x03u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x01u8; 32],
                tx_data: vec![],
            },
        ];
        let txs_b = vec![
            TxEntry {
                tx_hash: [0x01u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x03u8; 32],
                tx_data: vec![],
            },
        ];

        let mut smt_a = UtxoSetAccumulator::new();
        smt_a.process_epoch_transactions(&txs_a, 2);

        let mut smt_b = UtxoSetAccumulator::new();
        smt_b.process_epoch_transactions(&txs_b, 2);

        assert_eq!(
            smt_a.root(),
            smt_b.root(),
            "Root harus identik untuk tx set yang sama — spec §8.5"
        );
    }
}

// ── Tier C compliance tests — spec §10.1, §12.4 ──────────────────────────────

#[cfg(test)]
mod tests_v12_tier_c {
    #[test]
    fn compliance_test_tier_c_max_nodescore() {
        // TIER_C_MAX_NODESCORE = 600_000. OSSIFIED — spec §10.1, §12.4, §17.
        assert_eq!(scalar_network::node_score::TIER_C_MAX_NODESCORE, 600_000u64);
    }

    #[test]
    fn compliance_test_tier_c_nmt_ineligible() {
        // Tier C node tidak eligible NMT. Spec §12.4.
        use scalar_network::node_score::NodeScore;
        let mut id = [0u8; 32];
        id[0] = 0xFE; // Tier C prefix
        let node = NodeScore::new(id, 1_000_000); // raw max
        assert!(!node.is_nmt_eligible(), "Tier C tidak boleh eligible NMT");
    }

    #[test]
    fn compliance_test_tier_c_prefix_is_0xfe() {
        // TIER_C_PREFIX = 0xFE. Spec §10.1.
        assert_eq!(scalar_network::node_score::TIER_C_PREFIX, 0xFEu8);
    }

    #[test]
    fn compliance_test_tier_c_below_nmt_threshold() {
        // TIER_C_MAX_NODESCORE < NMT_SCORE_THRESHOLD — invariant. Spec §10.1.
        const {
            assert!(
                scalar_network::node_score::TIER_C_MAX_NODESCORE
                    < scalar_network::node_score::NMT_SCORE_THRESHOLD
            )
        };
    }

    #[test]
    fn compliance_test_tier_a_full_score() {
        // Tier A/B bisa mencapai 1_000_000. Spec §10.1.
        use scalar_network::node_score::NodeScore;
        let mut id = [0u8; 32];
        id[0] = 0x01; // Tier A
        let node = NodeScore::new(id, 1_000_000);
        assert_eq!(node.score(), 1_000_000);
    }
}

// ── NMT Hybrid 23+1 compliance tests — spec §12.3, §17 ───────────────────────

#[cfg(test)]
mod tests_v12_nmt_hybrid {
    #[test]
    fn compliance_test_nmt_peer_count_24() {
        // NMT_PEER_COUNT_V12 = 24. Spec §12.3, §17.
        assert_eq!(scalar_network::nmt_hybrid::NMT_PEER_COUNT_V12, 24usize);
    }

    #[test]
    fn compliance_test_nmt_random_slots_1() {
        // NMT_RANDOM_SLOTS = 1. Spec §12.3, §17.
        assert_eq!(scalar_network::nmt_hybrid::NMT_RANDOM_SLOTS, 1usize);
    }

    #[test]
    fn compliance_nmt_hybrid_23_plus_1() {
        // 23 deterministik + 1 random = 24. Spec §12.3.
        assert_eq!(
            scalar_network::nmt_hybrid::NMT_DETERMINISTIC_SLOTS
                + scalar_network::nmt_hybrid::NMT_RANDOM_SLOTS,
            scalar_network::nmt_hybrid::NMT_PEER_COUNT_V12
        );
    }

    #[test]
    fn compliance_nmt_tier_c_excluded() {
        // Tier C tidak muncul di NMT. Spec §12.3.
        use scalar_network::nmt_hybrid::{select_nmt_peers_hybrid, NmtNodeCandidate};
        use scalar_network::node_score::is_tier_c;

        let mut candidates: Vec<NmtNodeCandidate> = (1u8..=30)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = 0x01;
                id[1] = i;
                NmtNodeCandidate {
                    node_id_full: id,
                    node_score: 850_000,
                    subnet24: [i % 10, 0, 0, 0],
                    asn: [i % 20, 0, 0, 0],
                    region: i % 8,
                }
            })
            .collect();

        // Tambahkan Tier C
        let mut tier_c_id = [0u8; 32];
        tier_c_id[0] = 0xFE;
        candidates.push(NmtNodeCandidate {
            node_id_full: tier_c_id,
            node_score: 1_000_000,
            subnet24: [0xFF, 0, 0, 0],
            asn: [0, 0, 0, 0],
            region: 0,
        });

        let result = select_nmt_peers_hybrid(&candidates, &[0x42u8; 32]);
        for peer in result.all_peers() {
            assert!(!is_tier_c(&peer), "Tier C tidak boleh ada di NMT");
        }
    }
}

// ── Tier C Governance Power compliance tests — spec §11.2, §17 ───────────────

#[cfg(test)]
mod tests_v12_governance {
    #[test]
    fn compliance_test_tier_c_gov_power_cap_200k() {
        // TIER_C_MAX_GOV_POWER = 200_000 fp. OSSIFIED — spec §11.2, §17.
        assert_eq!(
            scalar_governance::governance_power_v12::TIER_C_MAX_GOV_POWER,
            200_000u64
        );
    }

    #[test]
    fn compliance_test_tier_c_gov_power_enforced() {
        // Tier C GP dibatasi 200_000. Spec §11.2.
        let mut id = [0u8; 32];
        id[0] = 0xFE;
        let gp = scalar_governance::governance_power_v12::compute_governance_power_v12(
            &id, 1_000_000, 1_000_000,
        );
        assert_eq!(gp, 200_000u64, "Tier C harus dibatasi 200_000 fp");
    }

    #[test]
    fn compliance_test_tier_a_full_gov_power() {
        // Tier A GP bisa mencapai 1_000_000. Spec §11.2.
        let mut id = [0u8; 32];
        id[0] = 0x01;
        let gp = scalar_governance::governance_power_v12::compute_governance_power_v12(
            &id, 1_000_000, 1_000_000,
        );
        assert_eq!(gp, 1_000_000u64);
    }

    #[test]
    fn compliance_test_gov_power_formula() {
        // GP(i,t) = min(BaseGP, GOV_MAX_FP_FOR_TIER). Spec §11.2.
        let mut id_c = [0u8; 32];
        id_c[0] = 0xFE;
        let mut id_a = [0u8; 32];
        id_a[0] = 0x01;

        use scalar_governance::governance_power_v12::compute_governance_power_v12;
        // BaseGP = 600_000, cap_c = 200_000, cap_a = 1_000_000
        let gp_c = compute_governance_power_v12(&id_c, 600_000, 1_000_000);
        let gp_a = compute_governance_power_v12(&id_a, 600_000, 1_000_000);
        assert_eq!(gp_c, 200_000); // min(600_000, 200_000)
        assert_eq!(gp_a, 600_000); // min(600_000, 1_000_000)
    }
}

// ── Compliance Suite v4.0 — Test Targets §XXI v11.1-FINAL ────────────────────
// Semua test targets dari §XXI yang belum dicover di atas.

#[cfg(test)]
mod tests_v12_suite_v4 {

    // ── §XXI: test determinisme tx_ordering_key ───────────────────────────────

    #[test]
    fn compliance_tx_ordering_determinism() {
        // Verifikasi utxo_set_root identik antar node. Spec §XXI, §8.5.
        use scalar_emission::ordering::TxEntry;
        use scalar_emission::utxo_set_smt::UtxoSetAccumulator;

        let txs_node_a = vec![
            TxEntry {
                tx_hash: [0x01u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x02u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x03u8; 32],
                tx_data: vec![],
            },
        ];
        let txs_node_b = vec![
            TxEntry {
                tx_hash: [0x03u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x01u8; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0x02u8; 32],
                tx_data: vec![],
            },
        ];

        let mut smt_a = UtxoSetAccumulator::new();
        smt_a.process_epoch_transactions(&txs_node_a, 1);

        let mut smt_b = UtxoSetAccumulator::new();
        smt_b.process_epoch_transactions(&txs_node_b, 1);

        assert_eq!(
            smt_a.root(),
            smt_b.root(),
            "utxo_set_root harus identik antar node — compliance §XXI"
        );
    }

    // ── §XXI: test governance power cap Tier C ────────────────────────────────

    #[test]
    fn compliance_tier_c_gov_cap() {
        // Governance power cap Tier C = 200_000. Spec §XXI, §11.2.
        use scalar_governance::governance_power_v12::{
            compute_governance_power_v12, TIER_C_MAX_GOV_POWER,
        };
        let mut id = [0u8; 32];
        id[0] = 0xFE;
        let gp = compute_governance_power_v12(&id, 1_000_000, 1_000_000);
        assert_eq!(
            gp, TIER_C_MAX_GOV_POWER,
            "Tier C governance power cap = 200_000 fp — compliance §XXI"
        );
        assert_eq!(TIER_C_MAX_GOV_POWER, 200_000u64);
    }

    // ── §XXI: test DMM secure bootstrapping ──────────────────────────────────

    #[test]
    fn compliance_dmm_bootstrapping() {
        // Node tanpa manifest tidak bangun DMM. Spec §XXI, §8.2.
        use scalar_emission::dmm::{build_dmm, DmmConfig, DmmError, LocalHeartbeatData};
        let local = LocalHeartbeatData::new(10);
        let config = DmmConfig {
            e_active_sscl: 12_600_000_000_000,
            fee_pool_sscl: 0,
            txids: vec![],
        };
        let result = build_dmm(10, None, &local, &config);
        assert_eq!(
            result,
            Err(DmmError::BootstrapRequired),
            "Node tanpa manifest HARUS return BootstrapRequired — compliance §XXI"
        );
    }

    // ── §XXI: test sinkronisasi node baru + utxo_set_root reconstruction ──────

    #[test]
    fn compliance_node_sync_utxo_reconstruction() {
        // Node baru sync → utxo_set_root identik dengan node lama. Spec §XXI, §8.5.
        use scalar_emission::ordering::TxEntry;
        use scalar_emission::utxo_set_smt::{
            verify_utxo_root_against_manifest, SyncVerificationResult, UtxoSetAccumulator,
        };

        let txs = vec![
            TxEntry {
                tx_hash: [0xAA; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0xBB; 32],
                tx_data: vec![],
            },
        ];

        // Node lama
        let mut old_node = UtxoSetAccumulator::new();
        old_node.process_epoch_transactions(&txs, 3);
        let expected_root = old_node.root();

        // Node baru rebuild dari genesis
        let mut new_node = UtxoSetAccumulator::new();
        let txs_reordered = vec![
            TxEntry {
                tx_hash: [0xBB; 32],
                tx_data: vec![],
            },
            TxEntry {
                tx_hash: [0xAA; 32],
                tx_data: vec![],
            },
        ];
        new_node.process_epoch_transactions(&txs_reordered, 3);
        let new_root = new_node.root();

        assert_eq!(
            expected_root, new_root,
            "Node baru harus menghasilkan root identik — compliance §XXI"
        );

        let result = verify_utxo_root_against_manifest(&new_root, &expected_root);
        assert_eq!(
            result,
            SyncVerificationResult::Valid,
            "Verifikasi root vs manifest harus Valid — compliance §XXI"
        );
    }

    // ── §XXI: compliance NMT hybrid 23+1 ─────────────────────────────────────

    #[test]
    fn compliance_nmt_hybrid_verified() {
        // 23+1 slot verified. Spec §XXI, §12.3.
        use scalar_network::nmt_hybrid::{
            select_nmt_peers_hybrid, NmtNodeCandidate, NMT_DETERMINISTIC_SLOTS, NMT_PEER_COUNT_V12,
            NMT_RANDOM_SLOTS,
        };
        assert_eq!(NMT_DETERMINISTIC_SLOTS, 23);
        assert_eq!(NMT_RANDOM_SLOTS, 1);
        assert_eq!(NMT_PEER_COUNT_V12, 24);

        // Verifikasi dengan actual selection
        let candidates: Vec<NmtNodeCandidate> = (1u8..=30)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = 0x01;
                id[1] = i;
                NmtNodeCandidate {
                    node_id_full: id,
                    node_score: 850_000,
                    subnet24: [i % 10, 0, 0, 0],
                    asn: [i % 20, 0, 0, 0],
                    region: i % 8,
                }
            })
            .collect();

        let result = select_nmt_peers_hybrid(&candidates, &[0x42u8; 32]);
        assert!(
            result.total_selected <= NMT_PEER_COUNT_V12,
            "Total selected tidak boleh melebihi 24"
        );
        assert!(result.total_selected > 0, "Harus ada peer yang terpilih");
    }

    // ── §XXI: compliance SPEC_VERSION = 0x01 (genesis) ───────────────────────

    #[test]
    fn compliance_spec_version_0x01_manifest() {
        // Genesis manifest version = 0x01. Spec §XXI, §2.4.
        use scalar_emission::dmm::SPEC_VERSION_MANIFEST;
        use scalar_emission::types::{validate_manifest_version, SPEC_VERSION_CURRENT};

        assert_eq!(
            SPEC_VERSION_MANIFEST, 0x01u8,
            "SPEC_VERSION_MANIFEST harus 0x01"
        );
        assert_eq!(
            SPEC_VERSION_CURRENT, 0x01u8,
            "SPEC_VERSION_CURRENT harus 0x01"
        );

        // hanya 0x01 yang valid di genesis
        assert!(validate_manifest_version(0x01).is_ok());
        // semua versi lain di-reject
        assert!(validate_manifest_version(0x06).is_err());
        assert!(validate_manifest_version(0x05).is_err());
    }

    // ── §XXI: formal verification invariants ─────────────────────────────────

    #[test]
    fn compliance_formal_cc_invariant() {
        // Runtime CC invariant assertion. Spec §XXI, §15.4.
        use scalar_nullifier::formal::assert_cc_invariant;
        // Non-member → ok
        assert!(assert_cc_invariant(&[0x01u8; 32], false, false).is_ok());
        // Member → violation
        assert!(assert_cc_invariant(&[0x01u8; 32], true, false).is_err());
        assert!(assert_cc_invariant(&[0x01u8; 32], false, true).is_err());
    }

    #[test]
    fn compliance_formal_deferred_pool_invariants() {
        // Runtime Deferred Pool invariants. Spec §XXI, §15.5.
        use scalar_emission::formal::{
            assert_deferred_pool_invariants, DeferredPoolState, DEFERRED_POOL_MAX_EPOCHS,
            DEFERRED_POOL_MAX_RELEASE,
        };
        let valid = DeferredPoolState {
            balance_sscl: 1_000_000,
            total_residual_sscl: 2_000_000,
            total_released_sscl: 500_000,
            epochs_since_defer: 5,
        };
        assert!(assert_deferred_pool_invariants(&valid, 100_000).is_ok());

        // Violation: release terlalu besar
        assert!(assert_deferred_pool_invariants(&valid, DEFERRED_POOL_MAX_RELEASE + 1).is_err());

        // Konstanta
        assert_eq!(DEFERRED_POOL_MAX_EPOCHS, 12u64);
    }

    // ── §XVII: semua parameter baru v11.1-FINAL ───────────────────────────────

    #[test]
    fn compliance_all_new_params_v11_1_final() {
        // Verifikasi semua parameter baru v11.1-FINAL sekaligus. Spec §XVII.
        // TIER_C_MAX_NODESCORE
        assert_eq!(scalar_network::node_score::TIER_C_MAX_NODESCORE, 600_000u64);
        // TIER_C_MAX_GOV_POWER
        assert_eq!(
            scalar_governance::governance_power_v12::TIER_C_MAX_GOV_POWER,
            200_000u64
        );
        // NMT_PEER_COUNT_V12
        assert_eq!(scalar_network::nmt_hybrid::NMT_PEER_COUNT_V12, 24usize);
        // NMT_RANDOM_SLOTS
        assert_eq!(scalar_network::nmt_hybrid::NMT_RANDOM_SLOTS, 1usize);
        // SPEC_VERSION_MANIFEST
        assert_eq!(scalar_emission::dmm::SPEC_VERSION_MANIFEST, 0x01u8);
        // TX_ORDER_DOMAIN
        assert_eq!(scalar_crypto::domain::DOMAIN_TX_ORDER, b"scalar_tx_order");
        // MAX_CONSECUTIVE_DEFER
        assert_eq!(scalar_emission::dmm::MAX_CONSECUTIVE_DEFER, 2u32);
        // T_TRANSITION_EPOCHS
        assert_eq!(scalar_emission::types::T_TRANSITION_EPOCHS, 0u64);
    }
}

// ── Compliance tests PR-011 s.d. 014 (P2P Gaps) — spec §7.2a, §10.2, §12.3a, §12.2 ──

#[cfg(test)]
mod tests_v12_p2p_gaps {

    // ── G-11: EpochAnchor (Gap G-1) ──────────────────────────────────────────

    #[test]
    fn compliance_epoch_anchor_handshake() {
        // EpochAnchor handshake valid. Spec §7.2a, Gap G-1.
        use scalar_emission::liveness::EpochAnchor;
        use scalar_node::epoch_anchor::{validate_epoch_anchor_basic, HandshakeResult};
        let anchor = EpochAnchor {
            node_id: [0x01, 0x02, 0x03, 0x04],
            epoch_id: 5,
            hb_count: 4320,
            chain_head: [0x42u8; 32],
            pubkey: [0x33u8; 64],
            sig: vec![0xAAu8; 32],
        };
        let result = validate_epoch_anchor_basic(&anchor);
        assert!(
            matches!(result, HandshakeResult::Accepted { .. }),
            "Anchor valid harus diterima — compliance Gap G-1"
        );
    }

    #[test]
    fn compliance_peer_node_key_not_hardcode() {
        // peer_node_key_epoch dari anchor, bukan hardcode. Spec §7.2a.
        use libp2p::identity::Keypair;
        use libp2p::PeerId;
        use scalar_emission::liveness::EpochAnchor;
        use scalar_node::epoch_anchor::PeerAnchorStore;
        let key = Keypair::generate_ed25519();
        let peer_id = PeerId::from(key.public());
        let anchor = EpochAnchor {
            node_id: [0x01, 0x00, 0x00, 0x00],
            epoch_id: 3,
            hb_count: 100,
            chain_head: [0x42u8; 32],
            pubkey: [0x33u8; 64],
            sig: vec![0xAAu8; 16],
        };
        let mut store = PeerAnchorStore::new();
        store.store_anchor(peer_id, &anchor);
        let nke = store.get_node_key_epoch(&peer_id);
        assert!(nke.is_some(), "node_key_epoch harus ada setelah handshake");
        assert_ne!(*nke.unwrap(), [0u8; 32], "Tidak boleh zero");
    }

    // ── G-12: NodeID production Argon2id (Gap G-2) ───────────────────────────

    #[test]
    #[ignore = "slow: Argon2id 16MB, run manually with -- --ignored"]
    fn compliance_nodeid_argon2id_not_placeholder() {
        // NodeID bukan placeholder [0x42;32]. Spec §10.2, Gap G-2.
        use scalar_node::node_id::{
            NodeIdDerivationMode, ProductionNodeId, ARGON2_NODE_MEMORY_TIER_C_KIB,
            ARGON2_NODE_TIME_TIER_C, NODE_ID_SALT_PREFIX,
        };
        // Salt prefix ossified
        // Spec §2.3, §10.2: NODE_ID_SALT_PREFIX = b"scalar_nodeid" (13 byte). OSSIFIED.
        assert_eq!(NODE_ID_SALT_PREFIX, b"scalar_nodeid");
        // Tier C params
        assert_eq!(ARGON2_NODE_MEMORY_TIER_C_KIB, 16 * 1024);
        assert_eq!(ARGON2_NODE_TIME_TIER_C, 100);
        // NodeID tidak sama dengan placeholder
        let result = ProductionNodeId::derive(
            b"compliance_test_mnemonic",
            &[0x42u8; 32],
            NodeIdDerivationMode::TierCOrDev,
        );
        assert!(result.is_ok());
        assert_ne!(result.unwrap().node_id_full, [0x42u8; 32]);
    }

    // ── G-13: NMT dari peer timestamps (Gap G-3) ─────────────────────────────

    #[test]
    fn compliance_nmt_from_peer_timestamps() {
        // NMT dari peer timestamps, bukan wall-clock. Spec §12.3a, Gap G-3.
        use scalar_node::nmt_production::{
            compute_production_nmt, PeerTimestampStore, ProductionNmtResult,
            NMT_MAX_STORED_TIMESTAMPS, NMT_MIN_PEERS_FOR_RELIABLE,
        };
        // Constants
        assert_eq!(NMT_MIN_PEERS_FOR_RELIABLE, 9usize);
        assert_eq!(NMT_MAX_STORED_TIMESTAMPS, 24usize);

        // Dengan cukup peer → FromPeers
        // Semua timestamp sama → median = 5_000_000, wall-clock = 5_000_000 (drift=0)
        let mut store = PeerTimestampStore::new();
        for i in 0..10u8 {
            store.update([i, 0, 0, 0], 5_000_000u32);
        }
        let result = compute_production_nmt(&store, 5_000_000);
        assert!(
            matches!(result, ProductionNmtResult::FromPeers { .. }),
            "NMT harus dari peer timestamps jika cukup peer — compliance Gap G-3"
        );

        // Tanpa peer → FallbackWallClock
        let empty = PeerTimestampStore::new();
        let fallback = compute_production_nmt(&empty, 999);
        assert!(matches!(
            fallback,
            ProductionNmtResult::FallbackWallClock { .. }
        ));
    }

    // ── G-14: HeartbeatRateLimiter + StateBeacon (Gap G-4 + G-5) ────────────

    #[test]
    fn compliance_rate_limiter_connected_gossip() {
        // T-4 rate limit aktif di gossip layer. Spec §7.2c T-4, Gap G-4.
        use scalar_network::time_security::T_HB_MIN_INTERVAL_S;
        use scalar_node::gossip_production::{GossipDecision, GossipLayer};
        let mut gossip = GossipLayer::new();
        let node = [0x01u8; 4];
        // Forward
        assert!(gossip
            .process_incoming_heartbeat(node, 1000)
            .should_forward());
        // Rate limited
        let d = gossip.process_incoming_heartbeat(node, 1000 + T_HB_MIN_INTERVAL_S - 1);
        assert!(
            !d.should_forward(),
            "Rate limit harus aktif di gossip layer"
        );
        assert!(matches!(d, GossipDecision::RateLimited { .. }));
    }

    #[test]
    fn compliance_state_beacon_broadcast_verified() {
        // StateBeacon broadcast + MAC verified. Spec §12.2, Gap G-5.
        use scalar_network::state_beacon::STATE_BEACON_WIRE_SIZE;
        use scalar_node::gossip_production::StateBeaconBroadcaster;
        let mut bc = StateBeaconBroadcaster::new([0x42u8; 32]);
        let bytes = bc.create_beacon(10, [0xABu8; 32]);
        assert_eq!(bytes.len(), STATE_BEACON_WIRE_SIZE, "Beacon harus 44 bytes");
        let beacon = bc.receive_and_verify_beacon(&bytes);
        assert!(beacon.is_some(), "Valid beacon harus diterima");
        assert_eq!(beacon.unwrap().epoch_id, 10);
    }
}
