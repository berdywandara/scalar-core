//! Compliance Suite v12.0 — Parameter v11.1-FINAL
//!
//! Spec §XVII (parameter referensi lengkap v11.1-FINAL), §XXI (test targets).
//!
//! Verifikasi semua parameter baru dari v11.1-FINAL:
//!   SPEC_VERSION_MANIFEST_V12 = 0x06
//!   T_TRANSITION_EPOCHS = 4
//!   network_health_digest field exists
//!   NodeRewardEntry.uptime_weight_fp field exists

#[cfg(test)]
mod tests_v12 {
    // ── §2.4 SPEC_VERSION_MANIFEST = 0x06 ────────────────────────────────────

    #[test]
    fn compliance_test_spec_version_0x06() {
        // Spec §2.4, §8.4: SPEC_VERSION_MANIFEST_V12 = 0x06. OSSIFIED.
        assert_eq!(
            scalar_emission::dmm::SPEC_VERSION_MANIFEST_V12,
            0x06u8,
            "SPEC_VERSION_MANIFEST_V12 harus 0x06"
        );
    }

    #[test]
    fn compliance_test_spec_version_current() {
        // types::SPEC_VERSION_CURRENT = 0x06. Spec §2.4.
        assert_eq!(
            scalar_emission::types::SPEC_VERSION_CURRENT,
            0x06u8
        );
    }

    #[test]
    fn compliance_test_t_transition_epochs() {
        // Spec §2.4: T_TRANSITION_EPOCHS = 4.
        assert_eq!(
            scalar_emission::types::T_TRANSITION_EPOCHS,
            4u64
        );
    }

    // ── §8.4 EpochRewardManifestV12 fields ───────────────────────────────────

    #[test]
    fn compliance_test_network_health_digest_field() {
        // Spec §8.4: network_health_digest field WAJIB ada di EpochRewardManifestV12.
        use scalar_emission::dmm::EpochRewardManifestV12;
        let m = EpochRewardManifestV12 {
            epoch_id: 1,
            node_list: vec![],
            spec_version: 0x06,
            total_emission_sscl: 0,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0xABu8; 32],
        };
        assert_eq!(m.network_health_digest, [0xABu8; 32],
            "network_health_digest harus ada dan dapat diakses");
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
        assert_eq!(entry.uptime_weight_fp, 800_000,
            "uptime_weight_fp harus ada di NodeRewardEntry");
    }

    // ── §8.4 Version gate ─────────────────────────────────────────────────────

    #[test]
    fn compliance_test_version_reject_0x05_production() {
        // Spec §8.4: manifest spec_version=0x05 di-reject di production.
        let result = scalar_emission::types::validate_manifest_version(0x05, false);
        assert!(result.is_err(),
            "spec_version 0x05 harus di-reject di production mode");
    }

    #[test]
    fn compliance_test_version_accept_0x05_testnet() {
        // Spec §2.4: spec_version=0x05 diterima dengan --testnet-compat.
        let result = scalar_emission::types::validate_manifest_version(0x05, true);
        assert!(result.is_ok(),
            "spec_version 0x05 harus diterima dengan testnet-compat");
    }

    #[test]
    fn compliance_test_version_accept_0x06_always() {
        // Spec §8.4: 0x06 selalu diterima.
        assert!(scalar_emission::types::validate_manifest_version(0x06, false).is_ok());
        assert!(scalar_emission::types::validate_manifest_version(0x06, true).is_ok());
    }

    // ── DMM MAX_CONSECUTIVE_DEFER ─────────────────────────────────────────────

    #[test]
    fn compliance_test_max_consecutive_defer() {
        // Spec §8.2: MAX_CONSECUTIVE_DEFER = 2. OSSIFIED.
        assert_eq!(
            scalar_emission::dmm::MAX_CONSECUTIVE_DEFER,
            2u32
        );
    }
}

// ── TX_ORDER_DOMAIN compliance tests ─────────────────────────────────────────

#[cfg(test)]
mod tests_v12_ordering {
    #[test]
    fn compliance_test_tx_order_domain() {
        // TX_ORDER_DOMAIN = b"scalar_tx_order_v1". OSSIFIED — spec §2.3.
        assert_eq!(
            scalar_emission::ordering::TX_ORDER_DOMAIN,
            b"scalar_tx_order_v1"
        );
    }

    #[test]
    fn compliance_test_tx_order_domain_len() {
        // TX_ORDER_DOMAIN_LEN = 18. Spec §2.3.
        assert_eq!(
            scalar_emission::ordering::TX_ORDER_DOMAIN_LEN,
            18usize
        );
    }

    #[test]
    fn compliance_test_canonical_sort_deterministic() {
        // sort_transactions_canonical deterministik — spec §8.5.
        use scalar_emission::ordering::{sort_transactions_canonical, TxEntry};
        let txs = vec![
            TxEntry { tx_hash: [0x03u8; 32], tx_data: vec![] },
            TxEntry { tx_hash: [0x01u8; 32], tx_data: vec![] },
            TxEntry { tx_hash: [0x02u8; 32], tx_data: vec![] },
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
        // DOMAIN_UTXO_SMT = b"scalar_utxo_v2". OSSIFIED — spec §2.3.
        assert_eq!(
            scalar_emission::utxo_set_smt::DOMAIN_UTXO_SMT,
            b"scalar_utxo_v2"
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
        use scalar_emission::utxo_set_smt::UtxoSetSMT;
        use scalar_emission::ordering::TxEntry;
        let mut smt = UtxoSetSMT::new();
        let txs = vec![
            TxEntry { tx_hash: [0x01u8; 32], tx_data: vec![] },
            TxEntry { tx_hash: [0x02u8; 32], tx_data: vec![] },
        ];
        smt.process_epoch_transactions(&txs, 1);
        let snap = smt.take_snapshot(1);
        assert_ne!(snap.utxo_set_root, [0u8; 32],
            "Root harus non-zero setelah transaksi diproses");
        assert_eq!(snap.snapshot_epoch, 1);
    }

    #[test]
    fn compliance_test_utxo_root_deterministic() {
        // Canonical ordering → root identik antar node. Spec §8.5.
        use scalar_emission::utxo_set_smt::UtxoSetSMT;
        use scalar_emission::ordering::TxEntry;

        let txs_a = vec![
            TxEntry { tx_hash: [0x03u8; 32], tx_data: vec![] },
            TxEntry { tx_hash: [0x01u8; 32], tx_data: vec![] },
        ];
        let txs_b = vec![
            TxEntry { tx_hash: [0x01u8; 32], tx_data: vec![] },
            TxEntry { tx_hash: [0x03u8; 32], tx_data: vec![] },
        ];

        let mut smt_a = UtxoSetSMT::new();
        smt_a.process_epoch_transactions(&txs_a, 2);

        let mut smt_b = UtxoSetSMT::new();
        smt_b.process_epoch_transactions(&txs_b, 2);

        assert_eq!(smt_a.root(), smt_b.root(),
            "Root harus identik untuk tx set yang sama — spec §8.5");
    }
}

// ── Tier C compliance tests — spec §10.1, §12.4 ──────────────────────────────

#[cfg(test)]
mod tests_v12_tier_c {
    #[test]
    fn compliance_test_tier_c_max_nodescore() {
        // TIER_C_MAX_NODESCORE = 600_000. OSSIFIED — spec §10.1, §12.4, §17.
        assert_eq!(
            scalar_network::node_score::TIER_C_MAX_NODESCORE,
            600_000u64
        );
    }

    #[test]
    fn compliance_test_tier_c_nmt_ineligible() {
        // Tier C node tidak eligible NMT. Spec §12.4.
        use scalar_network::node_score::NodeScore;
        let mut id = [0u8; 32];
        id[0] = 0xFE; // Tier C prefix
        let node = NodeScore::new(id, 1_000_000); // raw max
        assert!(!node.is_nmt_eligible(),
            "Tier C tidak boleh eligible NMT");
    }

    #[test]
    fn compliance_test_tier_c_prefix_is_0xfe() {
        // TIER_C_PREFIX = 0xFE. Spec §10.1.
        assert_eq!(scalar_network::node_score::TIER_C_PREFIX, 0xFEu8);
    }

    #[test]
    fn compliance_test_tier_c_below_nmt_threshold() {
        // TIER_C_MAX_NODESCORE < NMT_SCORE_THRESHOLD — invariant. Spec §10.1.
        assert!(
            scalar_network::node_score::TIER_C_MAX_NODESCORE
                < scalar_network::node_score::NMT_SCORE_THRESHOLD
        );
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
        use scalar_network::nmt_hybrid::{NmtNodeCandidate, select_nmt_peers_hybrid};
        use scalar_network::node_score::is_tier_c;

        let mut candidates: Vec<NmtNodeCandidate> = (1u8..=30).map(|i| {
            let mut id = [0u8; 32]; id[0] = 0x01; id[1] = i;
            NmtNodeCandidate {
                node_id_full: id,
                node_score: 850_000,
                subnet24: [i % 10, 0, 0, 0],
                asn: [i % 20, 0, 0, 0],
                region: i % 8,
            }
        }).collect();

        // Tambahkan Tier C
        let mut tier_c_id = [0u8; 32]; tier_c_id[0] = 0xFE;
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
