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
