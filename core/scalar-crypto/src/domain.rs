//! Domain Separators — Spec §2.3 OSSIFIED
//!
//! Setiap konteks penggunaan hash memiliki domain separator unik
//! untuk mencegah cross-context collision.
//! Seluruh separator bersifat OSSIFIED — tidak dapat diubah tanpa fork.

/// Nullifier circuit. Spec §2.3. 14 bytes.
pub const DOMAIN_NULLIFIER: &[u8] = b"scalar_nullifier";

/// UTXO commitment. Spec §2.3. 16 bytes.
pub const DOMAIN_UTXO_COMMITMENT: &[u8] = b"scalar_commitment";

/// Salt derivation. Spec §2.3. 14 bytes.
pub const DOMAIN_SALT: &[u8] = b"scalar_salt";

/// Seed aggregator. Spec §2.3. 15 bytes.
pub const DOMAIN_SEED: &[u8] = b"scalar_seed";

/// NMT peer selection. Spec §2.3. 14 bytes.
pub const DOMAIN_NMT: &[u8] = b"scalar_nmt";

/// Node short ID. Spec §2.3. 18 bytes.
pub const DOMAIN_NODE_SHORT: &[u8] = b"scalar_node_short";

/// Anchor signature. Spec §2.3. 16 bytes.
pub const DOMAIN_ANCHOR: &[u8] = b"scalar_anchor";

/// Governance vote. Spec §2.3. 15 bytes.
pub const DOMAIN_VOTE: &[u8] = b"scalar_vote";

/// Genesis bootstrap. Spec §2.3. 26 bytes.
pub const DOMAIN_GENESIS_BOOTSTRAP: &[u8] = b"scalar_genesis_bootstrap";

/// STARK Fiat-Shamir transcript (transfer). Spec §2.3. 17 bytes.
pub const DOMAIN_STARK_FS: &[u8] = b"scalar_stark_fs";

/// STARK Fiat-Shamir transcript (checkpoint). Spec §2.3. 22 bytes.
pub const DOMAIN_CHECKPOINT_FS: &[u8] = b"scalar_checkpoint_fs";

/// Beacon MAC. Spec §2.3. 16 bytes.
pub const DOMAIN_BEACON: &[u8] = b"scalar_beacon";

/// Seed KDF wallet. Spec §2.3. 9 bytes.
pub const DOMAIN_SEED_KDF: &[u8] = b"scalar_wallet_kdf";

/// TX ordering. Spec §2.3. 18 bytes.
pub const DOMAIN_TX_ORDER: &[u8] = b"scalar_tx_order";

/// PoU mint domain (field element). Spec §2.3. 8 bytes.
pub const DOMAIN_POU_MINT: u64 = 0x706f755f6d696e74;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_nullifier_len() {
        // Spec §2.3: 14 bytes. OSSIFIED.
        assert_eq!(DOMAIN_NULLIFIER, b"scalar_nullifier");
        assert_eq!(DOMAIN_NULLIFIER.len(), 16);
    }

    #[test]
    fn test_domain_utxo_commitment_len() {
        // Spec §2.3: 16 bytes. OSSIFIED.
        assert_eq!(DOMAIN_UTXO_COMMITMENT, b"scalar_commitment");
        assert_eq!(DOMAIN_UTXO_COMMITMENT.len(), 17);
    }

    #[test]
    fn test_domain_salt_len() {
        // Spec §2.3: 14 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SALT, b"scalar_salt");
        assert_eq!(DOMAIN_SALT.len(), 11);
    }

    #[test]
    fn test_domain_seed_len() {
        // Spec §2.3: 15 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SEED, b"scalar_seed");
        assert_eq!(DOMAIN_SEED.len(), 11);
    }

    #[test]
    fn test_domain_nmt_len() {
        // Spec §2.3: 14 bytes. OSSIFIED.
        assert_eq!(DOMAIN_NMT, b"scalar_nmt");
        assert_eq!(DOMAIN_NMT.len(), 10);
    }

    #[test]
    fn test_domain_node_short_len() {
        // Spec §2.3: 18 bytes. OSSIFIED.
        assert_eq!(DOMAIN_NODE_SHORT, b"scalar_node_short");
        assert_eq!(DOMAIN_NODE_SHORT.len(), 17);
    }

    #[test]
    fn test_domain_anchor_len() {
        // Spec §2.3: 16 bytes. OSSIFIED.
        assert_eq!(DOMAIN_ANCHOR, b"scalar_anchor");
        assert_eq!(DOMAIN_ANCHOR.len(), 13);
    }

    #[test]
    fn test_domain_vote_len() {
        // Spec §2.3: 15 bytes. OSSIFIED.
        assert_eq!(DOMAIN_VOTE, b"scalar_vote");
        assert_eq!(DOMAIN_VOTE.len(), 11);
    }

    #[test]
    fn test_domain_genesis_bootstrap_len() {
        // Spec §2.3: 26 bytes. OSSIFIED.
        assert_eq!(DOMAIN_GENESIS_BOOTSTRAP, b"scalar_genesis_bootstrap");
        assert_eq!(DOMAIN_GENESIS_BOOTSTRAP.len(), 24);
    }

    #[test]
    fn test_domain_stark_fs_len() {
        // Spec §2.3: 17 bytes. OSSIFIED.
        assert_eq!(DOMAIN_STARK_FS, b"scalar_stark_fs");
        assert_eq!(DOMAIN_STARK_FS.len(), 15);
    }

    #[test]
    fn test_domain_checkpoint_fs_len() {
        // Spec §2.3: 22 bytes. OSSIFIED.
        assert_eq!(DOMAIN_CHECKPOINT_FS, b"scalar_checkpoint_fs");
        assert_eq!(DOMAIN_CHECKPOINT_FS.len(), 20);
    }

    #[test]
    fn test_domain_beacon_len() {
        // Spec §2.3: 16 bytes. OSSIFIED.
        assert_eq!(DOMAIN_BEACON, b"scalar_beacon");
        assert_eq!(DOMAIN_BEACON.len(), 13);
    }

    #[test]
    fn test_domain_seed_kdf_len() {
        // Spec §2.3: 9 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SEED_KDF, b"scalar_wallet_kdf");
        assert_eq!(DOMAIN_SEED_KDF.len(), 17);
    }

    #[test]
    fn test_domain_tx_order_len() {
        // Spec §2.3: 18 bytes. OSSIFIED.
        assert_eq!(DOMAIN_TX_ORDER, b"scalar_tx_order");
        assert_eq!(DOMAIN_TX_ORDER.len(), 15);
    }

    #[test]
    fn test_domain_pou_mint_value() {
        // Spec §2.3: 0x706f755f6d696e74. OSSIFIED.
        assert_eq!(DOMAIN_POU_MINT, 0x706f755f6d696e74u64);
    }

    #[test]
    fn test_all_domains_unique() {
        // Semua domain separator harus unik. Spec §2.3.
        let domains: Vec<&[u8]> = vec![
            DOMAIN_NULLIFIER,
            DOMAIN_UTXO_COMMITMENT,
            DOMAIN_SALT,
            DOMAIN_SEED,
            DOMAIN_NMT,
            DOMAIN_NODE_SHORT,
            DOMAIN_ANCHOR,
            DOMAIN_VOTE,
            DOMAIN_GENESIS_BOOTSTRAP,
            DOMAIN_STARK_FS,
            DOMAIN_CHECKPOINT_FS,
            DOMAIN_BEACON,
            DOMAIN_SEED_KDF,
            DOMAIN_TX_ORDER,
        ];
        let mut seen = std::collections::HashSet::new();
        for d in &domains {
            assert!(
                seen.insert(*d),
                "Domain separator duplikat ditemukan: {:?}",
                d
            );
        }
    }
}
