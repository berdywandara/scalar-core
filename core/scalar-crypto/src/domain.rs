//! Domain Separators — Spec §2.3 OSSIFIED
//!
//! Every hash context uses a unique domain separator to prevent
//! cross-context collision. All separators are OSSIFIED — cannot be
//! changed without a hard fork.
//!
//! Sources:
//! - Genesis spec §2.3 (original 21 separators)
//! - Genesis spec §2.3 / §10.2 (NodeID, SMT active, SMT archived)
//! - Research Package Bagian 8 (IMT, Sub-Epoch, STARKPack)
//!
//! Errata (F-004, Audit 23 May 2026):
//! The following spec/RP documents have byte count typos (off by 1).
//! The code values are correct — the documents miscounted:
//!   DOMAIN_SMT_ACTIVE     : doc says 18, actual 17
//!   DOMAIN_SMT_ARCHIVED   : doc says 20, actual 19
//!   DOMAIN_IMT_FRONTIER   : doc says 20, actual 19
//!   DOMAIN_SUBEPOCH_SEED  : doc says 21, actual 20
//!   DOMAIN_SUBEPOCH_SCORE : doc says 22, actual 21

// ── Genesis Spec §2.3 — Original Separators ─────────────────────────────────

/// Nullifier circuit. Spec §2.3. 16 bytes.
pub const DOMAIN_NULLIFIER: &[u8] = b"scalar_nullifier";

/// UTXO commitment. Spec §2.3. 17 bytes.
pub const DOMAIN_UTXO_COMMITMENT: &[u8] = b"scalar_commitment";

/// Salt derivation. Spec §2.3. 11 bytes.
pub const DOMAIN_SALT: &[u8] = b"scalar_salt";

/// Seed aggregator. Spec §2.3. 11 bytes.
pub const DOMAIN_SEED: &[u8] = b"scalar_seed";

/// NMT peer selection. Spec §2.3. 10 bytes.
pub const DOMAIN_NMT: &[u8] = b"scalar_nmt";

/// Node short ID. Spec §2.3. 17 bytes.
pub const DOMAIN_NODE_SHORT: &[u8] = b"scalar_node_short";

/// Anchor signature. Spec §2.3. 13 bytes.
pub const DOMAIN_ANCHOR: &[u8] = b"scalar_anchor";

/// Governance vote. Spec §2.3. 11 bytes.
pub const DOMAIN_VOTE: &[u8] = b"scalar_vote";

/// Genesis bootstrap. Spec §2.3. 24 bytes.
pub const DOMAIN_GENESIS_BOOTSTRAP: &[u8] = b"scalar_genesis_bootstrap";

/// STARK Fiat-Shamir transcript (transfer). Spec §2.3. 15 bytes.
pub const DOMAIN_STARK_FS: &[u8] = b"scalar_stark_fs";

/// STARK Fiat-Shamir transcript (checkpoint). Spec §2.3. 20 bytes.
pub const DOMAIN_CHECKPOINT_FS: &[u8] = b"scalar_checkpoint_fs";

/// Beacon MAC. Spec §2.3. 13 bytes.
pub const DOMAIN_BEACON: &[u8] = b"scalar_beacon";

/// Seed KDF wallet. Spec §2.3. 17 bytes.
pub const DOMAIN_SEED_KDF: &[u8] = b"scalar_wallet_kdf";

/// TX ordering. Spec §2.3. 15 bytes.
pub const DOMAIN_TX_ORDER: &[u8] = b"scalar_tx_order";

/// TXID domain. Spec §2.3. 11 bytes.
pub const DOMAIN_TXID: &[u8] = b"scalar_txid";

/// Score_i (DMM aggregator selection). Spec §2.3. 12 bytes.
pub const DOMAIN_SCORE: &[u8] = b"scalar_score";

/// NMT random slot seed. Spec §2.3. 10 bytes.
pub const DOMAIN_NMT_RANDOM: &[u8] = b"nmt_random";

/// PoU mint domain (field element). Spec §2.3. 8 bytes.
pub const DOMAIN_POU_MINT: u64 = 0x706f755f6d696e74;

// ── Genesis Spec §2.3 / §10.2 — Previously Scattered ────────────────────────
// These were defined in genesis spec §2.3 but only existed as local
// constants in other crates. Centralized here as canonical source.

/// NodeID salt prefix. Spec §2.3, §10.2. 13 bytes.
/// Used in: Argon2id salt for node_id_full derivation.
pub const DOMAIN_NODEID: &[u8] = b"scalar_nodeid";

/// SMT active layer domain. Spec §2.3. 17 bytes. (Spec doc erroneously states 18 — code is correct.)
/// Used in: NullifierSet active layer hashing (NS_ACTIVE).
pub const DOMAIN_SMT_ACTIVE: &[u8] = b"scalar_smt_active";

/// SMT archived layer domain. Spec §2.3. 19 bytes. (Spec doc erroneously states 20 — code is correct.)
/// Used in: NullifierSet checkpoint layer hashing (NS_CHECKPOINT),
/// and SubEpochCommitment hash construction for cumulative_utxo_root.
pub const DOMAIN_SMT_ARCHIVED: &[u8] = b"scalar_smt_archived";

// ── Research Package — IMT (Incremental Merkle Tree) ─────────────────────────
// Spec: Research Package Bagian 8, Optimasi §A domain table.
// Decision: D-003 (imt_frontier_root from SubEpochCommitment quorum 5/7).
// Decision: D-006 (scalar_imt_frontier usage clarification).

/// IMT leaf hash. Research Package Bagian 8. 15 bytes.
/// Used in: IMT_MembershipVerify — hashing leaf nodes.
/// Formula: Poseidon2(DOMAIN_IMT_LEAF || commitment || leaf_index)
pub const DOMAIN_IMT_LEAF: &[u8] = b"scalar_imt_leaf";

/// IMT internal node hash. Research Package Bagian 8. 15 bytes.
/// Used in: IMT_MembershipVerify — hashing internal tree nodes.
/// Formula: Poseidon2(DOMAIN_IMT_NODE || left_child || right_child)
pub const DOMAIN_IMT_NODE: &[u8] = b"scalar_imt_node";

/// IMT frontier wrapper. Research Package Bagian 8. 19 bytes. (RP doc erroneously states 20 — code is correct.)
/// Used EXCLUSIVELY in: SubEpochCommitment hash construction to
/// distinguish imt_frontier_root from cumulative_utxo_root.
/// NOT used in: IMT_MembershipVerify (use imt_leaf/imt_node).
/// NOT used in: HeartbeatUnit MAC (use scalar_beacon).
/// Decision D-006 enforced.
pub const DOMAIN_IMT_FRONTIER: &[u8] = b"scalar_imt_frontier";

// ── Research Package — Sub-Epoch Finality ────────────────────────────────────
// Spec: Research Package Bagian 8, Optimasi §B.

/// Sub-epoch hash. Research Package Bagian 8. 15 bytes.
/// Used in: SubEpochCommitment hash construction (outer wrapper).
pub const DOMAIN_SUBEPOCH: &[u8] = b"scalar_subepoch";

/// Sub-epoch aggregator seed. Research Package Bagian 8. 20 bytes. (RP doc erroneously states 21 — code is correct.)
/// Used in: Deterministic aggregator selection per sub-epoch.
/// Formula: BLAKE3(DOMAIN_SUBEPOCH_SEED || committed_manifest_hash(k-1) || subepoch_id)
pub const DOMAIN_SUBEPOCH_SEED: &[u8] = b"scalar_subepoch_seed";

/// Sub-epoch validator scoring. Research Package Bagian 8. 21 bytes. (RP doc erroneously states 22 — code is correct.)
/// Used in: Deterministic validator ranking per sub-epoch.
/// Formula: BLAKE3(DOMAIN_SUBEPOCH_SCORE || node_id_full || subepoch_seed)
pub const DOMAIN_SUBEPOCH_SCORE: &[u8] = b"scalar_subepoch_score";

/// Sub-epoch Fiat-Shamir transcript. Research Package Bagian 8. 18 bytes.
/// Used in: STARKPack Fiat-Shamir transcript Phase 1 (per-proof commitment).
/// Distinct from DOMAIN_STARK_FS (15 bytes, transfer) and
/// DOMAIN_CHECKPOINT_FS (20 bytes, checkpoint).
pub const DOMAIN_SUBEPOCH_FS: &[u8] = b"scalar_subepoch_fs";

// ── Research Package — STARKPack Aggregator ──────────────────────────────────
// Spec: Research Package Bagian 8, Decision D-002.

/// STARKPack batch Fiat-Shamir. Research Package Bagian 8. 18 bytes.
/// Used in: STARKPack Fiat-Shamir transcript Phase 3 (global DEEP-FRI commitment).
/// Decision D-002: batch size N=256, soundness 2^-120.
pub const DOMAIN_STARK_BATCH: &[u8] = b"scalar_stark_batch";

/// UTXO Set accumulator root domain. Spec §2.3, §8.5, §4.3 CB. 15 bytes. OSSIFIED.
///
/// Used in: UtxoSetAccumulator::compute_root() — BLAKE3 domain prefix for
/// the sequential hash accumulator (genesis architecture, pre-testnet temporary).
/// Wajib diganti dengan IMT-based EpochSMT sebelum testnet (utang teknis D3).
pub const DOMAIN_UTXO_SMT: &[u8] = b"scalar_utxo_set";

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing separators — value and length assertions ─────────────────────

    #[test]
    fn test_domain_nullifier_len() {
        assert_eq!(DOMAIN_NULLIFIER, b"scalar_nullifier");
        assert_eq!(DOMAIN_NULLIFIER.len(), 16);
    }

    #[test]
    fn test_domain_utxo_commitment_len() {
        assert_eq!(DOMAIN_UTXO_COMMITMENT, b"scalar_commitment");
        assert_eq!(DOMAIN_UTXO_COMMITMENT.len(), 17);
    }

    #[test]
    fn test_domain_salt_len() {
        assert_eq!(DOMAIN_SALT, b"scalar_salt");
        assert_eq!(DOMAIN_SALT.len(), 11);
    }

    #[test]
    fn test_domain_seed_len() {
        assert_eq!(DOMAIN_SEED, b"scalar_seed");
        assert_eq!(DOMAIN_SEED.len(), 11);
    }

    #[test]
    fn test_domain_nmt_len() {
        assert_eq!(DOMAIN_NMT, b"scalar_nmt");
        assert_eq!(DOMAIN_NMT.len(), 10);
    }

    #[test]
    fn test_domain_node_short_len() {
        assert_eq!(DOMAIN_NODE_SHORT, b"scalar_node_short");
        assert_eq!(DOMAIN_NODE_SHORT.len(), 17);
    }

    #[test]
    fn test_domain_anchor_len() {
        assert_eq!(DOMAIN_ANCHOR, b"scalar_anchor");
        assert_eq!(DOMAIN_ANCHOR.len(), 13);
    }

    #[test]
    fn test_domain_vote_len() {
        assert_eq!(DOMAIN_VOTE, b"scalar_vote");
        assert_eq!(DOMAIN_VOTE.len(), 11);
    }

    #[test]
    fn test_domain_genesis_bootstrap_len() {
        assert_eq!(DOMAIN_GENESIS_BOOTSTRAP, b"scalar_genesis_bootstrap");
        assert_eq!(DOMAIN_GENESIS_BOOTSTRAP.len(), 24);
    }

    #[test]
    fn test_domain_stark_fs_len() {
        assert_eq!(DOMAIN_STARK_FS, b"scalar_stark_fs");
        assert_eq!(DOMAIN_STARK_FS.len(), 15);
    }

    #[test]
    fn test_domain_checkpoint_fs_len() {
        assert_eq!(DOMAIN_CHECKPOINT_FS, b"scalar_checkpoint_fs");
        assert_eq!(DOMAIN_CHECKPOINT_FS.len(), 20);
    }

    #[test]
    fn test_domain_beacon_len() {
        assert_eq!(DOMAIN_BEACON, b"scalar_beacon");
        assert_eq!(DOMAIN_BEACON.len(), 13);
    }

    #[test]
    fn test_domain_seed_kdf_len() {
        assert_eq!(DOMAIN_SEED_KDF, b"scalar_wallet_kdf");
        assert_eq!(DOMAIN_SEED_KDF.len(), 17);
    }

    #[test]
    fn test_domain_tx_order_len() {
        assert_eq!(DOMAIN_TX_ORDER, b"scalar_tx_order");
        assert_eq!(DOMAIN_TX_ORDER.len(), 15);
    }

    #[test]
    fn test_domain_txid_len() {
        assert_eq!(DOMAIN_TXID, b"scalar_txid");
        assert_eq!(DOMAIN_TXID.len(), 11);
    }

    #[test]
    fn test_domain_score_len() {
        assert_eq!(DOMAIN_SCORE, b"scalar_score");
        assert_eq!(DOMAIN_SCORE.len(), 12);
    }

    #[test]
    fn test_domain_nmt_random_len() {
        assert_eq!(DOMAIN_NMT_RANDOM, b"nmt_random");
        assert_eq!(DOMAIN_NMT_RANDOM.len(), 10);
    }

    #[test]
    fn test_domain_pou_mint_value() {
        assert_eq!(DOMAIN_POU_MINT, 0x706f755f6d696e74u64);
    }

    // ── Genesis spec — previously scattered separators ────────────────────────

    #[test]
    fn test_domain_nodeid_len() {
        // Spec §2.3, §10.2: 13 bytes. OSSIFIED.
        assert_eq!(DOMAIN_NODEID, b"scalar_nodeid");
        assert_eq!(DOMAIN_NODEID.len(), 13);
    }

    #[test]
    fn test_domain_smt_active_len() {
        // Spec §2.3: 17 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SMT_ACTIVE, b"scalar_smt_active");
        assert_eq!(DOMAIN_SMT_ACTIVE.len(), 17);
    }

    #[test]
    fn test_domain_smt_archived_len() {
        // Spec §2.3: 19 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SMT_ARCHIVED, b"scalar_smt_archived");
        assert_eq!(DOMAIN_SMT_ARCHIVED.len(), 19);
    }

    // ── Research Package — IMT separators ─────────────────────────────────────

    #[test]
    fn test_domain_imt_leaf_len() {
        // Research Package Bagian 8: 15 bytes. OSSIFIED.
        assert_eq!(DOMAIN_IMT_LEAF, b"scalar_imt_leaf");
        assert_eq!(DOMAIN_IMT_LEAF.len(), 15);
    }

    #[test]
    fn test_domain_imt_node_len() {
        // Research Package Bagian 8: 15 bytes. OSSIFIED.
        assert_eq!(DOMAIN_IMT_NODE, b"scalar_imt_node");
        assert_eq!(DOMAIN_IMT_NODE.len(), 15);
    }

    #[test]
    fn test_domain_imt_frontier_len() {
        // Research Package Bagian 8: 19 bytes. OSSIFIED.
        assert_eq!(DOMAIN_IMT_FRONTIER, b"scalar_imt_frontier");
        assert_eq!(DOMAIN_IMT_FRONTIER.len(), 19);
    }

    // ── Research Package — Sub-Epoch separators ───────────────────────────────

    #[test]
    fn test_domain_subepoch_len() {
        // Research Package Bagian 8: 15 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SUBEPOCH, b"scalar_subepoch");
        assert_eq!(DOMAIN_SUBEPOCH.len(), 15);
    }

    #[test]
    fn test_domain_subepoch_seed_len() {
        // Research Package Bagian 8: 20 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SUBEPOCH_SEED, b"scalar_subepoch_seed");
        assert_eq!(DOMAIN_SUBEPOCH_SEED.len(), 20);
    }

    #[test]
    fn test_domain_subepoch_score_len() {
        // Research Package Bagian 8: 21 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SUBEPOCH_SCORE, b"scalar_subepoch_score");
        assert_eq!(DOMAIN_SUBEPOCH_SCORE.len(), 21);
    }

    #[test]
    fn test_domain_subepoch_fs_len() {
        // Research Package Bagian 8: 18 bytes. OSSIFIED.
        assert_eq!(DOMAIN_SUBEPOCH_FS, b"scalar_subepoch_fs");
        assert_eq!(DOMAIN_SUBEPOCH_FS.len(), 18);
    }

    // ── Research Package — STARKPack separator ────────────────────────────────

    #[test]
    fn test_domain_stark_batch_len() {
        // Research Package Bagian 8, Decision D-002: 18 bytes. OSSIFIED.
        assert_eq!(DOMAIN_STARK_BATCH, b"scalar_stark_batch");
        assert_eq!(DOMAIN_STARK_BATCH.len(), 18);
    }

    // ── Cross-cutting: uniqueness and no-collision ────────────────────────────

    #[test]
    fn test_all_domains_unique() {
        // INV-4.5: No two contexts may use the same separator.
        // Covers all 28 byte-slice separators (POU_MINT excluded — u64 field element).
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
            DOMAIN_TXID,
            DOMAIN_SCORE,
            DOMAIN_NMT_RANDOM,
            DOMAIN_NODEID,
            DOMAIN_SMT_ACTIVE,
            DOMAIN_SMT_ARCHIVED,
            DOMAIN_IMT_LEAF,
            DOMAIN_IMT_NODE,
            DOMAIN_IMT_FRONTIER,
            DOMAIN_SUBEPOCH,
            DOMAIN_SUBEPOCH_SEED,
            DOMAIN_SUBEPOCH_SCORE,
            DOMAIN_SUBEPOCH_FS,
            DOMAIN_STARK_BATCH,
            DOMAIN_UTXO_SMT,
        ];
        let mut seen = std::collections::HashSet::new();
        for d in &domains {
            assert!(
                seen.insert(*d),
                "Duplicate domain separator found: {:?}",
                std::str::from_utf8(d).unwrap_or("<invalid utf8>")
            );
        }
        assert_eq!(
            domains.len(),
            29,
            "Expected 29 byte-slice domain separators"
        );
    }

    // NOTE: Prefix collision test intentionally omitted.
    // scalar_subepoch is a prefix of scalar_subepoch_seed/score/fs by design
    // (Research Package Bagian 8). Safety is ensured by the fact that each
    // separator is used in a distinct hash context with different data types
    // and lengths appended after the separator.
}

// ── D.1 Decision (FASE D) — DOMAIN_UTXO_SMT OSSIFIED ────────────────────────
// Decision: register b"scalar_utxo_set" as OSSIFIED separator.
// Rationale: value was always correct per spec §2.3; this formalizes
// its presence in the canonical registry so domain.rs remains the
// single source of truth ("Secured by Analysis"). No byte value
// changed — utxo_set_root on-chain is unaffected.
