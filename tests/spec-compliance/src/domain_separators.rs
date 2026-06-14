//! Spec Compliance: Domain Separators
//! Verifikasi semua domain separator OSSIFIED sesuai spec §2.3

use scalar_crypto::domain::*;

#[test]
fn ds_nullifier() {
    // Spec §2.3: b"scalar_nullifier" (16 byte). OSSIFIED.
    assert_eq!(DOMAIN_NULLIFIER, b"scalar_nullifier");
}
#[test]
fn ds_utxo_commitment() {
    // Spec §2.3: b"scalar_commitment" (17 byte). OSSIFIED.
    assert_eq!(DOMAIN_UTXO_COMMITMENT, b"scalar_commitment");
}
#[test]
fn ds_salt() {
    // Spec §2.3: b"scalar_salt" (11 byte). OSSIFIED.
    assert_eq!(DOMAIN_SALT, b"scalar_salt");
}
#[test]
fn ds_seed() {
    // Spec §2.3: b"scalar_seed" (11 byte). OSSIFIED.
    assert_eq!(DOMAIN_SEED, b"scalar_seed");
}
#[test]
fn ds_nmt() {
    // Spec §2.3: b"scalar_nmt" (10 byte). OSSIFIED.
    assert_eq!(DOMAIN_NMT, b"scalar_nmt");
}
#[test]
fn ds_node_short() {
    // Spec §2.3: b"scalar_node_short" (17 byte). OSSIFIED.
    assert_eq!(DOMAIN_NODE_SHORT, b"scalar_node_short");
}
#[test]
fn ds_anchor() {
    // Spec §2.3: b"scalar_anchor" (13 byte). OSSIFIED.
    assert_eq!(DOMAIN_ANCHOR, b"scalar_anchor");
}
#[test]
fn ds_vote() {
    // OSSIFIED — SCALAR-PROTOCOL §13.1. Zero-versioning.
    assert_eq!(DOMAIN_VOTE, b"scalar.governance.vote");
    assert_eq!(DOMAIN_REBIND, b"scalar.governance.rebind");
}
#[test]
fn ds_genesis_bootstrap() {
    // Spec §2.3: b"scalar_genesis_bootstrap" (24 byte). OSSIFIED.
    assert_eq!(DOMAIN_GENESIS_BOOTSTRAP, b"scalar_genesis_bootstrap");
}
#[test]
fn ds_stark_fs() {
    // Spec §2.3: b"scalar_stark_fs" (15 byte). OSSIFIED.
    assert_eq!(DOMAIN_STARK_FS, b"scalar_stark_fs");
}
#[test]
fn ds_checkpoint_fs() {
    // Spec §2.3: b"scalar_checkpoint_fs" (20 byte). OSSIFIED.
    assert_eq!(DOMAIN_CHECKPOINT_FS, b"scalar_checkpoint_fs");
}
#[test]
fn ds_beacon() {
    // Spec §2.3: b"scalar_beacon" (13 byte). OSSIFIED.
    assert_eq!(DOMAIN_BEACON, b"scalar_beacon");
}
#[test]
fn ds_seed_kdf() {
    // Spec §2.3: b"scalar_wallet_kdf" (17 byte). OSSIFIED.
    assert_eq!(DOMAIN_SEED_KDF, b"scalar_wallet_kdf");
}
#[test]
fn ds_tx_order() {
    // Spec §2.3: b"scalar_tx_order" (15 byte). OSSIFIED.
    assert_eq!(DOMAIN_TX_ORDER, b"scalar_tx_order");
}
#[test]
fn ds_pou_mint() {
    // Spec §2.3: 0x706f755f6d696e74 (u64 field element). OSSIFIED.
    assert_eq!(DOMAIN_POU_MINT, 0x706f755f6d696e74u64);
}

// ── Genesis spec §2.3 — previously scattered, now centralized ────────────

#[test]
fn ds_nodeid() {
    // Spec §2.3, §10.2: b"scalar_nodeid" (13 byte). OSSIFIED.
    assert_eq!(DOMAIN_NODEID, b"scalar_nodeid");
    assert_eq!(DOMAIN_NODEID.len(), 13);
}
#[test]
fn ds_smt_active() {
    // Spec §2.3: b"scalar_smt_active" (17 byte). OSSIFIED.
    assert_eq!(DOMAIN_SMT_ACTIVE, b"scalar_smt_active");
    assert_eq!(DOMAIN_SMT_ACTIVE.len(), 17);
}
#[test]
fn ds_smt_archived() {
    // Spec §2.3: b"scalar_smt_archived" (19 byte). OSSIFIED.
    assert_eq!(DOMAIN_SMT_ARCHIVED, b"scalar_smt_archived");
    assert_eq!(DOMAIN_SMT_ARCHIVED.len(), 19);
}

// ── Research Package Bagian 8 — IMT ──────────────────────────────────────

#[test]
fn ds_imt_leaf() {
    // Research Package Bagian 8: b"scalar_imt_leaf" (15 byte). OSSIFIED.
    assert_eq!(DOMAIN_IMT_LEAF, b"scalar_imt_leaf");
    assert_eq!(DOMAIN_IMT_LEAF.len(), 15);
}
#[test]
fn ds_imt_node() {
    // Research Package Bagian 8: b"scalar_imt_node" (15 byte). OSSIFIED.
    assert_eq!(DOMAIN_IMT_NODE, b"scalar_imt_node");
    assert_eq!(DOMAIN_IMT_NODE.len(), 15);
}
#[test]
fn ds_imt_frontier() {
    // Research Package Bagian 8, Decision D-006: b"scalar_imt_frontier" (19 byte). OSSIFIED.
    assert_eq!(DOMAIN_IMT_FRONTIER, b"scalar_imt_frontier");
    assert_eq!(DOMAIN_IMT_FRONTIER.len(), 19);
}

// ── Research Package Bagian 8 — Sub-Epoch ────────────────────────────────

#[test]
fn ds_subepoch() {
    // Research Package Bagian 8: b"scalar_subepoch" (15 byte). OSSIFIED.
    assert_eq!(DOMAIN_SUBEPOCH, b"scalar_subepoch");
    assert_eq!(DOMAIN_SUBEPOCH.len(), 15);
}
#[test]
fn ds_subepoch_seed() {
    // Research Package Bagian 8: b"scalar_subepoch_seed" (20 byte). OSSIFIED.
    assert_eq!(DOMAIN_SUBEPOCH_SEED, b"scalar_subepoch_seed");
    assert_eq!(DOMAIN_SUBEPOCH_SEED.len(), 20);
}
#[test]
fn ds_subepoch_score() {
    // Research Package Bagian 8: b"scalar_subepoch_score" (21 byte). OSSIFIED.
    assert_eq!(DOMAIN_SUBEPOCH_SCORE, b"scalar_subepoch_score");
    assert_eq!(DOMAIN_SUBEPOCH_SCORE.len(), 21);
}
#[test]
fn ds_subepoch_fs() {
    // Research Package Bagian 8: b"scalar_subepoch_fs" (18 byte). OSSIFIED.
    assert_eq!(DOMAIN_SUBEPOCH_FS, b"scalar_subepoch_fs");
    assert_eq!(DOMAIN_SUBEPOCH_FS.len(), 18);
}

// ── Research Package Bagian 8 — STARKPack ────────────────────────────────

#[test]
fn ds_stark_batch() {
    // Research Package Bagian 8, Decision D-002: b"scalar_stark_batch" (18 byte). OSSIFIED.
    assert_eq!(DOMAIN_STARK_BATCH, b"scalar_stark_batch");
    assert_eq!(DOMAIN_STARK_BATCH.len(), 18);
}
