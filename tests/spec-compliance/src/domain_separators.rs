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
    // Spec §2.3: b"scalar_vote" (11 byte). OSSIFIED.
    assert_eq!(DOMAIN_VOTE, b"scalar_vote");
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
