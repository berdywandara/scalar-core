//! Spec Compliance: Domain Separators
//! Verifikasi semua domain separator OSSIFIED sesuai spec §2.3

use scalar_crypto::domain::*;

#[test]
fn ds_nullifier() {
    assert_eq!(DOMAIN_NULLIFIER, b"scalar_null_v1");
}
#[test]
fn ds_utxo_commitment() {
    assert_eq!(DOMAIN_UTXO_COMMITMENT, b"scalar_utxo_v2");
}
#[test]
fn ds_salt() {
    assert_eq!(DOMAIN_SALT, b"scalar_salt_v1");
}
#[test]
fn ds_seed() {
    assert_eq!(DOMAIN_SEED, b"scalar_seed_v1");
}
#[test]
fn ds_nmt() {
    assert_eq!(DOMAIN_NMT, b"scalar_nmt_v1");
}
#[test]
fn ds_node_short() {
    assert_eq!(DOMAIN_NODE_SHORT, b"scalar_node_short_v1");
}
#[test]
fn ds_anchor() {
    assert_eq!(DOMAIN_ANCHOR, b"scalar_anchor_v1");
}
#[test]
fn ds_vote() {
    assert_eq!(DOMAIN_VOTE, b"scalar_vote_v1");
}
#[test]
fn ds_genesis_bootstrap() {
    assert_eq!(DOMAIN_GENESIS_BOOTSTRAP, b"scalar_genesis_bootstrap_v1");
}
#[test]
fn ds_stark_fs() {
    assert_eq!(DOMAIN_STARK_FS, b"scalar_stark_fs_v1");
}
#[test]
fn ds_checkpoint_fs() {
    assert_eq!(DOMAIN_CHECKPOINT_FS, b"scalar_checkpoint_fs_v1");
}
#[test]
fn ds_beacon() {
    assert_eq!(DOMAIN_BEACON, b"scalar_beacon_v1");
}
#[test]
fn ds_seed_kdf() {
    assert_eq!(DOMAIN_SEED_KDF, b"scalar_v2");
}
#[test]
fn ds_tx_order() {
    assert_eq!(DOMAIN_TX_ORDER, b"scalar_tx_order_v1");
}
#[test]
fn ds_pou_mint() {
    assert_eq!(DOMAIN_POU_MINT, 0x706f755f6d696e74u64);
}
