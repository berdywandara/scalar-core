//! Canonical Transaction Ordering — Spec §8.5 v11.1-FINAL
//!
//! Domain separator TX_ORDER_DOMAIN = b"scalar_tx_order_v1" (OSSIFIED — spec §2.3).
//! Domain separator TXID_DOMAIN = b"scalar_txid_v1" (OSSIFIED — spec §2.3, v11.1-FINAL).
//!
//! TXID = BLAKE3(TXID_DOMAIN || input_nullifiers[] || output_commitments[] || fee_total || epoch_id || crypto_version)
//! tx_ordering_key = BLAKE3(TX_ORDER_DOMAIN || TXID || epoch_id)
//!
//! Every node sorts all valid transactions within an epoch by
//! tx_ordering_key before inserting them into the UTXO set SMT.
//!
//! Determinism is guaranteed because TXID depends only on verified transaction data,
//! not on the non-deterministic STARK proof.
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.

use blake3::Hasher;

// ── Ossified constants — spec §2.3, §8.5 ─────────────────────────────────────

/// Domain separator for canonical transaction ordering. OSSIFIED — spec §2.3.
/// TX_ORDER_DOMAIN = b"scalar_tx_order_v1" (18 bytes).
pub const TX_ORDER_DOMAIN: &[u8] = b"scalar_tx_order_v1";

/// Length of TX_ORDER_DOMAIN in bytes. Spec §2.3.
pub const TX_ORDER_DOMAIN_LEN: usize = 18;

/// Domain separator for TXID computation. OSSIFIED — spec §2.3 v11.1-FINAL.
/// TXID_DOMAIN = b"scalar_txid_v1" (14 bytes).
pub const TXID_DOMAIN: &[u8] = b"scalar_txid_v1";

/// Length of TXID_DOMAIN in bytes.
pub const TXID_DOMAIN_LEN: usize = 14;

// ── TxEntry — transaction representation for ordering ────────────────────────

/// Minimal transaction representation for canonical ordering. Spec §8.5.
///
/// `tx_hash` stores the TXID computed as:
///   TXID = BLAKE3(TXID_DOMAIN || input_nullifiers[] || output_commitments[] || fee_total || epoch_id || crypto_version)
///
/// TXID is deterministic because it depends only on cryptographically verified
/// transaction data, NOT on the non-deterministic STARK proof. Spec §8.5 v11.1-FINAL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEntry {
    /// TXID — deterministic BLAKE3 hash of transaction components.
    /// Computed via compute_txid(). Spec §8.5 v11.1-FINAL.
    pub tx_hash: [u8; 32],
    /// Opaque transaction data for UTXO set processing.
    pub tx_data: Vec<u8>,
}

/// Ordering key computed for a single transaction. Spec §8.5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOrderingKey {
    pub txid: [u8; 32],
    /// tx_ordering_key = BLAKE3(TX_ORDER_DOMAIN || TXID || epoch_id). Spec §8.5.
    pub ordering_key: [u8; 32],
}

// ── TXID Computation ─────────────────────────────────────────────────────────

/// Compute deterministic TXID from transaction components. Spec §8.5 v11.1-FINAL.
///
/// TXID = BLAKE3(
///     TXID_DOMAIN ||
///     input_nullifiers[] ||
///     output_commitments[] ||
///     fee_total_le64 ||
///     epoch_id_le64 ||
///     crypto_version_u8
/// )
///
/// Domain separator OSSIFIED: b"scalar_txid_v1" — spec §2.3.
pub fn compute_txid(
    input_nullifiers: &[[u8; 32]],
    output_commitments: &[[u8; 32]],
    fee_total: u64,
    epoch_id: u64,
    crypto_version: u8,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(TXID_DOMAIN);
    for nullifier in input_nullifiers {
        hasher.update(nullifier);
    }
    for commitment in output_commitments {
        hasher.update(commitment);
    }
    hasher.update(&fee_total.to_le_bytes());
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(&[crypto_version]);
    *hasher.finalize().as_bytes()
}

/// Compute tx_ordering_key for a single transaction. Spec §8.5 v11.1-FINAL.
///
/// tx_ordering_key = BLAKE3(TX_ORDER_DOMAIN || txid || epoch_id_le64)
pub fn compute_tx_ordering_key(txid: &[u8; 32], epoch_id: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(TX_ORDER_DOMAIN);
    hasher.update(txid);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Sort transactions canonically for a given epoch. Spec §8.5 v11.1-FINAL.
pub fn sort_transactions_canonical(txs: &[TxEntry], epoch_id: u64) -> Vec<TxEntry> {
    let mut keyed: Vec<(TxOrderingKey, &TxEntry)> = txs
        .iter()
        .map(|tx| {
            let key = TxOrderingKey {
                txid: tx.tx_hash,
                ordering_key: compute_tx_ordering_key(&tx.tx_hash, epoch_id),
            };
            (key, tx)
        })
        .collect();

    keyed.sort_unstable_by_key(|(k, _)| k.ordering_key);
    keyed.into_iter().map(|(_, tx)| tx.clone()).collect()
}

/// Verify that TX_ORDER_DOMAIN is unchanged (compile-time check). Spec §2.3.
pub const fn tx_order_domain_ossified() -> &'static [u8] {
    TX_ORDER_DOMAIN
}

/// Verify that TXID_DOMAIN is unchanged (compile-time check). Spec §2.3.
pub const fn txid_domain_ossified() -> &'static [u8] {
    TXID_DOMAIN
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(seed: u8) -> TxEntry {
        let txid = compute_txid(
            &[[seed; 32]],
            &[[seed.wrapping_add(1); 32]],
            40,
            seed as u64,
            0x03,
        );
        TxEntry {
            tx_hash: txid,
            tx_data: vec![seed, seed, seed],
        }
    }

    fn make_txid(seed: u8, epoch_id: u64) -> [u8; 32] {
        compute_txid(
            &[[seed; 32]],
            &[[seed.wrapping_add(1); 32]],
            40,
            epoch_id,
            0x03,
        )
    }

    // TXID Tests
    #[test]
    fn unit_test_txid_deterministic() {
        let nullifiers = &[[0x42u8; 32]];
        let commitments = &[[0x43u8; 32]];
        let fee = 100u64;
        let epoch = 5u64;
        let version = 0x03u8;
        let txid1 = compute_txid(nullifiers, commitments, fee, epoch, version);
        let txid2 = compute_txid(nullifiers, commitments, fee, epoch, version);
        assert_eq!(
            txid1, txid2, 
            "TXID must be deterministic for identical inputs"
        );
    }

    #[test]
    fn unit_test_txid_different_nullifier() {
        let txid1 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 40, 1, 0x03);
        let txid2 = compute_txid(&[[0x02; 32]], &[[0x10; 32]], 40, 1, 0x03);
        assert_ne!(
            txid1, txid2, "TXID must differ for different nullifiers"
        );
    }

    #[test]
    fn unit_test_txid_different_commitment() {
        let txid1 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 40, 1, 0x03);
        let txid2 = compute_txid(&[[0x01; 32]], &[[0x11; 32]], 40, 1, 0x03);
        assert_ne!(
            txid1, txid2, 
            "TXID must differ for different commitments"
        );
    }

    #[test]
    fn unit_test_txid_different_fee() {
        let txid1 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 40, 1, 0x03);
        let txid2 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 50, 1, 0x03);
        assert_ne!(
            txid1, txid2, 
            "TXID must differ for different fees"
        );
    }

    #[test]
    fn unit_test_txid_different_epoch() {
        let txid1 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 40, 1, 0x03);
        let txid2 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 40, 2, 0x03);
        assert_ne!(
            txid1, txid2, 
            "TXID must differ for different epochs"
        );
    }

    #[test]
    fn unit_test_txid_different_crypto_version() {
        let txid1 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 40, 1, 0x03);
        let txid2 = compute_txid(&[[0x01; 32]], &[[0x10; 32]], 40, 1, 0x04);
        assert_ne!(
            txid1, txid2, 
            "TXID must differ for different crypto_version"
        );
    }

    #[test]
    fn unit_test_txid_nonzero() {
        let txid = compute_txid(&[[0x00; 32]], &[[0x00; 32]], 0, 0, 0x00);
        assert_ne!(
            txid, [0u8; 32], 
            "TXID must not be zero");
    }

    #[test]
    fn unit_test_txid_uses_domain_separator() {
        let nullifiers = &[[0x42u8; 32]];
        let commitments = &[[0x43u8; 32]];
        let fee = 100u64;
        let epoch = 5u64;
        let version = 0x03u8;
        let with_domain = compute_txid(nullifiers, commitments, fee, epoch, version);
        // FIX: `for n in nullifiers { hasher.update(n); }` satu baris → dipecah
        let mut hasher = Hasher::new();
        for n in nullifiers {
            hasher.update(n);
        }
        for c in commitments {
            hasher.update(c);
        }
        hasher.update(&fee.to_le_bytes());
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&[version]);
        let without_domain = *hasher.finalize().as_bytes();
        assert_ne!(
            with_domain, without_domain,
            "Domain separator must be used in TXID"
        );
    }

    #[test]
    fn unit_test_txid_multiple_inputs_outputs() {
        let txid_1_1 = compute_txid(&[[0xAA; 32]], &[[0xBB; 32]], 40, 1, 0x03);
        // FIX: baris terlalu panjang → argumen array dipecah
        let txid_2_2 = compute_txid(
            &[[0xAA; 32], [0xCC; 32]],
            &[[0xBB; 32], [0xDD; 32]],
            80,
            1,
            0x03,
        );
        assert_ne!(
            txid_1_1, txid_2_2,
            "2-in/2-out TXID must differ from 1-in/1-out"
        );
    }

    // Ordering Key Tests
    #[test]
    fn unit_test_tx_ordering_key_deterministic() {
        let txid = make_txid(0x42, 10);
        let k1 = compute_tx_ordering_key(&txid, 10);
        let k2 = compute_tx_ordering_key(&txid, 10);
        assert_eq!(
            k1, k2,
            "ordering_key must be deterministic for identical inputs"
        );
    }

    #[test]
    fn unit_test_tx_ordering_key_different_epoch() {
        let txid = make_txid(0x42, 10);
        let k1 = compute_tx_ordering_key(&txid, 10);
        let k2 = compute_tx_ordering_key(&txid, 11);
        assert_ne!(k1, k2, "ordering_key must differ for different epochs");
    }

    #[test]
    fn unit_test_tx_ordering_key_different_txid() {
        let k1 = compute_tx_ordering_key(&make_txid(0x01, 10), 10);
        let k2 = compute_tx_ordering_key(&make_txid(0x02, 10), 10);
        assert_ne!(k1, k2, "ordering_key must differ for different txid");
    }

    #[test]
    fn unit_test_tx_ordering_key_nonzero() {
        let k = compute_tx_ordering_key(&[0u8; 32], 0);
        assert_ne!(k, [0u8; 32], "ordering_key must not be zero");
    }

    // Canonical Sort Tests
    #[test]
    fn test_canonical_sort_stable() {
        let txs_asc = vec![make_tx(0x01), make_tx(0x02), make_tx(0x03)];
        let txs_desc = vec![make_tx(0x03), make_tx(0x02), make_tx(0x01)];
        let txs_shuffled = vec![make_tx(0x02), make_tx(0x01), make_tx(0x03)];
        let sorted_asc = sort_transactions_canonical(&txs_asc, 5);
        let sorted_desc = sort_transactions_canonical(&txs_desc, 5);
        let sorted_shuffled = sort_transactions_canonical(&txs_shuffled, 5);
        assert_eq!(sorted_asc, sorted_desc);
        assert_eq!(sorted_asc, sorted_shuffled);
    }

    #[test]
    fn integration_test_utxo_root_identical() {
        // FIX: vec literal panjang → satu item per baris
        let tx_set = vec![
            make_tx(0xAA),
            make_tx(0xBB),
            make_tx(0xCC),
            make_tx(0xDD),
            make_tx(0xEE),
        ];
        let node_a_input = tx_set.clone();
        let node_b_input = vec![
            make_tx(0xEE),
            make_tx(0xCC),
            make_tx(0xAA),
            make_tx(0xDD),
            make_tx(0xBB),
        ];
        let sorted_a = sort_transactions_canonical(&node_a_input, 7);
        let sorted_b = sort_transactions_canonical(&node_b_input, 7);
        assert_eq!(sorted_a, sorted_b);
        let hash_a = blake3_tx_list_hash(&sorted_a);
        let hash_b = blake3_tx_list_hash(&sorted_b);
        assert_eq!(hash_a, hash_b);
    }

    fn blake3_tx_list_hash(txs: &[TxEntry]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        for tx in txs {
            hasher.update(&tx.tx_hash);
        }
        *hasher.finalize().as_bytes()
    }

    // Domain Separator Tests
    #[test]
    fn test_domain_separator_tx_order_ossified() {
        assert_eq!(TX_ORDER_DOMAIN, b"scalar_tx_order_v1");
        assert_eq!(TX_ORDER_DOMAIN_LEN, 18);
        assert_eq!(TX_ORDER_DOMAIN.len(), TX_ORDER_DOMAIN_LEN);
    }

    #[test]
    fn test_domain_separator_txid_ossified() {
        assert_eq!(TXID_DOMAIN, b"scalar_txid_v1");
        assert_eq!(TXID_DOMAIN_LEN, 14);
        assert_eq!(TXID_DOMAIN.len(), TXID_DOMAIN_LEN);
    }

    #[test]
    fn test_domain_separator_via_const_fn() {
        assert_eq!(tx_order_domain_ossified(), TX_ORDER_DOMAIN);
        assert_eq!(txid_domain_ossified(), TXID_DOMAIN);
    }

    #[test]
    fn test_domains_are_distinct() {
        assert_ne!(TX_ORDER_DOMAIN, TXID_DOMAIN);
    }

    // Collision Tests
    #[test]
    fn prop_test_ordering_no_collision() {
        let epoch_id = 42u64;
        let mut keys: Vec<[u8; 32]> = (0u8..=255)
            .map(|seed| {
                let txid = make_txid(seed, epoch_id);
                compute_tx_ordering_key(&txid, epoch_id)
            })
            .collect();
        let original_len = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), original_len);
    }

    #[test]
    fn prop_test_txid_no_collision() {
        let mut txids: Vec<[u8; 32]> = (0u8..=255)
            .map(|seed| {
                compute_txid(
                    &[[seed; 32]],
                    &[[seed.wrapping_add(1); 32]],
                    40 + seed as u64,
                    5,
                    0x03,
                )
            })
            .collect();
        let original_len = txids.len();
        txids.sort_unstable();
        txids.dedup();
        assert_eq!(txids.len(), original_len);
    }

    // Edge Cases
    #[test]
    fn test_empty_tx_list_returns_empty() {
        let result = sort_transactions_canonical(&[], 1);
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_tx_unchanged() {
        let txs = vec![make_tx(0x42)];
        let sorted = sort_transactions_canonical(&txs, 1);
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].tx_hash, make_txid(0x42, 0x42u64));
    }

    #[test]
    fn test_ordering_epoch_isolation() {
        let txs = vec![make_tx(0x01), make_tx(0x02), make_tx(0x03)];
        let sorted_epoch_1 = sort_transactions_canonical(&txs, 1);
        let sorted_epoch_2 = sort_transactions_canonical(&txs, 2);
        let key_1_0 = compute_tx_ordering_key(&txs[0].tx_hash, 1);
        let key_2_0 = compute_tx_ordering_key(&txs[0].tx_hash, 2);
        assert_ne!(key_1_0, key_2_0);
        let sorted_epoch_1_again = sort_transactions_canonical(&txs, 1);
        assert_eq!(sorted_epoch_1, sorted_epoch_1_again);
        let _ = sorted_epoch_2;
    }

    #[test]
    fn test_little_endian_epoch_id() {
        let txid = make_txid(0x42, 10);
        let mut hasher_le = Hasher::new();
        hasher_le.update(TX_ORDER_DOMAIN);
        hasher_le.update(&txid);
        hasher_le.update(&10u64.to_le_bytes());
        let expected_le = *hasher_le.finalize().as_bytes();
        let mut hasher_be = Hasher::new();
        hasher_be.update(TX_ORDER_DOMAIN);
        hasher_be.update(&txid);
        hasher_be.update(&10u64.to_be_bytes());
        let expected_be = *hasher_be.finalize().as_bytes();
        let actual = compute_tx_ordering_key(&txid, 10);
        assert_eq!(actual, expected_le);
        assert_ne!(actual, expected_be);
    }

    #[test]
    fn test_txid_little_endian_values() {
        let nullifiers = &[[0x01; 32]];
        let commitments = &[[0x02; 32]];
        let txid_le = compute_txid(nullifiers, commitments, 256, 1, 0x03);
        let mut hasher_le = Hasher::new();
        hasher_le.update(TXID_DOMAIN);
        // FIX: for loop satu baris → dipecah (konsisten dengan loop lain di file ini)
        for n in nullifiers {
            hasher_le.update(n);
        }
        for c in commitments {
            hasher_le.update(c);
        }
        hasher_le.update(&256u64.to_le_bytes());
        hasher_le.update(&1u64.to_le_bytes());
        hasher_le.update(&[0x03]);
        let expected = *hasher_le.finalize().as_bytes();
        assert_eq!(txid_le, expected);
    }

    #[test]
    fn test_txid_ordering_isolation() {
        let nullifiers = &[[0x42; 32]];
        let commitments = &[[0x43; 32]];
        let epoch = 5u64;
        let txid = compute_txid(nullifiers, commitments, 40, epoch, 0x03);
        let order_key = compute_tx_ordering_key(&txid, epoch);
        assert_ne!(txid, order_key);
    }
}
