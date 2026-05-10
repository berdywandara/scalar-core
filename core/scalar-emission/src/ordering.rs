//! Canonical Transaction Ordering — Spec §8.5 v11.1-FINAL
//!
//! Domain separator TX_ORDER_DOMAIN = b"scalar_tx_order_v1" (OSSIFIED — spec §2.3).
//!
//! Setiap node mengurutkan semua transaksi valid dalam satu epoch berdasarkan
//! tx_ordering_key = BLAKE3(DOMAIN_TX_ORDER || tx_hash || epoch_id)
//! sebelum memasukkannya ke UTXO set SMT.
//!
//! Ini memastikan utxo_set_root identik antar semua node jujur dan
//! mencegah fork lunak akibat inkonsistensi ordering.
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.

use blake3::Hasher;

// ── Ossified constants — spec §2.3, §8.5 ─────────────────────────────────────

/// Domain separator untuk canonical transaction ordering. OSSIFIED — spec §2.3.
/// TX_ORDER_DOMAIN = b"scalar_tx_order_v1" (18 bytes).
pub const TX_ORDER_DOMAIN: &[u8] = b"scalar_tx_order_v1";

/// Panjang TX_ORDER_DOMAIN dalam bytes. Spec §2.3.
pub const TX_ORDER_DOMAIN_LEN: usize = 18;

// ── TxEntry — representasi transaksi untuk ordering ──────────────────────────

/// Representasi minimal transaksi untuk canonical ordering. Spec §8.5.
///
/// tx_hash adalah BLAKE3 hash dari seluruh transaksi (out-circuit).
/// Digunakan sebagai input untuk tx_ordering_key computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEntry {
    /// BLAKE3 hash dari transaksi lengkap. Spec §8.5.
    pub tx_hash: [u8; 32],
    /// Data transaksi (untuk pemrosesan UTXO set). Opaque di level ordering.
    pub tx_data: Vec<u8>,
}

/// Ordering key yang dihitung untuk satu transaksi. Spec §8.5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOrderingKey {
    pub tx_hash: [u8; 32],
    /// tx_ordering_key = BLAKE3(DOMAIN_TX_ORDER || tx_hash || epoch_id). Spec §8.5.
    pub ordering_key: [u8; 32],
}

// ── Core functions ────────────────────────────────────────────────────────────

/// Hitung tx_ordering_key untuk satu transaksi. Spec §8.5.
///
/// tx_ordering_key = BLAKE3(TX_ORDER_DOMAIN || tx_hash || epoch_id_le64)
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
/// Domain separator OSSIFIED: b"scalar_tx_order_v1" — spec §2.3.
pub fn compute_tx_ordering_key(tx_hash: &[u8; 32], epoch_id: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(TX_ORDER_DOMAIN);           // b"scalar_tx_order_v1"
    hasher.update(tx_hash);                   // tx_hash [u8;32]
    hasher.update(&epoch_id.to_le_bytes());   // S3: little-endian
    *hasher.finalize().as_bytes()
}

/// Urutkan transaksi secara canonical untuk epoch_id. Spec §8.5.
///
/// sort_transactions_canonical(txs, epoch_id) → Vec<TxEntry> terurut.
///
/// Algoritma:
/// 1. Hitung tx_ordering_key untuk setiap transaksi.
/// 2. Urutkan ascending berdasarkan ordering_key.
/// 3. Return Vec<TxEntry> dalam urutan canonical.
///
/// DETERMINISTIK: setiap node dengan tx set yang sama menghasilkan
/// urutan yang identik bit-ke-bit. Spec §8.5.
///
/// No collision guarantee: ordering_key = BLAKE3(domain || hash || epoch)
/// — collision resistance BLAKE3 memastikan tidak ada dua tx dengan
/// ordering_key identik untuk tx_hash yang berbeda.
pub fn sort_transactions_canonical(txs: &[TxEntry], epoch_id: u64) -> Vec<TxEntry> {
    // Hitung ordering_key untuk setiap tx
    let mut keyed: Vec<(TxOrderingKey, &TxEntry)> = txs
        .iter()
        .map(|tx| {
            let key = TxOrderingKey {
                tx_hash: tx.tx_hash,
                ordering_key: compute_tx_ordering_key(&tx.tx_hash, epoch_id),
            };
            (key, tx)
        })
        .collect();

    // Sort ascending berdasarkan ordering_key — deterministik
    keyed.sort_unstable_by_key(|(k, _)| k.ordering_key);

    // Return Vec<TxEntry> dalam urutan canonical
    keyed.into_iter().map(|(_, tx)| tx.clone()).collect()
}

/// Verifikasi bahwa TX_ORDER_DOMAIN tidak dapat diubah tanpa compile error.
/// Spec §2.3: domain separator OSSIFIED.
pub const fn tx_order_domain_ossified() -> &'static [u8] {
    TX_ORDER_DOMAIN
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(seed: u8) -> TxEntry {
        TxEntry {
            tx_hash: [seed; 32],
            tx_data: vec![seed, seed, seed],
        }
    }

    fn make_tx_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ── unit_test_tx_ordering_key_deterministic ───────────────────────────────

    #[test]
    fn unit_test_tx_ordering_key_deterministic() {
        // tx_hash sama + epoch_id sama → ordering_key sama. Spec §8.5.
        let tx_hash = make_tx_hash(0x42);
        let k1 = compute_tx_ordering_key(&tx_hash, 10);
        let k2 = compute_tx_ordering_key(&tx_hash, 10);
        assert_eq!(k1, k2,
            "ordering_key harus deterministik untuk input yang sama");
    }

    #[test]
    fn unit_test_tx_ordering_key_different_epoch() {
        // epoch_id berbeda → ordering_key berbeda. Spec §8.5.
        let tx_hash = make_tx_hash(0x42);
        let k1 = compute_tx_ordering_key(&tx_hash, 10);
        let k2 = compute_tx_ordering_key(&tx_hash, 11);
        assert_ne!(k1, k2,
            "ordering_key harus berbeda untuk epoch berbeda");
    }

    #[test]
    fn unit_test_tx_ordering_key_different_tx() {
        // tx_hash berbeda → ordering_key berbeda. Spec §8.5.
        let k1 = compute_tx_ordering_key(&make_tx_hash(0x01), 10);
        let k2 = compute_tx_ordering_key(&make_tx_hash(0x02), 10);
        assert_ne!(k1, k2,
            "ordering_key harus berbeda untuk tx_hash berbeda");
    }

    #[test]
    fn unit_test_tx_ordering_key_nonzero() {
        // ordering_key tidak boleh zero. Spec §8.5.
        let k = compute_tx_ordering_key(&make_tx_hash(0x00), 0);
        assert_ne!(k, [0u8; 32],
            "ordering_key tidak boleh zero");
    }

    // ── test_canonical_sort_stable ────────────────────────────────────────────

    #[test]
    fn test_canonical_sort_stable() {
        // Urutan input berbeda → output urutan selalu identik. Spec §8.5.
        let txs_asc = vec![make_tx(0x01), make_tx(0x02), make_tx(0x03)];
        let txs_desc = vec![make_tx(0x03), make_tx(0x02), make_tx(0x01)];
        let txs_shuffled = vec![make_tx(0x02), make_tx(0x01), make_tx(0x03)];

        let sorted_asc = sort_transactions_canonical(&txs_asc, 5);
        let sorted_desc = sort_transactions_canonical(&txs_desc, 5);
        let sorted_shuffled = sort_transactions_canonical(&txs_shuffled, 5);

        assert_eq!(sorted_asc, sorted_desc,
            "urutan desc harus menghasilkan output canonical yang sama");
        assert_eq!(sorted_asc, sorted_shuffled,
            "urutan shuffled harus menghasilkan output canonical yang sama");
    }

    // ── integration_test_utxo_root_identical ─────────────────────────────────

    #[test]
    fn integration_test_utxo_root_identical() {
        // Dua node dengan tx set sama → urutan canonical identik. Spec §8.5.
        // Simulasi: "node A" dan "node B" menerima tx dalam urutan berbeda.
        let tx_set = vec![
            make_tx(0xAA), make_tx(0xBB), make_tx(0xCC),
            make_tx(0xDD), make_tx(0xEE),
        ];

        // Node A: tx diterima dalam urutan 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
        let node_a_input = tx_set.clone();

        // Node B: tx diterima dalam urutan berbeda
        let node_b_input = vec![
            make_tx(0xEE), make_tx(0xCC), make_tx(0xAA),
            make_tx(0xDD), make_tx(0xBB),
        ];

        let sorted_a = sort_transactions_canonical(&node_a_input, 7);
        let sorted_b = sort_transactions_canonical(&node_b_input, 7);

        assert_eq!(sorted_a, sorted_b,
            "Dua node dengan tx set sama harus menghasilkan canonical order identik — spec §8.5");

        // Verifikasi: BLAKE3(sorted_a) == BLAKE3(sorted_b) sebagai proxy utxo_set_root
        let hash_a = blake3_tx_list_hash(&sorted_a);
        let hash_b = blake3_tx_list_hash(&sorted_b);
        assert_eq!(hash_a, hash_b,
            "utxo_set_root proxy harus identik antar node");
    }

    // Helper: hitung hash dari ordered tx list sebagai proxy utxo_set_root
    fn blake3_tx_list_hash(txs: &[TxEntry]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        for tx in txs {
            hasher.update(&tx.tx_hash);
        }
        *hasher.finalize().as_bytes()
    }

    // ── test_domain_separator_ossified ───────────────────────────────────────

    #[test]
    fn test_domain_separator_ossified() {
        // TX_ORDER_DOMAIN = b"scalar_tx_order_v1". OSSIFIED — spec §2.3.
        assert_eq!(TX_ORDER_DOMAIN, b"scalar_tx_order_v1");
        assert_eq!(TX_ORDER_DOMAIN_LEN, 18usize);
        assert_eq!(TX_ORDER_DOMAIN.len(), TX_ORDER_DOMAIN_LEN);
    }

    #[test]
    fn test_domain_separator_via_const_fn() {
        // tx_order_domain_ossified() mengembalikan domain yang sama.
        assert_eq!(tx_order_domain_ossified(), TX_ORDER_DOMAIN);
    }

    // ── prop_test_ordering_no_collision ──────────────────────────────────────

    #[test]
    fn prop_test_ordering_no_collision() {
        // 256 tx berbeda → semua ordering_key berbeda. Spec §8.5.
        let epoch_id = 42u64;
        let mut keys: Vec<[u8; 32]> = (0u8..=255)
            .map(|seed| compute_tx_ordering_key(&make_tx_hash(seed), epoch_id))
            .collect();

        let original_len = keys.len();
        keys.sort_unstable();
        keys.dedup();

        assert_eq!(keys.len(), original_len,
            "Tidak ada dua tx dengan ordering_key yang sama — prop_test_ordering_no_collision");
    }

    // ── test_empty_tx_list ────────────────────────────────────────────────────

    #[test]
    fn test_empty_tx_list_returns_empty() {
        // Tx list kosong → sorted list kosong. Spec §8.5.
        let result = sort_transactions_canonical(&[], 1);
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_tx_unchanged() {
        // Single tx → urutan tidak berubah. Spec §8.5.
        let txs = vec![make_tx(0x42)];
        let sorted = sort_transactions_canonical(&txs, 1);
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].tx_hash, make_tx_hash(0x42));
    }

    // ── test_ordering_key_uses_domain_separator ───────────────────────────────

    #[test]
    fn test_ordering_key_uses_domain_separator() {
        // Verifikasi bahwa domain separator digunakan dalam hash.
        // Tanpa domain separator, hash akan berbeda.
        let tx_hash = make_tx_hash(0x42);
        let epoch_id = 5u64;

        // Hitung dengan domain separator (canonical)
        let with_domain = compute_tx_ordering_key(&tx_hash, epoch_id);

        // Hitung tanpa domain separator (manual)
        let mut hasher = Hasher::new();
        hasher.update(&tx_hash);
        hasher.update(&epoch_id.to_le_bytes());
        let without_domain = *hasher.finalize().as_bytes();

        assert_ne!(with_domain, without_domain,
            "Domain separator harus digunakan dalam ordering_key computation");
    }

    // ── test_ordering_epoch_isolation ─────────────────────────────────────────

    #[test]
    fn test_ordering_epoch_isolation() {
        // Ordering berbeda per epoch — tx yang sama punya key berbeda di epoch berbeda.
        // Spec §8.5: tx_ordering_key bergantung pada epoch_id.
        let txs = vec![make_tx(0x01), make_tx(0x02), make_tx(0x03)];

        let sorted_epoch_1 = sort_transactions_canonical(&txs, 1);
        let sorted_epoch_2 = sort_transactions_canonical(&txs, 2);

        // Urutan tx bisa berbeda antar epoch karena ordering_key berbeda
        // (tidak selalu berbeda tapi ordering_key pasti berbeda)
        let key_1_0 = compute_tx_ordering_key(&txs[0].tx_hash, 1);
        let key_2_0 = compute_tx_ordering_key(&txs[0].tx_hash, 2);
        assert_ne!(key_1_0, key_2_0,
            "ordering_key harus berbeda antar epoch untuk tx yang sama");

        // Masing-masing epoch menghasilkan urutan yang konsisten dalam dirinya sendiri
        let sorted_epoch_1_again = sort_transactions_canonical(&txs, 1);
        assert_eq!(sorted_epoch_1, sorted_epoch_1_again,
            "Ordering harus deterministik dalam epoch yang sama");
        let _ = sorted_epoch_2; // suppress unused warning
    }

    // ── test_little_endian_epoch_id ───────────────────────────────────────────

    #[test]
    fn test_little_endian_epoch_id() {
        // S3: epoch_id harus little-endian dalam hash. Spec §8.2 S3.
        let tx_hash = make_tx_hash(0x42);

        // Manual computation dengan le_bytes
        let mut hasher_le = Hasher::new();
        hasher_le.update(TX_ORDER_DOMAIN);
        hasher_le.update(&tx_hash);
        hasher_le.update(&10u64.to_le_bytes());
        let expected_le = *hasher_le.finalize().as_bytes();

        // Manual computation dengan be_bytes (harus berbeda)
        let mut hasher_be = Hasher::new();
        hasher_be.update(TX_ORDER_DOMAIN);
        hasher_be.update(&tx_hash);
        hasher_be.update(&10u64.to_be_bytes());
        let expected_be = *hasher_be.finalize().as_bytes();

        let actual = compute_tx_ordering_key(&tx_hash, 10);
        assert_eq!(actual, expected_le,
            "epoch_id harus little-endian (S3)");
        assert_ne!(actual, expected_be,
            "big-endian harus berbeda dari canonical");
    }
}
