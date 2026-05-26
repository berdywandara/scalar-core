//! UTXO Set Accumulator — Snapshot Management & Node Sync Protocol
//!
//! NOTE: This is a sequential-hash accumulator, NOT a true Sparse Merkle Tree.
//! Named 'Accumulator' to reflect implementation reality ("Truth by Mathematics").
//! Wajib diganti dengan IMT-based EpochSMT sebelum testnet (utang teknis D3).
//! Spec §8.5, §16.1, §3.1 Scalar_Optimalisasi_PraGenesis.
//!
//! Spec §8.5 v11.1 + v11.1-FINAL, §16.1.
//!
//! Setiap node memelihara UtxoSetAccumulator yang diperbarui setiap kali output baru
//! tercipta. Snapshot utxo_set_root diambil pada akhir epoch k setelah semua
//! transaksi epoch k diproses secara deterministik (canonical ordering §8.5).
//!
//! Root ini disimpan sebagai bagian dari state yang dikomit dan digunakan
//! sebagai public input utxo_set_root untuk transaksi epoch k+1.
//!
//! Sinkronisasi node baru:
//!   1. Download utxo_set_root terbaru dari peers
//!   2. Verifikasi terhadap network_health_digest di manifest terbaru
//!   3. Atau rebuild dari genesis menggunakan canonical ordering
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.

use crate::ordering::{sort_transactions_canonical, TxEntry};
use blake3::Hasher;

// ── Constants — spec §8.5, §16.1 ─────────────────────────────────────────────

// DOMAIN_UTXO_SMT is now OSSIFIED in scalar_crypto::domain (D.1 decision, FASE D).
// Re-exported from scalar_crypto::domain for backward compatibility.
pub use scalar_crypto::domain::DOMAIN_UTXO_SMT;

/// Epoch ID awal (genesis). Spec §8.5.
pub const GENESIS_EPOCH_ID: u64 = 0;

// ── UtxoEntry — representasi UTXO dalam SMT ───────────────────────────────────

/// Representasi satu UTXO dalam SMT. Spec §3.4, §8.5.
///
/// commitment = Poseidon2(DOMAIN_COMMITMENT_V2 || value || owner_pubkey ||
///                        secret || salt)
/// Di layer ini hanya menyimpan commitment (opaque bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    /// Commitment kriptografis UTXO (Poseidon2 hash, 32 bytes). Spec §3.4.
    pub commitment: [u8; 32],
    /// Epoch saat UTXO dibuat. Spec §8.5.
    pub created_epoch: u64,
}

// ── UtxoSetState — state yang disimpan per epoch ──────────────────────────────

/// State UTXO set yang dikomit pada akhir setiap epoch. Spec §16.1.
///
/// Disimpan sebagai bagian dari NodeState dan digunakan sebagai
/// public input untuk transaksi epoch berikutnya.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoSetState {
    /// Root SMT dari semua UTXO yang pernah dibuat s.d. akhir epoch ini.
    pub utxo_set_root: [u8; 32],
    /// Epoch ID saat snapshot diambil. Spec §8.5.
    pub snapshot_epoch: u64,
    /// Jumlah total UTXO dalam set. Spec §16.1.
    pub utxo_count: u64,
}

impl UtxoSetState {
    /// Genesis state — root kosong, epoch 0. Spec §8.5.
    pub fn genesis() -> Self {
        Self {
            utxo_set_root: [0u8; 32],
            snapshot_epoch: GENESIS_EPOCH_ID,
            utxo_count: 0,
        }
    }

    /// Verifikasi bahwa root ini berasal dari epoch yang benar.
    pub fn is_valid_for_epoch(&self, epoch_k: u64) -> bool {
        // utxo_set_root untuk transaksi epoch k berasal dari snapshot epoch k-1
        self.snapshot_epoch == epoch_k.saturating_sub(1)
            || (epoch_k == 0 && self.snapshot_epoch == 0)
    }
}

// ── UtxoSetAccumulator — SMT untuk semua UTXO ────────────────────────────────────────

/// UTXO Set Sparse Merkle Tree. Spec §16.1, §8.5.
///
/// Diperbarui setiap kali output baru tercipta.
/// Root diambil snapshot pada akhir epoch setelah canonical ordering.
///
/// Implementasi ini adalah simplified SMT menggunakan BLAKE3 sebagai
/// hash function untuk node internal (out-circuit). Produksi menggunakan
/// Poseidon2 in-circuit untuk ZK proof; BLAKE3 untuk state management.
pub struct UtxoSetAccumulator {
    /// Semua UTXO yang pernah dibuat, dalam urutan insertion.
    utxos: Vec<UtxoEntry>,
    /// Root SMT terkini (dihitung ulang setelah setiap batch update).
    current_root: [u8; 32],
    /// Epoch terakhir yang diproses.
    current_epoch: u64,
}

impl UtxoSetAccumulator {
    /// Buat SMT baru dari genesis. Spec §8.5.
    pub fn new() -> Self {
        Self {
            utxos: Vec::new(),
            current_root: [0u8; 32],
            current_epoch: GENESIS_EPOCH_ID,
        }
    }

    /// Insert UTXO baru ke dalam SMT. Spec §8.5.
    ///
    /// Dipanggil setiap kali output baru tercipta dari transaksi yang valid.
    pub fn insert_utxo(&mut self, commitment: [u8; 32], epoch: u64) {
        self.utxos.push(UtxoEntry {
            commitment,
            created_epoch: epoch,
        });
        // Root diperbarui setelah insert
        self.current_root = self.compute_root();
    }

    /// Proses batch transaksi dengan canonical ordering. Spec §8.5.
    ///
    /// Sebelum memasukkan output ke SMT, transaksi diurutkan menggunakan
    /// sort_transactions_canonical(). Ini memastikan determinisme root.
    ///
    /// `txs`: transaksi valid yang diterima selama epoch_id.
    /// `extract_outputs`: fungsi untuk mengekstrak output commitments dari tx.
    pub fn process_epoch_transactions(&mut self, txs: &[TxEntry], epoch_id: u64) {
        // Canonical ordering sebelum pemrosesan — spec §8.5
        let ordered_txs = sort_transactions_canonical(txs, epoch_id);

        // Insert semua output dari setiap transaksi (dalam urutan canonical)
        for tx in &ordered_txs {
            // Simulasi: setiap tx_hash diperlakukan sebagai satu output commitment
            // Production: ekstrak output_commitments[] dari STARK proof
            self.insert_utxo(tx.tx_hash, epoch_id);
        }

        self.current_epoch = epoch_id;
    }

    /// Ambil snapshot root pada akhir epoch. Spec §8.5.
    ///
    /// "Root diambil pada akhir epoch setelah semua transaksi diproses
    /// secara deterministik menggunakan canonical transaction ordering."
    ///
    /// Root ini digunakan sebagai utxo_set_root untuk transaksi epoch berikutnya.
    pub fn take_snapshot(&self, epoch_id: u64) -> UtxoSetState {
        UtxoSetState {
            utxo_set_root: self.current_root,
            snapshot_epoch: epoch_id,
            utxo_count: self.utxos.len() as u64,
        }
    }

    /// Root SMT terkini. Spec §8.5.
    pub fn root(&self) -> [u8; 32] {
        self.current_root
    }

    /// Jumlah UTXO dalam set.
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    /// Hitung root SMT dari semua UTXO.
    ///
    /// Implementasi: BLAKE3(DOMAIN_UTXO_SMT || commitment_0 || commitment_1 || ...)
    /// Determinisme dijamin karena insertion order = canonical ordering.
    ///
    /// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
    /// PRE-GENESIS TEMPORARY: Sequential hash, witness O(n).
    /// Wajib diganti dengan IMT-based EpochSMT sebelum testnet
    /// dengan full client proving. Lihat §3.1 Scalar_Optimalisasi_PraGenesis.
    /// TRACKING: D3 decision — docs/decisions/DESIGN_DECISIONS_PENDING.md
    fn compute_root(&self) -> [u8; 32] {
        if self.utxos.is_empty() {
            return [0u8; 32];
        }
        let mut hasher = Hasher::new();
        hasher.update(DOMAIN_UTXO_SMT);
        for utxo in &self.utxos {
            hasher.update(&utxo.commitment);
            hasher.update(&utxo.created_epoch.to_le_bytes()); // S3: LE
        }
        *hasher.finalize().as_bytes()
    }
}

impl Default for UtxoSetAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

// ── SyncVerificationResult — hasil verifikasi root saat sync ──────────────────

/// Hasil verifikasi utxo_set_root saat node sync. Spec §8.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncVerificationResult {
    /// Root valid — cocok dengan network_health_digest di manifest. Spec §8.5.
    Valid,
    /// Root tidak cocok dengan network_health_digest. Spec §8.5.
    RootMismatch {
        local_root: [u8; 32],
        expected_root: [u8; 32],
    },
    /// Node tidak memiliki manifest untuk verifikasi — perlu sync dulu.
    NoManifestAvailable,
}

/// Verifikasi utxo_set_root dari peer terhadap network_health_digest. Spec §8.5.
///
/// "Keabsahan root diverifikasi dengan mencocokkan hash terhadap nilai yang
/// tercantum dalam network_health_digest di manifest terkomit."
///
/// `peer_root`: root yang didownload dari peer.
/// `expected_root`: root yang tersimpan dalam network_health_digest manifest.
pub fn verify_utxo_root_against_manifest(
    peer_root: &[u8; 32],
    expected_root: &[u8; 32],
) -> SyncVerificationResult {
    if peer_root == expected_root {
        SyncVerificationResult::Valid
    } else {
        SyncVerificationResult::RootMismatch {
            local_root: *peer_root,
            expected_root: *expected_root,
        }
    }
}

/// Ekstrak expected utxo_set_root dari network_health_digest. Spec §8.5.
///
/// network_health_digest = BLAKE3(epoch_k || anchor_count || total_weight_fp)
/// Root diverifikasi terhadap majority peers yang menyepakati manifest yang sama.
///
/// Dalam implementasi ini: expected_root diambil langsung dari manifest field.
/// Production: cross-reference dengan multiple peers.
pub fn extract_expected_root_from_manifest(
    network_health_digest: &[u8; 32],
    epoch_id: u64,
) -> [u8; 32] {
    // Derive expected root context dari network_health_digest + epoch_id
    // Production: root tersimpan eksplisit dalam manifest state
    // Implementasi ini: gunakan BLAKE3(digest || epoch_id) sebagai proxy
    let mut hasher = Hasher::new();
    hasher.update(network_health_digest);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordering::TxEntry;

    fn make_commitment(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn make_tx(seed: u8) -> TxEntry {
        TxEntry {
            tx_hash: [seed; 32],
            tx_data: vec![seed],
        }
    }

    // ── test_utxo_root_snapshot_timing ────────────────────────────────────────

    #[test]
    fn test_utxo_root_snapshot_timing() {
        // Snapshot diambil SETELAH semua tx epoch diproses. Spec §8.5.
        let mut smt = UtxoSetAccumulator::new();
        let txs = vec![make_tx(0x01), make_tx(0x02), make_tx(0x03)];

        // Sebelum processing — root masih zero
        let root_before = smt.root();
        assert_eq!(root_before, [0u8; 32]);

        // Process epoch 1
        smt.process_epoch_transactions(&txs, 1);

        // Setelah processing — root berubah
        let root_after = smt.root();
        assert_ne!(
            root_after, [0u8; 32],
            "Root harus berubah setelah transaksi diproses"
        );

        // Snapshot diambil setelah processing
        let snapshot = smt.take_snapshot(1);
        assert_eq!(
            snapshot.utxo_set_root, root_after,
            "Snapshot root harus sama dengan root setelah processing"
        );
        assert_eq!(snapshot.snapshot_epoch, 1);
        assert_eq!(snapshot.utxo_count, 3);
    }

    // ── test_utxo_root_rebuild_from_genesis ───────────────────────────────────

    #[test]
    fn test_utxo_root_rebuild_from_genesis() {
        // Rebuild dari genesis → root identik bit-ke-bit. Spec §8.5.
        let txs = vec![make_tx(0xAA), make_tx(0xBB), make_tx(0xCC)];

        // Node 1: proses dari genesis
        let mut smt1 = UtxoSetAccumulator::new();
        smt1.process_epoch_transactions(&txs, 5);
        let root1 = smt1.root();

        // Node 2: proses dari genesis dengan tx set sama (urutan berbeda)
        let txs_reordered = vec![make_tx(0xCC), make_tx(0xAA), make_tx(0xBB)];
        let mut smt2 = UtxoSetAccumulator::new();
        smt2.process_epoch_transactions(&txs_reordered, 5);
        let root2 = smt2.root();

        assert_eq!(
            root1, root2,
            "Root harus identik bit-ke-bit meski urutan penerimaan tx berbeda — spec §8.5"
        );
    }

    // ── test_utxo_root_verification_vs_manifest ───────────────────────────────

    #[test]
    fn test_utxo_root_verification_vs_manifest() {
        // Root diverifikasi terhadap network_health_digest. Spec §8.5.
        let peer_root = [0x42u8; 32];
        let expected_root = [0x42u8; 32]; // sama = valid

        let result = verify_utxo_root_against_manifest(&peer_root, &expected_root);
        assert_eq!(result, SyncVerificationResult::Valid);
    }

    #[test]
    fn test_utxo_root_verification_mismatch() {
        // Root berbeda → mismatch. Spec §8.5.
        let peer_root = [0x42u8; 32];
        let expected_root = [0xFFu8; 32]; // berbeda = mismatch

        let result = verify_utxo_root_against_manifest(&peer_root, &expected_root);
        assert!(matches!(
            result,
            SyncVerificationResult::RootMismatch { .. }
        ));
    }

    // ── integration_test_new_node_sync ────────────────────────────────────────

    #[test]
    fn integration_test_new_node_sync() {
        // Node baru sinkronisasi → root identik dengan node lama. Spec §8.5.
        let epoch_id = 3u64;
        let txs = vec![
            make_tx(0x01),
            make_tx(0x02),
            make_tx(0x03),
            make_tx(0x04),
            make_tx(0x05),
        ];

        // "Node lama" yang sudah sinkron
        let mut old_node = UtxoSetAccumulator::new();
        old_node.process_epoch_transactions(&txs, epoch_id);
        let old_root = old_node.root();

        // "Node baru" yang rebuild dari genesis
        // Menerima tx dalam urutan yang berbeda (simulasi gossip)
        let txs_gossip_order = vec![
            make_tx(0x05),
            make_tx(0x01),
            make_tx(0x04),
            make_tx(0x02),
            make_tx(0x03),
        ];
        let mut new_node = UtxoSetAccumulator::new();
        new_node.process_epoch_transactions(&txs_gossip_order, epoch_id);
        let new_root = new_node.root();

        assert_eq!(
            old_root, new_root,
            "Node baru setelah sync harus menghasilkan root identik — spec §8.5"
        );

        // Verifikasi root terhadap manifest (simulasi)
        let result = verify_utxo_root_against_manifest(&new_root, &old_root);
        assert_eq!(result, SyncVerificationResult::Valid);
    }

    // ── test_utxo_state_valid_for_epoch ───────────────────────────────────────

    #[test]
    fn test_utxo_state_valid_for_epoch() {
        // utxo_set_root untuk epoch k berasal dari snapshot epoch k-1. Spec §4.2.
        let state = UtxoSetState {
            utxo_set_root: [0x42u8; 32],
            snapshot_epoch: 4,
            utxo_count: 10,
        };
        // Valid untuk epoch 5 (snapshot dari epoch 4 = k-1)
        assert!(
            state.is_valid_for_epoch(5),
            "Snapshot epoch 4 valid untuk transaksi epoch 5"
        );
        // Tidak valid untuk epoch 4 (bukan k-1)
        assert!(
            !state.is_valid_for_epoch(4),
            "Snapshot epoch 4 tidak valid untuk transaksi epoch 4"
        );
    }

    #[test]
    fn test_genesis_state() {
        // Genesis state: root zero, epoch 0. Spec §8.5.
        let state = UtxoSetState::genesis();
        assert_eq!(state.utxo_set_root, [0u8; 32]);
        assert_eq!(state.snapshot_epoch, 0);
        assert_eq!(state.utxo_count, 0);
    }

    // ── test_insert_utxo_updates_root ────────────────────────────────────────

    #[test]
    fn test_insert_utxo_updates_root() {
        // Setiap insert memperbarui root. Spec §8.5.
        let mut smt = UtxoSetAccumulator::new();
        assert_eq!(smt.root(), [0u8; 32]);

        smt.insert_utxo(make_commitment(0x01), 1);
        let root_after_1 = smt.root();
        assert_ne!(root_after_1, [0u8; 32]);

        smt.insert_utxo(make_commitment(0x02), 1);
        let root_after_2 = smt.root();
        assert_ne!(
            root_after_2, root_after_1,
            "Root harus berubah setelah setiap insert"
        );
    }

    // ── test_domain_separator_utxo ───────────────────────────────────────────

    #[test]
    fn test_domain_separator_utxo_ossified() {
        // DOMAIN_UTXO_SMT = b"scalar_utxo_set". NON-OSSIFIED (audit K9-02).
        assert_eq!(DOMAIN_UTXO_SMT, b"scalar_utxo_set");
    }

    // ── test_root_deterministic_same_utxos ───────────────────────────────────

    #[test]
    fn test_root_deterministic_same_utxos() {
        // Dua SMT dengan UTXO yang sama → root identik. Spec §8.5.
        let mut smt1 = UtxoSetAccumulator::new();
        let mut smt2 = UtxoSetAccumulator::new();

        for seed in [0x01u8, 0x02, 0x03] {
            smt1.insert_utxo(make_commitment(seed), 1);
            smt2.insert_utxo(make_commitment(seed), 1);
        }

        assert_eq!(
            smt1.root(),
            smt2.root(),
            "SMT dengan UTXO identik harus menghasilkan root yang sama"
        );
    }

    // ── test_snapshot_multiple_epochs ────────────────────────────────────────

    #[test]
    fn test_snapshot_multiple_epochs() {
        // Snapshot per epoch terakumulasi dengan benar. Spec §8.5.
        let mut smt = UtxoSetAccumulator::new();

        smt.process_epoch_transactions(&[make_tx(0x01), make_tx(0x02)], 1);
        let snap1 = smt.take_snapshot(1);

        smt.process_epoch_transactions(&[make_tx(0x03), make_tx(0x04)], 2);
        let snap2 = smt.take_snapshot(2);

        // Snapshot epoch 2 harus punya lebih banyak UTXO dan root berbeda
        assert_ne!(
            snap1.utxo_set_root, snap2.utxo_set_root,
            "Root harus berbeda setelah epoch baru diproses"
        );
        assert!(
            snap2.utxo_count > snap1.utxo_count,
            "Epoch 2 harus punya lebih banyak UTXO"
        );

        // snap2 valid untuk epoch 3, snap1 valid untuk epoch 2
        assert!(snap2.is_valid_for_epoch(3));
        assert!(snap1.is_valid_for_epoch(2));
    }
}
