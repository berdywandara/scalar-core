// crates/scalar-nullifier/src/delta_sync.rs
//! Delta Sync Message for effillensi bandwidth
//! per concept 1 (3.2.2) and Concept 5 Layer 4
//! "Prinsip: Jangan sync seluruh NullifierSet — only sync DELTA"

/// message synchronization delta antar node
/// Memungkinkan node for sync state tanpa download seluruh NullifierSet
/// per concept 1 3.5.1 SYNCING state:
/// "Request delta from snapshot timestamp"
/// "Apply delta nullifiers (verify each proof)"
/// "Verify SMT root after apply"
pub struct DeltaSyncMessage {
    /// SMT root before delta atterapkan
    /// Receiver using this for verification konsistensi
    pub start_root: [u8; 32],
    /// SMT root after all delta atterapkan
    /// Harus matches perhitungan lokal after apply
    pub end_root: [u8; 32],
    /// Daftar nullifiers new in delta this
    /// each nullifier atsertai spend_proof for verification independent
    pub nullifiers: Vec<[u8; 32]>,
    /// Proof for each nullifier (index in accorandce with nullifiers[])
    /// per concept 1: each spend harus have valid STARK proof
    pub spend_proofs: Vec<Vec<u8>>,
    /// Timestamp start period delta
    pub from_timestamp: u64,
    /// Timestamp akhir period delta
    pub to_timestamp: u64,
}

impl DeltaSyncMessage {
    /// Buat delta sync message from daftar nullifiers
    pub fn new(
        start_root: [u8; 32],
        end_root: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        spend_proofs: Vec<Vec<u8>>,
        from_timestamp: u64,
        to_timestamp: u64,
    ) -> Self {
        assert_eq!(
            nullifiers.len(),
            spend_proofs.len(),
            "Setiap nullifier harus punya spend_proof"
        );
        Self {
            start_root,
            end_root,
            nullifiers,
            spend_proofs,
            from_timestamp,
            to_timestamp,
        }
    }

    /// Jumlah nullifiers in delta this
    pub fn size(&self) -> usize {
        self.nullifiers.len()
    }
}
