// crates/scalar-nullifier/src/delta_sync.rs
//! Delta Sync Message untuk efisiensi bandwidth
//! Sesuai Concept 1 (3.2.2) dan Concept 5 Layer 4
//! "Prinsip: Jangan sync seluruh NullifierSet — hanya sync DELTA"

/// Pesan sinkronisasi delta antar node
/// Memungkinkan node untuk sync state tanpa download seluruh NullifierSet
/// Sesuai Concept 1 3.5.1 SYNCING state:
/// "Request delta dari snapshot timestamp"
/// "Apply delta nullifiers (verify setiap proof)"
/// "Verify SMT Root setelah apply"
pub struct DeltaSyncMessage {
    /// SMT Root sebelum delta diterapkan
    /// Receiver menggunakan ini untuk verifikasi konsistensi
    pub start_root: [u8; 32],
    /// SMT Root setelah semua delta diterapkan
    /// Harus cocok dengan perhitungan lokal setelah apply
    pub end_root: [u8; 32],
    /// Daftar nullifiers baru dalam delta ini
    /// Setiap nullifier disertai spend_proof untuk verifikasi mandiri
    pub nullifiers: Vec<[u8; 32]>,
    /// Proof untuk setiap nullifier (index sesuai dengan nullifiers[])
    /// Sesuai Concept 1: setiap spend harus punya valid STARK proof
    pub spend_proofs: Vec<Vec<u8>>,
    /// Timestamp mulai periode delta
    pub from_timestamp: u64,
    /// Timestamp akhir periode delta
    pub to_timestamp: u64,
}

impl DeltaSyncMessage {
    /// Buat delta sync message dari daftar nullifiers
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

    /// Jumlah nullifiers dalam delta ini
    pub fn size(&self) -> usize {
        self.nullifiers.len()
    }
}
