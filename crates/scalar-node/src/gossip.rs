// crates/scalar-node/src/gossip.rs
//! Gossip Protocol "Delta Sync"
//! Sesuai Concept 1 Fase 3.2.2 dan Concept 5 Layer 4
//! "Jangan sync seluruh NullifierSet — hanya sync DELTA (perubahan)"

/// Satu nullifier baru beserta bukti validitasnya
/// Sesuai Concept 1 3.2.2 ScalarGossipMessage.delta_nullifiers
pub struct DeltaNullifier {
    /// Nullifier yang akan ditambah ke NullifierSet
    /// Sesuai Concept 5 GAP-001: ini adalah N_network = BLAKE3(N_circuit)
    pub nullifier: [u8; 32],
    /// zk-STARK proof yang membuktikan transaksi valid
    /// Berisi bukti C1-C7 (commitment validity, nullifier, genesis, non-membership,
    /// value conservation, range proof, output commitment)
    /// Sesuai Concept 1 4A: proof size ~50-100 KB
    pub spend_proof: Vec<u8>,
    /// Commitment coin baru yang dihasilkan dari transaksi
    pub new_commitment: [u8; 32],
}

/// Pesan gossip yang dikirim antar node
/// Sesuai Concept 1 Fase 3.2.2 SCALAR GOSSIP: "DELTA SYNC PROTOCOL"
pub struct ScalarGossipMessage {
    /// Unix timestamp saat pesan dibuat
    pub timestamp: u64,
    /// SMT Root current sender — digunakan untuk root reconciliation
    /// Sesuai Concept 1 3.2.2 Step 3: "Setiap N detik, node broadcast SMT Root"
    pub smt_root: [u8; 32],
    /// Delta nullifiers baru yang belum dimiliki receiver
    pub delta_nullifiers: Vec<DeltaNullifier>,
    /// SPHINCS+ Signature dari sender untuk autentikasi pesan
    /// Sesuai Concept 1 Layer 0: "Signatures: SPHINCS+"
    /// Ini adalah signature atas (timestamp ‖ smt_root ‖ hash(delta_nullifiers))
    pub sender_signature: Vec<u8>,
}

impl ScalarGossipMessage {
    /// Validasi pesan gossip sebelum disebarkan ke peer lain
    /// Sesuai Concept 1 3.2.2 Step 2 - VALIDATE:
    /// a. Verify spend_proof (zk-STARK) = TRUE
    /// b. Verify nullifier ∉ local_NullifierSet
    /// c. Verify new_commitment format valid
    /// 
    /// PENTING: Implementasi lengkap membutuhkan:
    /// 1. Akses ke NullifierSet lokal
    /// 2. STARK verifier untuk spend_proof
    /// 3. SPHINCS+ verifier untuk sender_signature
    /// Return true jika pesan valid dan layak di-relay
    pub fn validate_and_relay(&self) -> bool {
        // Validasi dasar: pesan tidak boleh kosong
        if self.delta_nullifiers.is_empty() {
            return false;
        }

        // Validasi format setiap nullifier
        for delta in &self.delta_nullifiers {
            // spend_proof tidak boleh kosong (minimal ada data proof)
            if delta.spend_proof.is_empty() {
                return false;
            }
            // new_commitment tidak boleh all-zero (genesis placeholder)
            if delta.new_commitment == [0u8; 32] {
                return false;
            }
        }

        // TODO (Fase implementasi penuh):
        // 1. Verifikasi sender_signature dengan SPHINCS+:
        //    scalar_crypto::sphincs::verify(&sig, &message, &pubkey)
        // 2. Untuk setiap delta: verifikasi spend_proof via STARK verifier:
        //    scalar_stark::verifier::verify_proof(&delta.spend_proof)
        // 3. Cek setiap nullifier tidak ada di NullifierSet lokal:
        //    !local_nullifier_set.is_spent(&delta.nullifier)
        // 4. Update local NullifierSet dan SMT Root
        // 5. Relay ke peers lain

        true
    }
}