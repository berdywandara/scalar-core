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

use scalar_stark::verifier::verify_proof;
use scalar_stark::air::ScalarPublicInputs;

// Helper untuk konversi byte ke u64 (Goldilocks Field compatible)
fn bytes_to_u64_le(bytes: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[0..8]);
    u64::from_le_bytes(buf)
}

impl ScalarGossipMessage {
    /// Validasi pesan gossip sebelum disebarkan ke peer lain
    /// Implementasi PR-CS-09: Integrasi zk-STARK Verifier
    pub fn validate_and_relay(&self) -> bool {
        // 1. Validasi dasar: pesan tidak boleh kosong
        if self.delta_nullifiers.is_empty() {
            return false;
        }

        // 2. Persiapkan Public Inputs untuk STARK Verifier
        // SMT Root dari pesan digunakan sebagai jangkar validasi (Anchor)
        let current_root_u64 = bytes_to_u64_le(&self.smt_root);
        
        let pub_inputs = ScalarPublicInputs {
            genesis_smt_root: 0, // Placeholder: Di produksi diisi genesis root asli
            current_nullifier_smt_root: current_root_u64,
            fee_value: 0,        // Placeholder: Diambil dari metadata transaksi jika ada
            timestamp: self.timestamp,
        };

        // 3. Loop Validasi untuk setiap Delta (Atomic Verification)
        for delta in &self.delta_nullifiers {
            // A. Cek integritas data dasar
            if delta.spend_proof.is_empty() || delta.new_commitment == [0u8; 32] {
                return false;
            }

            // B. VERIFIKASI ZK-STARK (C1-C6)
            // Memanggil verifier 32-kolom untuk membuktikan validitas tanpa privasi bocor
            if let Err(_e) = verify_proof(&delta.spend_proof, pub_inputs.clone()) {
                // Log kegagalan verifikasi (Opsional: tambahkan tracing)
                // eprintln!("STARK Verification Failed: {}", e);
                return false;
            }

            // C. TODO: Cek Double-Spend (Cek NullifierSet lokal)
            // if local_nullifier_set.contains(&delta.nullifier) { return false; }
        }

        // 4. TODO: Verifikasi SPHINCS+ Signature (Layer 0 Authentication)
        // verify_sphincs_signature(&self.sender_signature, &self.data_hash(), &sender_pubkey)

        // Jika semua bukti (proof) valid secara matematis, pesan layak di-relay
        true
    }
}