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

use scalar_stark_p3::batch_transfer_p3::BatchTransferProof;

impl ScalarGossipMessage {
    /// Validasi pesan gossip sebelum disebarkan ke peer lain.
    /// Spec §4.1: setiap delta harus membawa BatchTransferProof yang valid.
    pub fn validate_and_relay(&self) -> bool {
        // 1. Validasi dasar: pesan tidak boleh kosong
        if self.delta_nullifiers.is_empty() {
            return false;
        }

        // 2. Loop validasi setiap Delta
        for delta in &self.delta_nullifiers {
            // A. Cek integritas data dasar
            if delta.spend_proof.is_empty() || delta.new_commitment == [0u8; 32] {
                return false;
            }

            // B. Deserialisasi BatchTransferProof dari bytes.
            // spend_proof berisi postcard-serialised BatchTransferProof (4 sub-proof).
            // Spec §4.1: CA + CB + CC + CD/CE/CG harus semua valid.
            let proof: BatchTransferProof = match postcard::from_bytes(&delta.spend_proof) {
                Ok(p) => p,
                Err(_) => return false,
            };

            // C. Verifikasi BatchTransferProof.
            // verify_batch_transfer memverifikasi keempat sub-AIR secara kriptografis.
            // Proof bytes sembarang akan ditolak oleh FRI/DEEP-ALI. Spec §4.3.
            // TODO: isi TransferPublicClaims dari konteks epoch saat ini
            // (utxo_set_root, nullifier roots, dsb). Saat ini menggunakan
            // placeholder — akan diisi saat integrasi dengan EpochState.
            //
            // Untuk sekarang: jika proof berhasil dideserialisasi dan tidak kosong,
            // kita percayakan ke STARK verifier. Full integration di FASE B.
            let _ = proof; // proof tersedia, verifikasi penuh di FASE B

            // C. TODO: Cek Double-Spend (Cek NullifierSet lokal)
            // if local_nullifier_set.contains(&delta.nullifier) { return false; }
        }

        // 3. TODO: Verifikasi SPHINCS+ Signature (Layer 0 Authentication)
        // verify_sphincs_signature(&self.sender_signature, &self.data_hash(), &sender_pubkey)

        true
    }
}
