use crate::coin_selection::{CoinSelector, PrivacyMode};
use scalar_crypto::sphincs::{sign_message, ScalarKeyPair};
use scalar_network::message::{MsgType, ScalarMessage};
use scalar_stark::air::ScalarPublicInputs;
use scalar_stark::prover::ScalarProver;
use std::collections::HashMap;

pub struct TransactionBuilder {
    wallet_coins: HashMap<u64, usize>,
    keypair: ScalarKeyPair,
}

impl TransactionBuilder {
    pub fn new(wallet_coins: HashMap<u64, usize>, keypair: ScalarKeyPair) -> Self {
        Self {
            wallet_coins,
            keypair,
        }
    }

    pub fn build_transfer(
        &self,
        target_pubkey: &[u8],
        amount: u64,
        fee: u64,
    ) -> Result<ScalarMessage, &'static str> {
        // 1. Pilih koin UTXO yang mencukupi untuk (amount + fee)
        let selected_coins =
            CoinSelector::select_coins(&self.wallet_coins, amount + fee, PrivacyMode::Speed)?;
            
        // 2. Inisialisasi Prover 32-Kolom yang baru saja kita buat
        let prover = ScalarProver::default(); 

        // Placeholder SMT Root (Nantinya akan di-fetch dari state jaringan/Mempool)
        let current_smt_root = 0;

        // 3. Bangun Execution Trace (SEKARANG MENYERTAKAN smt_root UNTUK C4 STATE INCLUSION!)
        let trace = ScalarProver::build_execution_trace(&selected_coins, &[amount], fee, current_smt_root);

        let pub_inputs = ScalarPublicInputs {
            genesis_smt_root: 0, 
            current_nullifier_smt_root: current_smt_root,
            fee_value: fee,
            timestamp: 0, // TODO: Gunakan timestamp aktual
        };

        // 4. Hasilkan STARK Proof (Bukti bahwa C1-C6 valid tanpa membocorkan privasi)
        let stark_proof = prover.generate_proof(trace, pub_inputs)?;
        
        // 5. Rakit Payload Pesan
        // CATATAN ARSITEKTUR: Di produksi akhir, payload ini harus memuat "Network Nullifier" 
        // agar node bisa mendeteksi Double-Spend sebelum memverifikasi STARK proof yang berat.
        let mut payload = Vec::new();
        payload.extend_from_slice(target_pubkey);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&stark_proof);

        // 6. Tanda tangani payload menggunakan SPHINCS+ (Post-Quantum Signature)
        let signature =
            sign_message(&payload, &self.keypair.secret).unwrap_or_else(|_| vec![0u8; 64]);

        Ok(ScalarMessage {
            msg_type: MsgType::CompactProof,
            payload,
            signature,
            transport_metadata: None,
        })
    }
}