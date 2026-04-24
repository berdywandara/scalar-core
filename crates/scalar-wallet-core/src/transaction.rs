use scalar_crypto::sphincs::{ScalarKeyPair, sign_message};
use scalar_network::message::{ScalarMessage, MsgType};
use crate::coin_selection::{CoinSelector, PrivacyMode};
use std::collections::HashMap;

pub struct TransactionBuilder {
    wallet_coins: HashMap<u64, usize>,
    keypair: ScalarKeyPair,
}

impl TransactionBuilder {
    pub fn new(wallet_coins: HashMap<u64, usize>, keypair: ScalarKeyPair) -> Self {
        Self { wallet_coins, keypair }
    }

    pub fn build_transfer(
        &self,
        target_pubkey: &[u8],
        amount: u64,
        fee: u64
    ) -> Result<ScalarMessage, &'static str> {
        let _selected_coins = CoinSelector::select_coins(&self.wallet_coins, amount + fee, PrivacyMode::Speed)?;

        // Di produksi, instance ScalarProver akan dipanggil di sini.
        // Simulasi hasil proof bytes untuk meloloskan layer message (Mencegah cyclic prover call di wallet murni)
        let stark_proof = vec![0xBB; 1024]; 

        let mut payload = Vec::new();
        payload.extend_from_slice(target_pubkey);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&stark_proof);

        // Simulasi penandatanganan dengan SPHINCS+
        let signature = vec![0xAA; 64];

        Ok(ScalarMessage {
            msg_type: MsgType::CompactProof,
            payload,
            signature,
            transport_metadata: None,
        })
    }
}
