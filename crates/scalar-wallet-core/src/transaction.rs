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
        let selected_coins =
            CoinSelector::select_coins(&self.wallet_coins, amount + fee, PrivacyMode::Speed)?;
        let prover = ScalarProver::new();
        let trace = ScalarProver::build_execution_trace(&selected_coins, &[amount], fee);

        let pub_inputs = ScalarPublicInputs {
            genesis_smt_root: 0, // Akan di-inject oleh Node state
            current_nullifier_smt_root: 0,
            fee_value: fee,
            timestamp: 0,
        };

        let stark_proof = prover.generate_proof(trace, pub_inputs)?;
        let mut payload = Vec::new();
        payload.extend_from_slice(target_pubkey);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&stark_proof);

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
