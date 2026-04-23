//! Implementasi Truth by Mathematics, not by Majority

pub struct ScalarCoin {
    pub id: [u8; 32],
    pub value_sscl: u64,          // Fixed Denomination
    pub genesis_cert: Vec<u8>,    // zk-STARK proof
    pub ownership_proof: Vec<u8>, // SPHINCS+ signature
}

#[derive(Debug, PartialEq)]
pub enum ConsensusError {
    InvalidSignature,
    DoubleSpendDetected,
    InvalidZkProof,
}

pub struct ConsensusEngine {
    spent_nullifiers: std::collections::HashSet<[u8; 32]>,
}

impl ConsensusEngine {
    pub fn new() -> Self {
        Self {
            spent_nullifiers: std::collections::HashSet::new(),
        }
    }

    /// Validasi deterministik TANPA Majority Vote
    pub fn verify_mathematical_truth(
        &mut self,
        tx_proof_valid: bool,
        signature_valid: bool,
        nullifier: [u8; 32],
    ) -> Result<(), ConsensusError> {
        if !signature_valid {
            return Err(ConsensusError::InvalidSignature);
        }
        if !tx_proof_valid {
            return Err(ConsensusError::InvalidZkProof);
        }
        if self.spent_nullifiers.contains(&nullifier) {
            return Err(ConsensusError::DoubleSpendDetected);
        }

        self.spent_nullifiers.insert(nullifier);
        Ok(())
    }
}
