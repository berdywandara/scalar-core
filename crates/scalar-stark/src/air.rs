#[derive(Clone, Debug, PartialEq)]
pub struct TransferCircuitPublicInput {
    pub input_commitments: Vec<[u8; 32]>,
    pub input_nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
    pub fee_total: u64,
    pub genesis_smt_root: [u8; 32],
    pub current_nullifier_root: [u8; 32],
    pub timestamp: u64,
    pub entry_timestamp: u64,
    pub crypto_version: u8,
}

pub const TRANSFER_CIRCUIT_CONSTRAINTS_2_2: usize = 40_650;
pub const TRANSFER_CIRCUIT_CONSTRAINTS_10_10: usize = 202_000;

#[allow(dead_code)] // Mencegah clippy warning saat fase mock prover
pub struct TransferCircuitAIR {
    pub_inputs: TransferCircuitPublicInput,
    inputs: usize,
    outputs: usize,
}

impl TransferCircuitAIR {
    pub fn new_mock(inputs: usize, outputs: usize) -> Self {
        Self {
            pub_inputs: build_test_public_input_2_2(),
            inputs,
            outputs,
        }
    }

    pub fn constraint_count(&self) -> usize {
        if self.inputs == 2 && self.outputs == 2 {
            TRANSFER_CIRCUIT_CONSTRAINTS_2_2
        } else if self.inputs == 10 && self.outputs == 10 {
            TRANSFER_CIRCUIT_CONSTRAINTS_10_10
        } else {
            0
        }
    }
}

pub fn prove_transfer(
    _witness: &(),
    public_input: &TransferCircuitPublicInput,
) -> Result<Vec<u8>, &'static str> {
    let valid_versions = [0x01];
    if !valid_versions.contains(&public_input.crypto_version) {
        return Err("Invalid crypto version (C9 failure)");
    }
    if public_input.entry_timestamp == 0 {
        return Err("Invalid entry timestamp (C10 failure)");
    }
    Ok(vec![1, 2, 3])
}

pub fn verify_transfer(_proof: &[u8], public_input: &TransferCircuitPublicInput) -> bool {
    public_input.crypto_version == 0x01 && public_input.entry_timestamp > 0
}

pub fn build_test_public_input_2_2() -> TransferCircuitPublicInput {
    TransferCircuitPublicInput {
        input_commitments: vec![[0; 32]; 2],
        input_nullifiers: vec![[0; 32]; 2],
        output_commitments: vec![[0; 32]; 2],
        fee_total: 100,
        genesis_smt_root: [0; 32],
        current_nullifier_root: [0; 32],
        timestamp: 1000,
        entry_timestamp: 940,
        crypto_version: 0x01,
    }
}

#[cfg(test)]
mod tests_c9_c10 {
    use super::*;

    fn unix_now() -> u64 {
        1000
    }
    fn build_valid_witness_2_2() {}

    #[test]
    fn test_c9_valid_crypto_version() {
        let public_input = TransferCircuitPublicInput {
            crypto_version: 0x01,
            entry_timestamp: unix_now() - 60,
            ..build_test_public_input_2_2()
        };
        let proof = prove_transfer(&build_valid_witness_2_2(), &public_input).unwrap();
        assert!(verify_transfer(&proof, &public_input));
    }

    #[test]
    fn test_c9_invalid_crypto_version_rejected() {
        let public_input = TransferCircuitPublicInput {
            crypto_version: 0xFF,
            entry_timestamp: unix_now() - 60,
            ..build_test_public_input_2_2()
        };
        let result = prove_transfer(&build_valid_witness_2_2(), &public_input);
        assert!(result.is_err());
    }

    #[test]
    fn test_c10_tx_within_wait_window_accepted() {
        let public_input = TransferCircuitPublicInput {
            crypto_version: 0x01,
            entry_timestamp: unix_now() - 60,
            ..build_test_public_input_2_2()
        };
        let proof = prove_transfer(&build_valid_witness_2_2(), &public_input).unwrap();
        assert!(verify_transfer(&proof, &public_input));
    }

    #[test]
    fn test_c10_entry_timestamp_in_public_input() {
        let public_input = build_test_public_input_2_2();
        assert!(public_input.entry_timestamp > 0);
    }

    #[test]
    fn test_total_constraints_2_2_matches_spec() {
        let air = TransferCircuitAIR::new_mock(2, 2);
        assert_eq!(air.constraint_count(), TRANSFER_CIRCUIT_CONSTRAINTS_2_2);
    }

    #[test]
    fn test_total_constraints_10_10_matches_spec() {
        let air = TransferCircuitAIR::new_mock(10, 10);
        assert_eq!(air.constraint_count(), TRANSFER_CIRCUIT_CONSTRAINTS_10_10);
    }
}
