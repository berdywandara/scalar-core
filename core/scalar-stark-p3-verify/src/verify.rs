//! Cross-verification entry points. Spec §15.3, A-R7.
//!
//! verify_transfer_independent(): verifies a Transfer CD/CE/CG proof generated
//!   by scalar-stark-p3 using independently re-implemented TransferAirV2.
//!
//! verify_mint_independent(): verifies a MintLinear proof using MintAirV2.
//!
//! Spec §15.3: "dua implementasi independen harus menghasilkan proof yang
//! saling dapat diverifikasi."

use p3_uni_stark::{verify, Proof};
use postcard;

use scalar_stark_p3::{
    config::{build_scalar_config, ScalarStarkConfig},
    mint_air_p3::{build_mint_linear_pv, MintLinearPublicInputs, MINT_LINEAR_WIDTH},
    transfer_air_p3::TRANSFER_TRACE_WIDTH,
    transfer_public_inputs::TransferPublicInputsP3,
};

use crate::mint_air_v2::{MintAirV2, MINT_TRACE_WIDTH_V2};
use crate::transfer_air_v2::{TransferAirV2, TRANSFER_TRACE_WIDTH_V2};

/// Error type for independent verification. Spec §15.3.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IndependentVerifyError {
    #[error("Deserialization failed: {0}")]
    Deserialize(String),

    #[error(
        "Independent verifier (V2) rejected proof: {reason}. \
         Indicates AIR constraint divergence between implementations."
    )]
    VerificationFailed { reason: String },

    #[error("Trace width mismatch: primary={primary}, v2={v2}")]
    TraceWidthMismatch { primary: usize, v2: usize },
}

/// Verify a Transfer CD/CE/CG proof using independent TransferAirV2.
///
/// `proof_bytes`: serialized Plonky3 proof from scalar-stark-p3::prove_transfer_p3.
/// `pi`: public inputs — must match what was used during proving.
///
/// Returns Ok(()) if independent verifier accepts the proof.
/// Spec §15.3.
pub fn verify_transfer_independent(
    proof_bytes: &[u8],
    pi: &TransferPublicInputsP3,
) -> Result<(), IndependentVerifyError> {
    // OSSIFIED trace width consistency check.
    if TRANSFER_TRACE_WIDTH != TRANSFER_TRACE_WIDTH_V2 {
        return Err(IndependentVerifyError::TraceWidthMismatch {
            primary: TRANSFER_TRACE_WIDTH,
            v2: TRANSFER_TRACE_WIDTH_V2,
        });
    }

    let proof: Proof<ScalarStarkConfig> = postcard::from_bytes(proof_bytes)
        .map_err(|e| IndependentVerifyError::Deserialize(e.to_string()))?;

    let config = build_scalar_config();
    let air = TransferAirV2;
    let public_values = pi.to_goldilocks();

    verify(&config, &air, &proof, &public_values).map_err(|e| {
        IndependentVerifyError::VerificationFailed {
            reason: format!("{e:?}"),
        }
    })
}

/// Verify a MintLinear proof using independent MintAirV2.
///
/// `proof_bytes`: serialized proof from scalar-stark-p3::prove_mint_linear_p3.
/// `pi`: mint linear public inputs.
/// Spec §15.3.
pub fn verify_mint_independent(
    proof_bytes: &[u8],
    pi: &MintLinearPublicInputs,
) -> Result<(), IndependentVerifyError> {
    if MINT_LINEAR_WIDTH != MINT_TRACE_WIDTH_V2 {
        return Err(IndependentVerifyError::TraceWidthMismatch {
            primary: MINT_LINEAR_WIDTH,
            v2: MINT_TRACE_WIDTH_V2,
        });
    }

    let proof: Proof<ScalarStarkConfig> = postcard::from_bytes(proof_bytes)
        .map_err(|e| IndependentVerifyError::Deserialize(e.to_string()))?;

    let config = build_scalar_config();
    let air = MintAirV2;
    let public_values = build_mint_linear_pv(pi);

    verify(&config, &air, &proof, &public_values).map_err(|e| {
        IndependentVerifyError::VerificationFailed {
            reason: format!("{e:?}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_stark_p3::{
        mint_air_p3::prove_mint_linear_p3, mint_air_p3::MintLinearPublicInputs,
        transfer_air_p3::prove_transfer_p3, transfer_public_inputs::TransferPublicInputsP3,
    };

    fn valid_transfer_pi() -> TransferPublicInputsP3 {
        TransferPublicInputsP3 {
            fee_total_sscl: 40,
            sum_inputs_sscl: 1_000_000_040,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0xAAu8; 32],
            nullifier_archived_root: [0xBBu8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
            commitment_hash: [0u64; 4],
            nullifier_hash: [0u64; 4],
        }
    }

    fn valid_mint_pi() -> MintLinearPublicInputs {
        MintLinearPublicInputs {
            crypto_version: 0x01,
            total_minted_sscl: 0,
            reward_amount_sscl: 1_000_000,
            node_auth_valid: true,
            mint_nullifier: [1u64, 2, 3, 4],
        }
    }

    /// A-R7 spec §15.3: Transfer proof from primary → accepted by independent V2.
    #[test]
    fn test_ar7_transfer_cross_verification() {
        let pi = valid_transfer_pi();
        let proof_bytes = prove_transfer_p3(&pi).expect("primary prover must succeed");

        let result = verify_transfer_independent(&proof_bytes, &pi);
        assert!(
            result.is_ok(),
            "independent V2 verifier must accept proof from primary prover: {result:?}"
        );
    }

    /// A-R7 spec §15.3: Mint proof from primary → accepted by independent V2.
    #[test]
    fn test_ar7_mint_cross_verification() {
        let pi = valid_mint_pi();
        let proof_bytes = prove_mint_linear_p3(&pi).expect("primary mint prover must succeed");

        let result = verify_mint_independent(&proof_bytes, &pi);
        assert!(
            result.is_ok(),
            "independent V2 verifier must accept mint proof from primary prover: {result:?}"
        );
    }

    /// A-R7: Tampered proof rejected by independent verifier.
    #[test]
    fn test_ar7_tampered_proof_rejected_by_v2() {
        let pi = valid_transfer_pi();
        let mut proof_bytes = prove_transfer_p3(&pi).expect("primary prover must succeed");

        // Tamper last bytes
        let len = proof_bytes.len();
        if len > 4 {
            proof_bytes[len - 1] ^= 0xFF;
            proof_bytes[len - 2] ^= 0xFF;
        }

        let result = verify_transfer_independent(&proof_bytes, &pi);
        assert!(
            result.is_err(),
            "independent V2 must reject tampered proof (A-R7)"
        );
    }

    /// A-R7: Wrong public inputs rejected by independent verifier.
    #[test]
    fn test_ar7_wrong_pi_rejected_by_v2() {
        let pi = valid_transfer_pi();
        let proof_bytes = prove_transfer_p3(&pi).expect("primary prover must succeed");

        let mut wrong_pi = pi.clone();
        wrong_pi.fee_total_sscl = 100; // different fee
        wrong_pi.sum_inputs_sscl = wrong_pi.sum_outputs_sscl + 100;

        let result = verify_transfer_independent(&proof_bytes, &wrong_pi);
        assert!(
            result.is_err(),
            "independent V2 must reject proof with wrong public inputs (A-R7)"
        );
    }
}
