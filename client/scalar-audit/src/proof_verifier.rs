//! Proof Verifier — Read-only ZK Proof Verification — Spec §16.4 v11.1-FINAL
//!
//! API publik for verification STARK proof tanpa access to private toy.
//! only using API publik from scalar-stark.
//!
//! Spec §16.4: "Crate separate for tobutuhan auatt, verification proof,
//! and inspect state. none access to private toy.
//! only operation read-only and ZK verification."

use scalar_stark::air::ScalarPublicInputs;
use scalar_stark::verifier::{verify_proof, VerifyError};

// ── ProofVerificationResult — spec §16.4 ─────────────────────────────────────

/// verification result STARK proof. Spec §16.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerificationResult {
    /// Proof valid — all constraint terfulli. Spec §16.4.
    Valid,
    /// Proof invalid — constraint failed. Spec §16.4.
    Invalid { reason: String },
    /// Proof empty or format invalid. Spec §16.4.
    Malformed,
}

impl ProofVerificationResult {
    /// true if proof valid. Spec §16.4.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

// ── AuditPublicInputs — input publik untuk audit ──────────────────────────────

/// Public inputs for auatt proof verification. Spec §16.4.
///
/// only berfill data publik — none private witness.
#[derive(Clone, Debug)]
pub struct AuditPublicInputs {
    /// UTXO set root from epoch k-1 (CB constraint). Spec §4.2.
    pub utxo_set_root: [u8; 32],
    /// Nullifier SMT root when this. Spec §4.2.
    pub nullifier_smt_root: u64,
    /// Fee total in SSCL. Spec §9.1.
    pub fee_value: u64,
    /// Timestamp when proving. Spec §4.2.
    pub timestamp: u64,
    /// Entry timestamp (anti-censorship). Spec §4.3 CG.
    pub entry_timestamp: u64,
    /// version cryptography. Spec §4.3 CG.
    pub crypto_version: u8,
}

impl AuditPublicInputs {
    /// Konversion to ScalarPublicInputs for verifier. Spec §16.4.
    fn to_scalar_public_inputs(&self) -> ScalarPublicInputs {
        ScalarPublicInputs {
            genesis_smt_root: 0, // Legacy field
            utxo_set_root: self.utxo_set_root,
            current_nullifier_smt_root: self.nullifier_smt_root,
            fee_value: self.fee_value,
            timestamp: self.timestamp,
            entry_timestamp: self.entry_timestamp,
            crypto_version: self.crypto_version,
        }
    }
}

// ── verify_transfer_proof — spec §16.4 ───────────────────────────────────────

/// verification STARK proof transfer. Spec §16.4.
///
/// `proof`: bytes from STARK proof.
/// `public_inputs`: public inputs for verification.
///
/// Returns ProofVerificationResult — not throws, always returns.
/// none access to private witness or private toy. Spec §16.4.
pub fn verify_transfer_proof(
    proof: &[u8],
    public_inputs: &AuditPublicInputs,
) -> ProofVerificationResult {
    if proof.is_empty() {
        return ProofVerificationResult::Malformed;
    }

    let scalar_inputs = public_inputs.to_scalar_public_inputs();

    match verify_proof(proof, scalar_inputs) {
        Ok(()) => ProofVerificationResult::Valid,
        Err(VerifyError::InvalidProof) => ProofVerificationResult::Malformed,
        Err(e) => ProofVerificationResult::Invalid {
            reason: e.to_string(),
        },
    }
}

/// verification proof valid (convenience wrapper). Spec §16.4.
///
/// returns true if proof valid, false if not.
pub fn is_proof_valid(proof: &[u8], public_inputs: &AuditPublicInputs) -> bool {
    verify_transfer_proof(proof, public_inputs).is_valid()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_inputs() -> AuditPublicInputs {
        AuditPublicInputs {
            utxo_set_root: [0x42u8; 32],
            nullifier_smt_root: 1,
            fee_value: 40,
            timestamp: 1_000_060_000,
            entry_timestamp: 1_000_000_000,
            crypto_version: 0x01,
        }
    }

    // ── test_verify_transfer_proof_valid ─────────────────────────────────────

    #[test]
    fn test_verify_transfer_proof_valid() {
        // Proof non-empty dengan inputs valid → Valid. Spec §16.4.
        let proof = vec![0xABu8; 100];
        let result = verify_transfer_proof(&proof, &valid_inputs());
        assert!(
            result.is_valid(),
            "Proof valid harus diterima: {:?}",
            result
        );
    }

    // ── test_verify_transfer_proof_invalid ───────────────────────────────────

    #[test]
    fn test_verify_transfer_proof_invalid_crypto_version() {
        // Crypto version tidak valid → Invalid. Spec §16.4.
        let proof = vec![0xABu8; 100];
        let mut inputs = valid_inputs();
        inputs.crypto_version = 0x99; // invalid
        let result = verify_transfer_proof(&proof, &inputs);
        assert!(
            !result.is_valid(),
            "Proof dengan crypto version invalid harus ditolak"
        );
    }

    #[test]
    fn test_verify_transfer_proof_empty_malformed() {
        // Proof kosong → Malformed. Spec §16.4.
        let result = verify_transfer_proof(&[], &valid_inputs());
        assert_eq!(result, ProofVerificationResult::Malformed);
    }

    // ── test_no_private_key_access ────────────────────────────────────────────

    #[test]
    fn test_audit_no_private_key_access() {
        // Verifikasi: fungsi ini tidak membutuhkan private key.
        // Test compile → tidak ada parameter private key. Spec §16.4.
        let proof = vec![0xABu8; 50];
        let inputs = valid_inputs();
        // Hanya proof bytes dan public inputs — tidak ada private key param
        let _ = verify_transfer_proof(&proof, &inputs);
        let _ = is_proof_valid(&proof, &inputs);
    }

    #[test]
    fn test_is_proof_valid_convenience() {
        // is_proof_valid adalah convenience wrapper. Spec §16.4.
        let proof = vec![0xABu8; 100];
        let inputs = valid_inputs();
        assert!(is_proof_valid(&proof, &inputs));
    }
}
