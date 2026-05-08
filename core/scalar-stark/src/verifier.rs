// File: crates/scalar-stark/src/verifier.rs
//
// Verifier Transfer Circuit v5.0
// Memeriksa C9 (crypto_version) dan C10 (entry_timestamp).

use crate::air::{
    is_tx_censorship_expired, verify_c10_tx_within_wait_window, verify_c9_crypto_version,
    ScalarPublicInputs,
};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("C9 FAIL: crypto_version {0} tidak valid")]
    InvalidCryptoVersion(u8),
    #[error("C10 FAIL: entry_timestamp tidak valid atau tx sudah timeout")]
    CensorshipViolation,
    #[error("Proof kosong atau malformed")]
    InvalidProof,
}

/// Verifikasi STARK proof Transfer Circuit v5.0.
pub fn verify_proof(proof: &[u8], pub_inputs: ScalarPublicInputs) -> Result<(), VerifyError> {
    if proof.is_empty() {
        return Err(VerifyError::InvalidProof);
    }

    // C9: Version Compatibility
    verify_c9_crypto_version(pub_inputs.crypto_version)
        .map_err(|_| VerifyError::InvalidCryptoVersion(pub_inputs.crypto_version))?;

    // C10: entry_timestamp wajib ada
    if pub_inputs.entry_timestamp == 0 {
        return Err(VerifyError::CensorshipViolation);
    }

    // C10: tx tidak boleh expired
    if is_tx_censorship_expired(pub_inputs.entry_timestamp, pub_inputs.timestamp) {
        return Err(VerifyError::CensorshipViolation);
    }

    // C10: tx harus dalam window
    if !verify_c10_tx_within_wait_window(pub_inputs.entry_timestamp, pub_inputs.timestamp) {
        return Err(VerifyError::CensorshipViolation);
    }

    // TODO: Winterfell full verification
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_inputs() -> ScalarPublicInputs {
        ScalarPublicInputs {
            genesis_smt_root: 0,
            current_nullifier_smt_root: 1,
            fee_value: 40,
            timestamp: 1_000_060_000,
            entry_timestamp: 1_000_000_000,
            crypto_version: 0x01,
        }
    }

    #[test]
    fn test_verify_valid_proof_accepted() {
        assert!(verify_proof(&[0xAB; 100], valid_inputs()).is_ok());
    }

    #[test]
    fn test_verify_empty_proof_rejected() {
        assert!(matches!(
            verify_proof(&[], valid_inputs()),
            Err(VerifyError::InvalidProof)
        ));
    }

    #[test]
    fn test_verify_invalid_crypto_version_rejected() {
        let mut pi = valid_inputs();
        pi.crypto_version = 0xFF;
        assert!(matches!(
            verify_proof(&[0xAB; 10], pi),
            Err(VerifyError::InvalidCryptoVersion(0xFF))
        ));
    }

    #[test]
    fn test_verify_zero_entry_timestamp_rejected() {
        let mut pi = valid_inputs();
        pi.entry_timestamp = 0;
        assert!(matches!(
            verify_proof(&[0xAB; 10], pi),
            Err(VerifyError::CensorshipViolation)
        ));
    }

    #[test]
    fn test_verify_expired_tx_rejected() {
        let mut pi = valid_inputs();
        pi.entry_timestamp = 1_000_000_000;
        pi.timestamp = 1_000_000_000 + 2_000_000; // 33 menit
        assert!(matches!(
            verify_proof(&[0xAB; 10], pi),
            Err(VerifyError::CensorshipViolation)
        ));
    }
}
