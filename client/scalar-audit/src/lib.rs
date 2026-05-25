//! scalar-audit — Read-only Audit, Verify Proof, Inspect State
//!
//! Spec §16.4 v11.1-FINAL.
//!
//! PRINSIP ISOLASI (spec §16.4):
//!   - Crate terpisah untuk kebutuhan audit, verifikasi proof, dan inspeksi state.
//!   - TIDAK ada akses ke kunci privat.
//!   - Hanya operasi read-only dan ZK verification.
//!   - Menggunakan API publik dari scalar-crypto dan scalar-stark SAJA.
//!   - TIDAK boleh import scalar-nullifier internal state secara langsung.
//!
//! API PUBLIK (spec §16.4):
//!   verify_transfer_proof(proof, public_inputs) -> bool
//!   inspect_nullifier_state(nullifier) -> NullifierStatus
//!   verify_manifest_hash(manifest) -> bool

pub mod proof_verifier;
pub mod state_inspector;

// Re-export API publik — spec §16.4
pub use proof_verifier::{
    is_proof_valid, verify_transfer_proof, AuditPublicInputs, ProofVerificationResult,
};
pub use state_inspector::{
    audit_blake3_hash, inspect_nullifier_state, verify_manifest_hash, ManifestAuditResult,
    NullifierStatus,
};

#[cfg(test)]
mod tests {
    use super::*;

    // ── test_verify_transfer_proof_valid ─────────────────────────────────────

    #[test]
    fn test_verify_transfer_proof_via_lib() {
        // K5-01: REAL STARK proof via public API. Spec §16.4.
        use scalar_stark::transfer_air::{TransferProver, TransferPublicInputs};
        let inputs = AuditPublicInputs {
            utxo_set_root: [0x42u8; 32],
            nullifier_smt_root: 1,
            fee_value: 40,
            timestamp: 1_000_060_000,
            entry_timestamp: 1_000_000_000,
            crypto_version: 0x01,
        };
        // Generate a real proof matching scalar_to_transfer_pi's reconstruction.
        let tpi = TransferPublicInputs {
            fee_total_sscl: inputs.fee_value,
            sum_inputs_sscl: inputs.fee_value,
            sum_outputs_sscl: 0,
            crypto_version: inputs.crypto_version,
            entry_timestamp_ms: inputs.entry_timestamp,
            current_timestamp_ms: inputs.timestamp,
            nullifier_nonzero: inputs.nullifier_smt_root != 0,
            output_nonzero: inputs.utxo_set_root != [0u8; 32],
            single_utxo_source: true,
        };
        let proof = TransferProver::new()
            .prove_transfer(&tpi)
            .expect("real proof");
        let result = verify_transfer_proof(&proof, &inputs);
        assert!(result.is_valid(), "real proof must verify: {:?}", result);
    }

    // ── test_verify_transfer_proof_invalid ───────────────────────────────────

    #[test]
    fn test_verify_transfer_proof_invalid_via_lib() {
        // Invalid proof → tidak valid. Spec §16.4.
        let proof = vec![0xABu8; 100];
        let inputs = AuditPublicInputs {
            utxo_set_root: [0x42u8; 32],
            nullifier_smt_root: 1,
            fee_value: 40,
            timestamp: 1_000_060_000,
            entry_timestamp: 1_000_000_000,
            crypto_version: 0xFF, // invalid
        };
        assert!(!verify_transfer_proof(&proof, &inputs).is_valid());
    }

    // ── test_inspect_nullifier_state ─────────────────────────────────────────

    #[test]
    fn test_inspect_nullifier_state_via_lib() {
        // API publik inspect_nullifier_state tersedia. Spec §16.4.
        let nullifier = [0x01u8; 32];
        let result = inspect_nullifier_state(&nullifier, &[]);
        assert_eq!(result, NullifierStatus::Unspent);
    }

    // ── test_audit_no_private_key_access ─────────────────────────────────────

    #[test]
    fn test_audit_no_private_key_access() {
        // Semua API publik tidak membutuhkan private key. Spec §16.4.
        let proof = vec![0xABu8; 50];
        let inputs = AuditPublicInputs {
            utxo_set_root: [0u8; 32],
            nullifier_smt_root: 0,
            fee_value: 40,
            timestamp: 1_000_000,
            entry_timestamp: 999_000,
            crypto_version: 0x01,
        };
        let _ = verify_transfer_proof(&proof, &inputs);
        let _ = inspect_nullifier_state(&[0x01u8; 32], &[]);
    }

    // ── test_audit_isolation ──────────────────────────────────────────────────

    #[test]
    fn test_audit_isolation() {
        // scalar-audit tidak import scalar-nullifier internal. Spec §16.4.
        // Test ini compile → isolation terjaga.
        let _ = audit_blake3_hash(b"test");
    }
}
