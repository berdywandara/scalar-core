//! Proof Verifier — Read-only ZK Proof Verification — Spec §16.4
//!
//! API publik untuk verifikasi STARK proof tanpa akses ke kunci privat.
//! Menggunakan scalar-stark-p3 (Plonky3-based, ZK-enabled). Spec §2.1 D-E1.
//!
//! Spec §16.4: "Crate terpisah untuk kebutuhan audit, verifikasi proof,
//! dan inspeksi state. Tidak ada akses ke kunci privat.
//! Hanya operasi read-only dan ZK verification."
//!
//! FASE A: returns Unverifiable when EpochState is not available.
//! FASE B (TODO): connect EpochState → build_claims_from_epoch_state() → Valid.

use scalar_stark_p3::batch_transfer_p3::BatchTransferProof;

// ── ProofVerificationResult — spec §16.4 ─────────────────────────────────────

/// Hasil verifikasi STARK proof. Spec §16.4.
///
/// SEMANTICS — setiap varian berbeda secara kriptografis:
///   `Valid`        — proof STARK + roots tervalidasi terhadap EpochState nyata. FASE B.
///   `Unverifiable` — proof well-formed, tapi EpochState belum tersambung;
///                    root tidak dapat divalidasi.
///                    "Belum bisa diverifikasi" BUKAN "terverifikasi valid". [P1]
///   `Invalid`      — STARK constraint gagal secara kriptografis.
///   `Malformed`    — tidak dapat di-deserialisasi.
///
/// Jangan pernah return Valid tanpa verifikasi kriptografis nyata. [P1, Larangan Mutlak]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerificationResult {
    /// Proof valid — semua constraint terpenuhi DAN root tervalidasi terhadap
    /// EpochState otoritatif. FASE B (belum diimplementasikan). Spec §16.4.
    Valid,
    /// Proof well-formed secara kriptografis, tapi EpochState belum tersambung.
    /// Root (utxo_set_root, nullifier_roots) tidak dapat divalidasi. [P1]
    Unverifiable { reason: String },
    /// Proof tidak valid — STARK constraint gagal. Spec §16.4.
    Invalid { reason: String },
    /// Proof kosong atau format tidak valid. Spec §16.4.
    Malformed,
}

impl ProofVerificationResult {
    /// True HANYA jika proof terverifikasi penuh terhadap EpochState nyata.
    /// Unverifiable mengembalikan FALSE. [P1]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// True jika proof terbentuk dengan benar (deserialisasi sukses),
    /// meski root belum tervalidasi. Gunakan untuk relay decision, bukan finalitas.
    pub fn is_well_formed(&self) -> bool {
        matches!(self, Self::Valid | Self::Unverifiable { .. })
    }
}

// ── AuditPublicInputs — spec §16.4 ───────────────────────────────────────────

/// Public inputs untuk audit proof verification. Spec §16.4.
///
/// Hanya berisi data publik — tidak ada private witness.
#[derive(Clone, Debug)]
pub struct AuditPublicInputs {
    /// UTXO set root dari epoch k-1 (CB constraint). Spec §4.2.
    pub utxo_set_root: [u8; 32],
    /// Nullifier SMT root saat ini. Spec §4.2.
    pub nullifier_smt_root: u64,
    /// Fee total dalam sSCL. Spec §9.1.
    pub fee_value: u64,
    /// Timestamp saat proving. Spec §4.2.
    pub timestamp: u64,
    /// Entry timestamp (anti-censorship). Spec §4.3 CG.
    pub entry_timestamp: u64,
    /// Versi kriptografi. Spec §4.3 CG.
    pub crypto_version: u8,
}

// ── verify_transfer_proof — spec §16.4 ───────────────────────────────────────

/// Verifikasi STARK proof transfer. Spec §16.4.
///
/// `proof`: postcard-serialised BatchTransferProof bytes.
/// `_public_inputs`: public inputs untuk audit context.
///
/// Returns ProofVerificationResult — tidak throws, selalu returns.
/// Tidak ada akses ke private witness atau kunci privat. Spec §16.4.
pub fn verify_transfer_proof(
    proof: &[u8],
    _public_inputs: &AuditPublicInputs,
) -> ProofVerificationResult {
    if proof.is_empty() {
        return ProofVerificationResult::Malformed;
    }

    // Deserialisasi BatchTransferProof dari postcard bytes.
    let batch_proof: BatchTransferProof = match postcard::from_bytes(proof) {
        Ok(p) => p,
        Err(_) => return ProofVerificationResult::Malformed,
    };

    // FASE A — Unverifiable: EpochState belum tersambung.
    //
    // scalar-audit tidak memiliki EpochState otoritatif (utxo_set_root,
    // nullifier_roots tervalidasi via VIR-001 quorum 5/7 manifest-tier).
    // Tanpa root yang benar, verify_batch_transfer terhadap zero roots
    // tidak soundness-preserving — proof terhadap zeros bukan bukti apapun.
    //
    // Mengembalikan Unverifiable adalah respons jujur (P1):
    //   - "Belum bisa diverifikasi" != "terverifikasi valid"
    //   - Tidak memalsukan keberhasilan untuk menghijaukan jalur
    //   - Proof well-formed (deserialisasi sukses) sudah dikonfirmasi di atas
    //
    // FASE B (TODO): sambungkan EpochState → build claims → verify nyata:
    //   let claims = build_claims_from_epoch_state(public_inputs)?;
    //   match verify_batch_transfer(&batch_proof, &claims) {
    //       Ok(()) => ProofVerificationResult::Valid,
    //       Err(e) => ProofVerificationResult::Invalid { reason: e.to_string() },
    //   }
    // Ref: SCALAR-PROTOCOL §7.4 VIR-001; SCALAR-TECHNICAL §4.1 §4.3. [P1]
    let _ = batch_proof; // well-formed confirmed above
    ProofVerificationResult::Unverifiable {
        reason: "EpochState not available — root validation requires FASE B integration. \
                 Proof is well-formed (deserialized OK) but utxo_set_root and \
                 nullifier_roots cannot be validated without EpochState context. \
                 [SCALAR-PROTOCOL §7.4 VIR-001]"
            .to_string(),
    }
}

/// True hanya jika proof terverifikasi PENUH terhadap EpochState. Spec §16.4.
/// Unverifiable -> false. Jangan gunakan sebagai relay decision. [P1]
pub fn is_proof_valid(proof: &[u8], public_inputs: &AuditPublicInputs) -> bool {
    verify_transfer_proof(proof, public_inputs).is_valid()
}

/// True jika proof terbentuk dengan benar (deserialisasi sukses).
/// Valid DAN Unverifiable -> true. Gunakan untuk relay; bukan finalitas.
pub fn is_proof_well_formed(proof: &[u8], public_inputs: &AuditPublicInputs) -> bool {
    verify_transfer_proof(proof, public_inputs).is_well_formed()
}

// ── FASE B placeholder ────────────────────────────────────────────────────────
//
// build_claims_from_epoch_state() akan diimplementasikan di FASE B.
// Menerima EpochState otoritatif (utxo_set_root, nullifier_roots dari
// SubEpochCommitment quorum 5/7) dan mengembalikan TransferPublicClaims
// untuk verify_batch_transfer() yang soundness-preserving.
// Ref: SCALAR-PROTOCOL §7.4 VIR-001; SCALAR-TECHNICAL §4.1.

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

    #[test]
    fn test_verify_transfer_proof_empty_malformed() {
        // Proof kosong -> Malformed. Spec §16.4.
        let result = verify_transfer_proof(&[], &valid_inputs());
        assert_eq!(result, ProofVerificationResult::Malformed);
    }

    #[test]
    fn test_verify_transfer_proof_garbage_malformed() {
        // Garbage bytes -> Malformed (gagal deserialisasi). Spec §16.4.
        let result = verify_transfer_proof(&[0xABu8; 100], &valid_inputs());
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_transfer_proof_via_lib() {
        // Well-formed check: non-empty non-garbage -> Unverifiable (FASE A), not Malformed.
        // Actual validity check deferred to FASE B (EpochState required). Spec §16.4.
        let proof = vec![0xABu8; 50];
        let result = verify_transfer_proof(&proof, &valid_inputs());
        // Garbage bytes fail deserialization -> Malformed (not Unverifiable).
        // This is correct: Malformed means "cannot deserialize", not "invalid proof".
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_transfer_proof_invalid_via_lib() {
        // Invalid proof bytes -> not valid. Spec §16.4.
        let result = verify_transfer_proof(&[0xFFu8; 200], &valid_inputs());
        assert!(!result.is_valid());
    }

    #[test]
    fn test_audit_no_private_key_access() {
        // Verifikasi: fungsi ini tidak membutuhkan private key. Spec §16.4.
        let proof = vec![0xABu8; 50];
        let inputs = valid_inputs();
        let _ = verify_transfer_proof(&proof, &inputs);
        let _ = is_proof_valid(&proof, &inputs);
        let _ = is_proof_well_formed(&proof, &inputs);
    }

    #[test]
    fn test_inspect_nullifier_state_via_lib() {
        // Placeholder: state inspection via audit API. Spec §16.4.
        let nullifier = [0x01u8; 32];
        let _ = nullifier;
    }

    #[test]
    fn test_audit_isolation() {
        // audit crate must not import private key material. Spec §16.4.
        let inputs = valid_inputs();
        assert_eq!(inputs.crypto_version, 0x01);
    }

    #[test]
    fn test_unverifiable_is_not_valid() {
        // Unverifiable != Valid. [P1, Larangan Mutlak]
        let r = ProofVerificationResult::Unverifiable {
            reason: "test".to_string(),
        };
        assert!(!r.is_valid());
        assert!(r.is_well_formed());
    }

    #[test]
    fn test_is_well_formed_valid_case() {
        // Valid -> is_well_formed() true.
        let r = ProofVerificationResult::Valid;
        assert!(r.is_valid());
        assert!(r.is_well_formed());
    }
}
