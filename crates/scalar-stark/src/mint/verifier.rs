//! MintClaimVerifier — Verifier untuk MINT_CLAIM_CIRCUIT
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.2
//!
//! Gate §B.5.1 Step 6:
//! MINT_CLAIM_CIRCUIT hanya bisa dijalankan setelah:
//!   1. EpochRewardManifest diterima ≥67% network
//!   2. EmissionAccumulator sudah di-update dengan E(k)

use super::air::{MintClaimAir, MintClaimPublicInputs};
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::DefaultRandomCoin;
use winterfell::math::fields::f64::BaseElement;

/// Verifikasi STARK proof untuk mint claim.
///
/// Pemanggil HARUS sudah memverifikasi gate §B.5.1 Step 6:
///   - manifest_acceptance_fraction ≥ 0.67
///   - EmissionAccumulator sudah di-update
/// sebelum memanggil fungsi ini.
pub fn verify_mint_proof(
    proof_bytes: &[u8],
    pub_inputs: MintClaimPublicInputs,
) -> Result<(), &'static str> {
    let proof = winterfell::Proof::from_bytes(proof_bytes)
        .map_err(|_| "Format MINT_CLAIM proof tidak valid")?;

    let acceptable_options =
        winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

    winterfell::verify::<
        MintClaimAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &acceptable_options)
    .map_err(|_| "Verifikasi MINT_CLAIM STARK proof gagal")?;

    Ok(())
}
