use crate::air::{ScalarAir, ScalarPublicInputs};
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::DefaultRandomCoin;
use winterfell::math::fields::f64::BaseElement;

pub fn verify_proof(
    proof_bytes: &[u8],
    pub_inputs: ScalarPublicInputs,
) -> Result<(), &'static str> {
    let proof =
        winterfell::Proof::from_bytes(proof_bytes).map_err(|_| "Format proof tidak valid")?;
    let acceptable_options =
        winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

    winterfell::verify::<
        ScalarAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &acceptable_options)
    .map_err(|_| "Verifikasi STARK gagal")?;

    Ok(())
}
