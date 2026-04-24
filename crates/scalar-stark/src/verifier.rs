use crate::air::ScalarAir;
use winterfell::math::fields::f64::BaseElement;
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::DefaultRandomCoin;

pub fn verify_proof(proof_bytes: &[u8]) -> Result<(), &'static str> {
    let proof = winterfell::Proof::from_bytes(proof_bytes).map_err(|_| "Format proof tidak valid")?;
    
    // FIXED: Menyuntikkan AcceptableOptions sebagai parameter ke-3
    let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    
    winterfell::verify::<ScalarAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>>(
        proof,
        (),
        &acceptable_options
    ).map_err(|_| "Verifikasi STARK gagal")?;
    
    Ok(())
}
