// File: crates/scalar-stark/src/mint/verifier.rs

use crate::mint::air::MintClaimPublicInput;

pub fn verify_mint(proof: &[u8], pub_input: &MintClaimPublicInput) -> bool {
    crate::mint::air::verify_mint_claim(proof, pub_input)
}
