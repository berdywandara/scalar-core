// File: crates/scalar-stark/src/mint/prover.rs

use crate::mint::air::MintClaimPublicInput;

pub fn prove_mint(
    _witness: &(),
    pub_input: &MintClaimPublicInput,
) -> Result<Vec<u8>, &'static str> {
    crate::mint::air::prove_mint_claim(_witness, pub_input)
}
