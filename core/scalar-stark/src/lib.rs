//! scalar-stark — STARK Proving System for Scalar Network
//!
//! Spec §4 (Transfer Circuit), §5 (Mint Circuit), §15 (Formal Verification).
//!
//! Real Winterfell-based AIR implementations:
//! - transfer_air: TransferAir, TransferProver, verify_transfer_proof (CA–CG)
//! - mint_air:     MintAir, MintProver, verify_mint_proof (MC1–MC5, K5-03)
//!
//! Legacy modules retained for compatibility:
//! - air, prover, verifier: ScalarPublicInputs, legacy verify_proof
//! - mint: MintClaimPublicInput, legacy mint interface
//! - starkpack: STARKPack transcript (K7-01)
//! - independent_verifier: semantic constraint verifier (K5-02 defense-in-depth)

// ── New real AIR implementations ──────────────────────────────────────────────
pub mod mint_air;
pub mod nullifier_air;
pub mod poseidon2_air;
pub mod transfer_air;

// ── Legacy modules (retained for consumer compatibility) ──────────────────────
pub mod air;
pub mod constraints;
pub mod independent_stark_verifier;
pub mod independent_verifier;
pub mod mint;
pub mod prover;
pub mod starkpack;
pub mod verifier;

// ── Re-exports for convenience ────────────────────────────────────────────────
pub use mint_air::{
    evaluate_mint_constraints, verify_mint_proof, MintProveError, MintProver, MintPublicInputs,
    MintVerifyError, S_E_SSCL,
};
pub use transfer_air::{
    evaluate_transfer_constraints, verify_transfer_proof, TransferProveError, TransferProver,
    TransferPublicInputs, TransferVerifyError, TRANSFER_BLOWUP, TRANSFER_FOLDING,
    TRANSFER_GRINDING, TRANSFER_NUM_QUERIES,
};
