//! scalar-stark-p3 — Plonky3-based STARK proving system
//!
//! Replaces scalar-stark (Winterfell) before testnet. Spec §2.1.
//!
//! Sub-phases:
//!   P3-R1: Setup & dependency resolution (this file)
//!   P3-R2: ScalarP3Config — OSSIFIED FRI params (Goldilocks + Poseidon2)
//!   P3-R3: Poseidon2Air — in-circuit Poseidon2 permutation
//!   P3-R4: TransferAir — constraint groups CA-CG (spec §4.3)
//!   P3-R5: MintAir — constraint groups MC1-MC5 (spec §5.2)
//!   P3-R6: ZK blinding — trace values hidden from verifier
//!   P3-R7: Remove Winterfell dependency from workspace
//!   P3-R8: STARKPack — native Plonky3 batch proving
//!   P3-R9: Empirical benchmark — proving time on spec hardware

pub mod config;
pub mod poseidon2_p3;

/// Plonky3 crate versions used. Spec §2.1.
pub const P3_VERSION: &str = "0.5.3";

/// Goldilocks prime p = 2^64 - 2^32 + 1. OSSIFIED — spec §4.4, §17.
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// FRI blowup factor. OSSIFIED — spec §4.4.
pub const FRI_LOG_BLOWUP: usize = 3; // 2^3 = 8

/// FRI queries. OSSIFIED — spec §4.4.
pub const FRI_NUM_QUERIES: usize = 84;

/// FRI grinding bits. OSSIFIED — spec §4.4.
pub const FRI_PROOF_OF_WORK_BITS: usize = 20;
