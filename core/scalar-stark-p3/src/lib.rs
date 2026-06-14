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

pub mod batch_transfer_p3;
pub mod cg_arith;
pub mod config;
pub mod membership_air_p3;
pub mod mint_air_p3;
pub mod nonmembership_air_p3;
pub mod ownership_air_p3;
pub mod poseidon2_p3;
pub mod starkpack_p3;
pub mod transfer_air_p3;
pub mod transfer_public_inputs;

/// Plonky3 crate versions used. Spec §2.1.
pub const P3_VERSION: &str = "0.5.3";

/// Goldilocks prime p = 2^64 - 2^32 + 1. OSSIFIED — spec §4.4, §17.
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// FRI blowup factor. OSSIFIED — spec §4.4.
pub const FRI_LOG_BLOWUP: usize = 3; // 2^3 = 8

/// FRI query count. OSSIFIED — SCALAR-SECURITY §[PROOF-PARAMS].
/// q=108 meets >160-bit soundness target under Johnson bound (proven) with
/// cubic extension GF(p^3). ADR-SEC-023 formal confirmation required pre-mainnet.
/// DO NOT duplicate this value — reference this constant only.
pub const FRI_NUM_QUERIES: usize = 108;

/// FRI grinding bits. OSSIFIED — SCALAR-SECURITY §[PROOF-PARAMS].
/// g=0: grinding AMPUTATED as final architectural decision.
/// Soundness now relies on cubic field extension (GF(p^3), |F|≈2^192) and
/// query count — both sampling/proximity bounds, not PoW search bounds.
/// This eliminates QROM degradation from Grover acceleration entirely.
/// ADR-SEC-023 formal confirmation required pre-mainnet.
pub const FRI_PROOF_OF_WORK_BITS: usize = 0;

// ── Compile-time OSSIFIED enforcement ──────────────────────────────────────
// Aktif di SEMUA build profile (debug, release, test).
// Perubahan nilai apapun → compile error.
// Perubahan hanya via COMMIT 75% governance + formal soundness re-proof.
// Ref: SCALAR-PROTOCOL §13.1, SCALAR-SECURITY §3.4 RISK-02, D-028
/// Compile-time enforcement of OSSIFIED proof parameters.
/// Source: SCALAR-SECURITY §[PROOF-PARAMS]. DO NOT change without COMMIT 75%
/// governance vote AND formal soundness re-proof (ADR-SEC-023).
const _: () = {
    assert!(
        FRI_LOG_BLOWUP == 3,
        "OSSIFIED: FRI_LOG_BLOWUP must be 3 (blowup=8). [SCALAR-SECURITY §[PROOF-PARAMS]]"
    );
    assert!(
        FRI_NUM_QUERIES == 108,
        "OSSIFIED: FRI_NUM_QUERIES must be 108. [SCALAR-SECURITY §[PROOF-PARAMS]]"
    );
    assert!(
        FRI_PROOF_OF_WORK_BITS == 0,
        "OSSIFIED: FRI grinding must be 0 (amputated). [SCALAR-SECURITY §[PROOF-PARAMS]]"
    );
    assert!(
        GOLDILOCKS_PRIME == 0xFFFF_FFFF_0000_0001,
        "OSSIFIED: Goldilocks prime must not change. [SCALAR-SECURITY §[PROOF-PARAMS]]"
    );
};
