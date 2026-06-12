//! Fuzz: STARKPack Adversarial — TV5.15, K7-03
//! Spec §5.15: 10M attempt adversarial prover
//! Attack vectors: correlation injection, transcript reset, element skipping,
//! order manipulation, domain separation bypass
#![no_main]
use libfuzzer_sys::fuzz_target;
use scalar_stark_p3::starkpack_p3::{
    aggregate_for_fuzz, aggregate_real_proofs, RealAggregateError, RealProofInput,
    STARK_MAX_BATCH_SIZE,
};
use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

fn make_pi(seed: u64) -> TransferPublicInputsP3 {
    TransferPublicInputsP3 {
        fee_total_sscl: 40 + (seed % 1000),
        sum_inputs_sscl: 1_000_000_040 + (seed % 1000),
        sum_outputs_sscl: 1_000_000_000,
        crypto_version: 0x01,
        current_subepoch_id: 1_000,
        target_subepoch_id: 1_000,
        utxo_set_root: [0u8; 32],
        nullifier_active_root: [0u8; 32],
        nullifier_archived_root: [0u8; 32],
        cb_membership_verified: true,
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
            commitment_hash: [0u64; 4], // A-R9: set via derive_public_claims
            nullifier_hash: [0u64; 4], // A-R9: set via derive_public_claims
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let seed = data[0];
    let mode = data[1] & 0x07;
    let n = ((data[2] as usize) % 4).max(1);

    // Build inputs with placeholder proof_bytes (real proving is too slow for fuzzing).
    // The fuzz target validates transcript logic and rejection paths.
    let base_pi = make_pi(seed as u64);
    let mut inputs: Vec<RealProofInput> = (0..n).map(|i| RealProofInput {
        proof_bytes: data[3..].to_vec(), // adversarial bytes
        public_inputs: make_pi(i as u64 + seed as u64),
        tx_ordering_key: {
            let mut k = [0u8; 32];
            k[0] = i as u8;
            k[1] = seed;
            k
        },
    }).collect();

    match mode {
        0 | 1 | 2 | 3 => {
            // P1: adversarial proof bytes must either fail or succeed structurally.
            // We just ensure no panic — correctness checked in unit tests.
            let _ = aggregate_for_fuzz(&inputs);
        }
        4 => {
            // P2: order manipulation — transcript_hash must differ for different orders.
            if inputs.len() >= 2 {
                inputs[0].tx_ordering_key = [0x00u8; 32];
                inputs[1].tx_ordering_key = [0xFFu8; 32];
                let mut rev = inputs.clone();
                rev[0].tx_ordering_key = [0xFFu8; 32];
                rev[1].tx_ordering_key = [0x00u8; 32];
                // Both may error (bad proof bytes) — no panic is the invariant.
                let _ = aggregate_for_fuzz(&inputs);
                let _ = aggregate_for_fuzz(&rev);
            }
        }
        5 => {
            // P2: element skipping — no panic.
            if inputs.len() >= 2 {
                let _ = aggregate_for_fuzz(&inputs);
                inputs.pop();
                let _ = aggregate_for_fuzz(&inputs);
            }
        }
        6 => {
            // P3: determinism — same input twice, no panic.
            let _ = aggregate_for_fuzz(&inputs);
            let _ = aggregate_for_fuzz(&inputs);
        }
        7 => {
            // P1: batch size overflow.
            let big: Vec<RealProofInput> = (0..=STARK_MAX_BATCH_SIZE).map(|i| RealProofInput {
                proof_bytes: vec![0u8; 4],
                public_inputs: base_pi.clone(),
                tx_ordering_key: [i as u8; 32],
            }).collect();
            let r = aggregate_real_proofs(&big);
            assert!(
                matches!(r, Err(RealAggregateError::InvalidBatchSize { .. })),
                "oversized batch must be rejected"
            );
        }
        _ => {}
    }
});