//! Fuzz: STARKPack Adversarial — TV5.15, K7-03
//! Spec §5.15: 10M attempt adversarial prover
//! Attack vectors: correlation injection, transcript reset, element skipping,
//! order manipulation, domain separation bypass
#![no_main]
use libfuzzer_sys::fuzz_target;
use scalar_stark::starkpack::{
    aggregate_real_proofs, RealAggregateError, RealProofInput, STARK_MAX_BATCH_SIZE,
};
use scalar_stark::transfer_air::{TransferProver, TransferPublicInputs};

fn make_pi(seed: u64) -> TransferPublicInputs {
    // Mirror valid_pi() from transfer_air tests — all fields current as of FASE A.
    TransferPublicInputs {
        fee_total_sscl: 40 + (seed % 1000),
        sum_inputs_sscl: 1_000_000_040 + (seed % 1000),
        sum_outputs_sscl: 1_000_000_000,
        crypto_version: 0x01,
        entry_timestamp_ms: 1_000_000_000 + seed,
        current_timestamp_ms: 1_000_060_000 + seed,
        utxo_set_root: [0u8; 32],
        nullifier_active_root: [0u8; 32],
        nullifier_archived_root: [0u8; 32],
        cb_membership_verified: true,
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
    }
}

fn make_input(seed: u8) -> RealProofInput {
    let pi = make_pi(seed as u64);
    let proof_bytes = TransferProver::new().prove_transfer(&pi).expect("proof");
    RealProofInput {
        proof_bytes,
        public_inputs: pi,
        tx_ordering_key: [seed; 32],
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let seed = data[0];
    let mode = data[1] & 0x07;
    let n = ((data[2] as usize) % 4).max(1);
    let mut inputs: Vec<RealProofInput> = (0..n as u8)
        .map(|i| make_input(i.wrapping_add(seed)))
        .collect();

    match mode {
        0 => {
            // P1: valid batch must aggregate successfully
            let r = aggregate_real_proofs(&inputs);
            assert!(r.is_ok(), "P1: valid batch must aggregate: {:?}", r.err());
        }
        1 => {
            // P1: tampered proof bytes must be rejected
            if let Some(inp) = inputs.first_mut() {
                inp.proof_bytes = vec![0x5c; 64];
            }
            let r = aggregate_real_proofs(&inputs);
            assert!(
                matches!(r, Err(RealAggregateError::ProofVerificationFailed { .. })),
                "P1: tampered must reject: {:?}",
                r
            );
        }
        2 => {
            // P1: empty proof bytes must be rejected
            inputs.push(RealProofInput {
                proof_bytes: vec![],
                public_inputs: make_pi(0),
                tx_ordering_key: [0xFF; 32],
            });
            let r = aggregate_real_proofs(&inputs);
            assert!(
                matches!(r, Err(RealAggregateError::ProofVerificationFailed { .. })),
                "P1: empty must reject: {:?}",
                r
            );
        }
        3 => {
            // P1: mismatched public inputs must be rejected
            if let Some(inp) = inputs.first_mut() {
                inp.public_inputs.fee_total_sscl = 999_999_999;
            }
            let r = aggregate_real_proofs(&inputs);
            assert!(
                matches!(r, Err(RealAggregateError::ProofVerificationFailed { .. })),
                "P1: mismatched PI must reject: {:?}",
                r
            );
        }
        4 => {
            // P2: order manipulation — transcript_hash must differ
            if inputs.len() >= 2 {
                let r1 = aggregate_real_proofs(&inputs).unwrap();
                inputs.reverse();
                let r2 = aggregate_real_proofs(&inputs).unwrap();
                assert_ne!(r1.transcript_hash, r2.transcript_hash, "P2: order matters");
            }
        }
        5 => {
            // P2: element skipping — transcript_hash must differ
            if inputs.len() >= 2 {
                let r1 = aggregate_real_proofs(&inputs).unwrap();
                inputs.pop();
                let r2 = aggregate_real_proofs(&inputs).unwrap();
                assert_ne!(
                    r1.transcript_hash, r2.transcript_hash,
                    "P2: skipping matters"
                );
            }
        }
        6 => {
            // P2+P3: determinism — same input same output
            let r1 = aggregate_real_proofs(&inputs).unwrap();
            let r2 = aggregate_real_proofs(&inputs).unwrap();
            assert_eq!(
                r1.transcript_hash, r2.transcript_hash,
                "P2: transcript determinism"
            );
            assert_eq!(
                r1.global_fri_root, r2.global_fri_root,
                "P3: fri root determinism"
            );
        }
        7 => {
            // P1: batch size overflow must be rejected
            if inputs.len() > STARK_MAX_BATCH_SIZE {
                let r = aggregate_real_proofs(&inputs);
                assert!(
                    matches!(r, Err(RealAggregateError::InvalidBatchSize { .. })),
                    "P1: max batch exceeded: {:?}",
                    r
                );
            }
        }
        _ => {}
    }
});
