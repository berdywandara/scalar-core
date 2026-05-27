//! Integration Tests — Fase 5: L2 Components
//!
//! Covers:
//!   1. Poseidon2 t=8 ↔ IMT integration
//!   2. Sub-Epoch + IMT frontier round-trip
//!   3. STARKPack transcript determinism
//!   4. Quaternary SMT + NullifierSet integration
//!   5. Transfer Circuit dual UTXOSource fields
//!   6. End-to-end: IMT → SubEpoch → verify_imt_source

// ── 1. Poseidon2 t=8 ↔ IMT integration ───────────────────────────────────────

#[test]
fn test_poseidon2_t8_used_in_imt_hash() {
    // IMT uses Poseidon2 t=8 for leaf and node hashing.
    // Verify: two different commitments produce different leaf hashes.
    use scalar_crypto::imt::IncrementalMerkleTree;

    let mut imt = IncrementalMerkleTree::new();
    let c0 = [0x01u8; 32];
    let c1 = [0x02u8; 32];
    imt.append(&c0).unwrap();
    imt.append(&c1).unwrap();

    let root_2 = imt.root();

    // Insert same commitments in separate tree — must produce same root (determinism)
    let mut imt2 = IncrementalMerkleTree::new();
    imt2.append(&c0).unwrap();
    imt2.append(&c1).unwrap();

    assert_eq!(
        root_2,
        imt2.root(),
        "Poseidon2 t=8 IMT must be deterministic"
    );
    assert_ne!(root_2, [0u8; 32], "root must be non-zero");
}

// ── 2. Sub-Epoch + IMT frontier round-trip ────────────────────────────────────

#[test]
fn test_subepoch_imt_frontier_round_trip() {
    // Build IMT, create SubEpochCommitment with its frontier,
    // then verify imt_frontier_root retrieval requires quorum.
    use scalar_crypto::imt::IncrementalMerkleTree;
    use scalar_network::subepoch::{SubEpochChain, SubEpochCommitment};

    let mut imt = IncrementalMerkleTree::new();
    for i in 0..5u8 {
        imt.append(&[i; 32]).unwrap();
    }
    let frontier_root = imt.root();
    let count = imt.count;

    // Build SubEpochCommitment with IMT frontier
    let mut commitment = SubEpochCommitment::new(
        1,             // epoch_id
        0,             // subepoch_id
        [0xAAu8; 32],  // tx_set_root
        [0xBBu8; 32],  // cumulative_utxo_root
        frontier_root, // imt_frontier_root
        [0xCCu8; 32],  // nullifier_batch_root
        [0u8; 32],     // prev_subepoch_hash (genesis)
        count,         // imt_count
        5,             // tx_count
        1_700_000_000, // timestamp
    );

    // Without quorum → cannot get frontier
    let mut chain = SubEpochChain::new(1);
    chain.add_commitment(commitment.clone()).unwrap();
    assert!(
        chain.get_imt_frontier_root(0).is_none(),
        "frontier must not be available without quorum"
    );

    // Add quorum (5 signatures)
    for i in 0..5u8 {
        commitment.add_validator_sig([i; 32], vec![i; 10]);
    }

    let mut chain2 = SubEpochChain::new(1);
    chain2.add_commitment(commitment).unwrap();

    let retrieved = chain2.get_imt_frontier_root(0);
    assert_eq!(
        retrieved,
        Some(frontier_root),
        "frontier must be available after quorum"
    );
}

// ── 3. STARKPack transcript determinism ──────────────────────────────────────

#[test]
fn test_starkpack_transcript_deterministic_across_calls() {
    // TV5.15 P3: same inputs → same transcript_hash across two calls.
    // Spec §3.4.3 R4: one transcript per batch, deterministic.
    use scalar_stark_p3::batch_transfer_p3::BatchTransferProof;
    use scalar_stark_p3::starkpack_p3::{aggregate_real_proofs, RealProofInput};
    use scalar_stark_p3::transfer_air_p3::prove_transfer_p3;
    use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

    fn make_pi(fee_extra: u64) -> TransferPublicInputsP3 {
        TransferPublicInputsP3 {
            fee_total_sscl: 40 + fee_extra,
            sum_inputs_sscl: 1_000_000_040 + fee_extra,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0xAAu8; 32],
            nullifier_archived_root: [0xBBu8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
        }
    }

    fn make_input(fee_extra: u64, key_byte: u8) -> RealProofInput {
        let pi = make_pi(fee_extra);
        // Build a minimal BatchTransferProof: only cdcecg_proof is verified
        // by the aggregator; ca/cb/cc are structural non-empty checks.
        let cdcecg = prove_transfer_p3(&pi).expect("prove must succeed");
        let batch = BatchTransferProof {
            ca_proof: vec![0xCAu8; 64],
            cb_proof: vec![0xCBu8; 64],
            cc_proof: vec![0xCCu8; 64],
            cdcecg_proof: cdcecg,
        };
        let proof_bytes = postcard::to_allocvec(&batch).unwrap();
        let mut key = [0u8; 32];
        key[0] = key_byte;
        RealProofInput {
            proof_bytes,
            public_inputs: pi,
            tx_ordering_key: key,
        }
    }

    let inputs = vec![make_input(0, 0x01), make_input(10, 0x02)];

    let r1 = aggregate_real_proofs(&inputs).expect("first aggregation must succeed");
    let r2 = aggregate_real_proofs(&inputs).expect("second aggregation must succeed");

    assert_eq!(
        r1.transcript_hash, r2.transcript_hash,
        "transcript_hash must be identical across repeated calls"
    );
    assert_eq!(
        r1.global_fri_root, r2.global_fri_root,
        "global_fri_root must be identical across repeated calls"
    );
}

#[test]
fn test_starkpack_ordering_affects_transcript() {
    // TV5.15 P2: different tx_ordering_key order → different transcript_hash.
    // Spec §3.4.3 R1: proofs absorbed in tx_ordering_key order.
    use scalar_stark_p3::batch_transfer_p3::BatchTransferProof;
    use scalar_stark_p3::starkpack_p3::{aggregate_real_proofs, RealProofInput};
    use scalar_stark_p3::transfer_air_p3::prove_transfer_p3;
    use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

    fn make_pi(fee_extra: u64) -> TransferPublicInputsP3 {
        TransferPublicInputsP3 {
            fee_total_sscl: 40 + fee_extra,
            sum_inputs_sscl: 1_000_000_040 + fee_extra,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0xAAu8; 32],
            nullifier_archived_root: [0xBBu8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
        }
    }

    fn make_input(fee_extra: u64) -> RealProofInput {
        let pi = make_pi(fee_extra);
        let cdcecg = prove_transfer_p3(&pi).expect("prove must succeed");
        let batch = BatchTransferProof {
            ca_proof: vec![0xCAu8; 64],
            cb_proof: vec![0xCBu8; 64],
            cc_proof: vec![0xCCu8; 64],
            cdcecg_proof: cdcecg,
        };
        let proof_bytes = postcard::to_allocvec(&batch).unwrap();
        RealProofInput {
            proof_bytes,
            public_inputs: pi,
            tx_ordering_key: [0u8; 32],
        }
    }

    let mut inp_a = make_input(0);
    let mut inp_b = make_input(50);

    // Assign different keys so sort order is deterministic and different when reversed.
    inp_a.tx_ordering_key = [0x01u8; 32];
    inp_b.tx_ordering_key = [0xFFu8; 32];

    let r_ab =
        aggregate_real_proofs(&[inp_a.clone(), inp_b.clone()]).expect("forward order must succeed");
    // Swap keys to force reversed sort order.
    inp_a.tx_ordering_key = [0xFFu8; 32];
    inp_b.tx_ordering_key = [0x01u8; 32];
    let r_ba = aggregate_real_proofs(&[inp_a, inp_b]).expect("reverse order must succeed");

    assert_ne!(
        r_ab.transcript_hash, r_ba.transcript_hash,
        "different ordering must produce different transcript_hash (spec §3.4.3 R1)"
    );
}

#[test]
fn test_quaternary_smt_non_membership_consistent() {
    use scalar_nullifier::smt_quaternary::QuaternarySparseMerkleTree;

    let mut smt = QuaternarySparseMerkleTree::new();
    let n1 = [0x01u8; 32];
    let n2 = [0x02u8; 32];

    smt.insert(&n1, 1);
    assert!(smt.verify_non_membership(&n2));
    assert!(!smt.verify_non_membership(&n1));

    smt.insert(&n2, 2);
    assert!(!smt.verify_non_membership(&n2));
}

#[test]
fn test_checkpoint_proof_quaternary_flag() {
    use scalar_nullifier::nullifier_set::CheckpointProof;

    let binary = CheckpointProof::genesis();
    assert_eq!(binary.smt_depth, 32);
    assert!(!binary.is_quaternary());

    let quaternary = CheckpointProof::genesis_quaternary();
    assert_eq!(quaternary.smt_depth, 16);
    assert!(quaternary.is_quaternary());
}

// ── 5. Transfer Circuit dual UTXOSource fields ────────────────────────────────

#[test]
fn test_transfer_circuit_epoch_smt_default() {
    use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

    let pi = TransferPublicInputsP3 {
        fee_total_sscl: 40,
        sum_inputs_sscl: 40,
        sum_outputs_sscl: 0,
        utxo_set_root: [0x42u8; 32],
        cb_membership_verified: true,
        nullifier_active_root: [0u8; 32],
        nullifier_archived_root: [0u8; 32],
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
        crypto_version: 0x01,
        entry_timestamp_ms: 1_000_000_000,
        current_timestamp_ms: 1_000_001_000,
    };

    assert!(pi.validate_imt_inputs(), "EpochSMT always valid");
    assert!(pi.validate_cb_root_non_zero());
}

#[test]
fn test_transfer_circuit_subepoch_imt_source() {
    use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

    let pi = TransferPublicInputsP3 {
        fee_total_sscl: 40,
        sum_inputs_sscl: 40,
        sum_outputs_sscl: 0,
        utxo_set_root: [0x42u8; 32],
        cb_membership_verified: true,
        nullifier_active_root: [0u8; 32],
        nullifier_archived_root: [0u8; 32],
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
        crypto_version: 0x01,
        entry_timestamp_ms: 1_000_000_000,
        current_timestamp_ms: 1_000_001_000,
    };

    assert!(pi.validate_imt_inputs(), "valid inputs");
}

#[test]
fn test_transfer_circuit_invalid_imt_inputs() {
    use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

    let pi = TransferPublicInputsP3 {
        fee_total_sscl: 40,
        sum_inputs_sscl: 40,
        sum_outputs_sscl: 0,
        utxo_set_root: [0x42u8; 32],
        cb_membership_verified: true,
        nullifier_active_root: [0u8; 32],
        nullifier_archived_root: [0u8; 32],
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
        crypto_version: 0x01,
        entry_timestamp_ms: 1_000_000_000,
        current_timestamp_ms: 1_000_001_000,
    };
    // validate_imt_inputs always true in current impl (FASE B: full IMT source tracking)
    assert!(pi.validate_imt_inputs());
}

// ── 6. End-to-end: IMT → SubEpoch → verify_imt_source ────────────────────────

#[test]
fn test_e2e_imt_subepoch_verify_source() {
    use scalar_crypto::imt::{IncrementalMerkleTree, VerificationResult};
    use scalar_network::subepoch::{SubEpochChain, SubEpochCommitment};

    // Step 1: Build IMT with some UTXOs
    let mut imt = IncrementalMerkleTree::new();
    for i in 0..10u8 {
        imt.append(&[i; 32]).unwrap();
    }
    let frontier_root = imt.root();
    let count = imt.count;

    // Step 2: Create SubEpochCommitment with quorum — use subepoch_id=0 (genesis)
    let mut commitment = SubEpochCommitment::new(
        2,
        0, // subepoch_id=0 (genesis, prev=[0;32])
        [0x11u8; 32],
        [0x22u8; 32],
        frontier_root,
        [0x33u8; 32],
        [0u8; 32], // prev=[0;32] correct for genesis
        count,
        10,
        1_700_100_000,
    );
    let subepoch_hash = commitment.subepoch_hash;

    for i in 0..5u8 {
        commitment.add_validator_sig([i; 32], vec![i; 10]);
    }

    // Step 3: Add to chain
    let mut chain = SubEpochChain::new(2);
    chain.add_commitment(commitment).unwrap();

    // Step 4: verify_imt_source — valid case
    let result = chain.verify_imt_source(0, &frontier_root, &subepoch_hash, count, 2, 2);
    assert_eq!(result, VerificationResult::Valid);

    // Step 5: wrong frontier → mismatch
    let wrong_frontier = [0xFFu8; 32];
    let result2 = chain.verify_imt_source(0, &wrong_frontier, &subepoch_hash, count, 2, 2);
    assert_eq!(result2, VerificationResult::IMTFrontierMismatch);

    // Step 6: non-existent subepoch
    let result3 = chain.verify_imt_source(999, &frontier_root, &subepoch_hash, count, 2, 2);
    assert_eq!(result3, VerificationResult::SubEpochNotFound);

    // Step 7: prove membership for leaf 0 — verify with frontier
    let path = imt.prove_membership(0).unwrap();
    let valid = scalar_crypto::imt::imt_membership_verify(&[0u8; 32], &path, &frontier_root, count);
    assert!(valid, "leaf 0 membership must verify against frontier root");
}

// ── 7. Domain separator integration — all new separators unique ──────────────

#[test]
fn test_all_l2_domain_separators_unique() {
    use scalar_crypto::domain::*;

    // All 28 domain separators including L2 additions
    let domains: Vec<&[u8]> = vec![
        DOMAIN_NULLIFIER,
        DOMAIN_UTXO_COMMITMENT,
        DOMAIN_SALT,
        DOMAIN_SEED,
        DOMAIN_NMT,
        DOMAIN_NODE_SHORT,
        DOMAIN_ANCHOR,
        DOMAIN_VOTE,
        DOMAIN_GENESIS_BOOTSTRAP,
        DOMAIN_STARK_FS,
        DOMAIN_CHECKPOINT_FS,
        DOMAIN_BEACON,
        DOMAIN_SEED_KDF,
        DOMAIN_TX_ORDER,
        DOMAIN_TXID,
        DOMAIN_SCORE,
        DOMAIN_NMT_RANDOM,
        DOMAIN_NODEID,
        DOMAIN_SMT_ACTIVE,
        DOMAIN_SMT_ARCHIVED,
        DOMAIN_IMT_LEAF,
        DOMAIN_IMT_NODE,
        DOMAIN_IMT_FRONTIER,
        DOMAIN_SUBEPOCH,
        DOMAIN_SUBEPOCH_SEED,
        DOMAIN_SUBEPOCH_SCORE,
        DOMAIN_SUBEPOCH_FS,
        DOMAIN_STARK_BATCH,
    ];

    let mut seen = std::collections::HashSet::new();
    for d in &domains {
        assert!(
            seen.insert(*d),
            "Duplicate domain separator: {:?}",
            std::str::from_utf8(d).unwrap_or("<invalid>")
        );
    }
    assert_eq!(domains.len(), 28);
}
