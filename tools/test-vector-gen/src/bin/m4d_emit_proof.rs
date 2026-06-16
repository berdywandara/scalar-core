//! GAP-16 M4D-1: emit a REAL prove_transfer_p3() proof as JSON.
//!
//! This binary calls prove_transfer_p3() (impl#1's real prover), takes the
//! postcard-serialized proof bytes it returns, deserializes them back into
//! the actual Proof<ScalarStarkConfig> struct (the SAME struct
//! verify_transfer_p3() consumes -- no alternate code path), and re-emits
//! that struct as JSON via serde_json.
//!
//! This is the PUBLIC PROOF ARTIFACT -- the object a verifier (including
//! impl#2 Python) is entitled to read. No witness/private data is exposed
//! here beyond what's already in the public proof. [SCALAR-SECURITY §5.3, P4]
//!
//! JSON shape notes (proven by m4d_roundtrip.rs round-trip test):
//!   - Goldilocks (u64 internally) -> JSON integer, canonical value, no precision loss.
//!   - EF = ExtField<F,3,...> -> JSON OBJECT {"value": [a0,a1,a2], "_phantom": null},
//!     NOT a bare array. Parsers must index ["value"]["value"] and ignore "_phantom".
//!   - MerkleCap<F,Digest> -> JSON OBJECT {"cap": [...digests...], "_marker": null}
//!     (same PhantomData pattern as ExtField).
//!   - Option<T>::None -> JSON null. Option<T>::Some(v) -> v serialized directly
//!     (no [1, v] tag wrapper like postcard; this is serde_json's standard behavior).

use p3_uni_stark::Proof;
use scalar_stark_p3::config::ScalarStarkConfig;
use scalar_stark_p3::transfer_air_p3::prove_transfer_p3;
use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;
use std::io::Write;

fn valid_pi() -> TransferPublicInputsP3 {
    // Mirrors transfer_air_p3.rs test module's valid_pi() exactly, so the
    // proof we emit here corresponds to a known, already-tested-valid PI.
    TransferPublicInputsP3 {
        fee_total_sscl: 40,
        sum_inputs_sscl: 1_000_000_040,
        sum_outputs_sscl: 1_000_000_000,
        crypto_version: 0x01,
        current_subepoch_id: 1_000,
        target_subepoch_id: 1_000,
        utxo_set_root: [0x42u8; 32],
        cb_membership_verified: true,
        nullifier_active_root: [0xAAu8; 32],
        nullifier_archived_root: [0xBBu8; 32],
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
        commitment_hash: [0u64; 4],
        nullifier_hash: [0u64; 4],
    }
}

fn main() {
    println!("GAP-16 M4D-1: emitting real prove_transfer_p3() proof as JSON");

    let pi = valid_pi();

    println!("Calling prove_transfer_p3() (this is impl#1's real prover)...");
    let proof_bytes = prove_transfer_p3(&pi).expect("prove_transfer_p3 must succeed for valid_pi");
    println!(
        "Proof generated: {} bytes (postcard-encoded)",
        proof_bytes.len()
    );

    // Deserialize back into the SAME Proof<ScalarStarkConfig> struct that
    // verify_transfer_p3() consumes -- no alternate/simplified representation.
    let proof: Proof<ScalarStarkConfig> =
        postcard::from_bytes(&proof_bytes).expect("postcard deserialize must succeed");
    println!("Deserialized into Proof<ScalarStarkConfig> struct.");

    // Re-emit as JSON via serde_json -- proven lossless by m4d_roundtrip.rs
    // for the field element types involved (Goldilocks, EF).
    let json_value = serde_json::to_value(&proof).expect("serde_json::to_value must succeed");

    let output = serde_json::json!({
        "format_version": "M4D-1.0",
        "source": "scalar impl#1 (Rust/Plonky3) -- prove_transfer_p3() real proof",
        "note": "Public proof artifact only. Read-only consumption by impl#2 is sound under SCALAR-SECURITY section 5.3 P4 independence -- no impl#1 verification logic was called to produce this; this IS the object being verified.",
        "public_inputs": {
            "fee_total_sscl": pi.fee_total_sscl,
            "sum_inputs_sscl": pi.sum_inputs_sscl,
            "sum_outputs_sscl": pi.sum_outputs_sscl,
            "crypto_version": pi.crypto_version,
            "current_subepoch_id": pi.current_subepoch_id,
        },
        "proof": json_value,
    });

    let path = "verifier-py/tests/vectors/m4d_real_proof.json";
    let mut f = std::fs::File::create(path).expect("create output file");
    f.write_all(serde_json::to_string_pretty(&output).unwrap().as_bytes())
        .expect("write output file");

    println!("Written: {} ", path);

    // Sanity print: top-level proof structure keys, to confirm shape before
    // any Python parsing is attempted.
    if let Some(obj) = json_value.as_object() {
        println!(
            "Top-level proof JSON keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        if let Some(opening_proof) = obj.get("opening_proof") {
            if let Some(op_obj) = opening_proof.as_object() {
                println!(
                    "opening_proof (FriProof) keys: {:?}",
                    op_obj.keys().collect::<Vec<_>>()
                );
                if let Some(commits) = op_obj.get("commit_phase_commits") {
                    if let Some(arr) = commits.as_array() {
                        println!("commit_phase_commits: {} round(s)", arr.len());
                        if let Some(first) = arr.first() {
                            println!("First commit_phase_commits[0] shape: {}", first);
                        }
                    }
                }
            }
        }
    }
}
