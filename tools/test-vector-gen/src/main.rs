//! Test vector generator for GAP-16 Python verifier cross-check.
//! Outputs JSON test vectors from impl#1 (Rust/scalar-stark-p3).
//! [SCALAR-SECURITY §5.3 Tier 2]

use scalar_crypto::poseidon2_t8::{
    poseidon2_permute_t8, poseidon2_hash_chained, Poseidon2T8Hasher,
};
use std::io::Write;

fn main() {
    let mut vectors = Vec::new();

    // ── Poseidon2 permutation test vectors ────────────────────────────────
    // Zero input
    let input_zero = [0u64; 8];
    let out_zero = poseidon2_permute_t8(&input_zero);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_permute_t8",
        "input": input_zero,
        "output": out_zero,
        "note": "zero state"
    }));

    // Identity-like input
    let input_seq: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let out_seq = poseidon2_permute_t8(&input_seq);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_permute_t8",
        "input": input_seq,
        "output": out_seq,
        "note": "sequential 1..8"
    }));

    // Goldilocks-max-adjacent input
    let p: u64 = (1u64 << 32).wrapping_sub(1);
    let input_max = [p, p-1, p-2, p-3, p-4, p-5, p-6, p-7];
    let out_max = poseidon2_permute_t8(&input_max);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_permute_t8",
        "input": input_max,
        "output": out_max,
        "note": "near-max Goldilocks values"
    }));

    // Domain separator inputs (from gossip.rs CF-PREMIUM)
    let domain_fee: u64 = u64::from_le_bytes(*b"scalar_f");
    let input_fee = [domain_fee, 12345u64, 40000u64, 0, 0, 0, 0, 0];
    let out_fee = poseidon2_permute_t8(&input_fee);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_permute_t8",
        "input": input_fee,
        "output": out_fee,
        "note": "CF-PREMIUM domain separator input"
    }));

    // ── Poseidon2 sponge (hash_chained) test vectors ──────────────────────
    // Single element
    let hc1 = poseidon2_hash_chained(&[42u64]);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_hash_chained",
        "input": [42u64],
        "output": hc1,
        "note": "single element"
    }));

    // 4 elements (one full rate block)
    let hc4 = poseidon2_hash_chained(&[1u64, 2, 3, 4]);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_hash_chained",
        "input": [1u64, 2, 3, 4],
        "output": hc4,
        "note": "one rate block (RATE=4)"
    }));

    // 8 elements (two rate blocks)
    let hc8 = poseidon2_hash_chained(&[10u64, 20, 30, 40, 50, 60, 70, 80]);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_hash_chained",
        "input": [10u64, 20, 30, 40, 50, 60, 70, 80],
        "output": hc8,
        "note": "two rate blocks"
    }));

    // commitment_hash simulation: 2 commitments × 4 u64 each = 8 u64
    let commit_elems: Vec<u64> = vec![
        0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
        0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x8888888888888888,
    ];
    let hc_commit = poseidon2_hash_chained(&commit_elems);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_hash_chained",
        "input": commit_elems,
        "output": hc_commit,
        "note": "commitment_hash simulation (2 commitments)"
    }));

    // ── Poseidon2T8Hasher::hash_to_4 ─────────────────────────────────────
    let ht4 = Poseidon2T8Hasher::hash_to_4(&[1u64, 2, 3, 4, 5]);
    vectors.push(serde_json::json!({
        "primitive": "poseidon2_hash_to_4",
        "input": [1u64, 2, 3, 4, 5],
        "output": ht4,
        "note": "hash_to_4 five elements"
    }));

    let result = serde_json::json!({
        "version": "1.0",
        "source": "scalar-stark-p3 impl#1 (Rust/Plonky3)",
        "spec": "SCALAR-SECURITY §[PROOF-PARAMS], §5.3",
        "vectors": vectors
    });

    let path = "verifier-py/tests/vectors/poseidon2_vectors.json";
    let mut f = std::fs::File::create(path).expect("create vector file");
    let json = serde_json::to_string_pretty(&result).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("Written: {path}");
    println!("Vectors: {}", result["vectors"].as_array().unwrap().len());
}
