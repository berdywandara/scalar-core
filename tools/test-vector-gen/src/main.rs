//! Test vector generator for GAP-16 Python verifier cross-check.
//! [SCALAR-SECURITY §5.3 Tier 2]

use p3_field::extension::{CubicTrinomialExtensionField, HasFrobenius};
use p3_field::RawDataSerializable;
use p3_field::Field;
use p3_goldilocks::Goldilocks as GL;
use scalar_crypto::{
    imt::IncrementalMerkleTree,
    poseidon2_t8::{poseidon2_hash_chained, poseidon2_permute_t8, Poseidon2T8Hasher},
};
use scalar_nullifier::smt_quaternary::{
    hash_qsmt_leaf, hash_qsmt_node, QuaternarySparseMerkleTree, QSMT_ARITY,
};
type EF = CubicTrinomialExtensionField<GL>;
fn ef(a0: u64, a1: u64, a2: u64) -> EF {
    EF::new([GL::new(a0), GL::new(a1), GL::new(a2)])
}
fn ef_u(e: EF) -> [u64; 3] {
    // Extract via into_bytes then reinterpret as u64 LE
    use p3_field::RawDataSerializable;
    let bytes: Vec<u8> = e.into_bytes().into_iter().collect();
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i*8..(i+1)*8].try_into().unwrap()))
}
use scalar_stark_p3::transfer_public_inputs::{
    check_all_constraints, TransferPublicInputsP3, FEE_FLOOR_SSCL, VALID_CRYPTO_VERSION,
};
use std::io::Write;

fn pi(
    fee: u64,
    sum_in: u64,
    sum_out: u64,
    version: u64,
    cur_sub: u64,
    tgt_sub: u64,
    cb: bool,
    cc: bool,
    out_nz: bool,
    single: bool,
) -> TransferPublicInputsP3 {
    TransferPublicInputsP3 {
        fee_total_sscl: fee,
        sum_inputs_sscl: sum_in,
        sum_outputs_sscl: sum_out,
        crypto_version: version,
        current_subepoch_id: cur_sub,
        target_subepoch_id: tgt_sub,
        utxo_set_root: [0x42u8; 32],
        cb_membership_verified: cb,
        nullifier_active_root: [0u8; 32],
        nullifier_archived_root: [0u8; 32],
        cc_nonmembership_verified: cc,
        output_nonzero: out_nz,
        single_utxo_source: single,
        commitment_hash: [0u64; 4],
        nullifier_hash: [0u64; 4],
    }
}

fn pi_to_json(p: &TransferPublicInputsP3) -> serde_json::Value {
    serde_json::json!({
        "fee_total_sscl": p.fee_total_sscl,
        "sum_inputs_sscl": p.sum_inputs_sscl,
        "sum_outputs_sscl": p.sum_outputs_sscl,
        "crypto_version": p.crypto_version,
        "current_subepoch_id": p.current_subepoch_id,
        "target_subepoch_id": p.target_subepoch_id,
        "cb_membership_verified": p.cb_membership_verified,
        "cc_nonmembership_verified": p.cc_nonmembership_verified,
        "output_nonzero": p.output_nonzero,
        "single_utxo_source": p.single_utxo_source,
    })
}

fn main() {
    // ── Poseidon2 ─────────────────────────────────────────────────────────
    let mut p2_vecs: Vec<serde_json::Value> = Vec::new();
    for (note, inp) in [
        ("zero state", vec![0u64; 8]),
        ("sequential 1..8", vec![1, 2, 3, 4, 5, 6, 7, 8]),
        (
            "near-max",
            vec![
                0xFFFF_FFFFu64,
                0xFFFF_FFFE,
                0xFFFF_FFFD,
                0xFFFF_FFFC,
                0xFFFF_FFFB,
                0xFFFF_FFFA,
                0xFFFF_FFF9,
                0xFFFF_FFF8,
            ],
        ),
        (
            "CF-PREMIUM",
            vec![
                u64::from_le_bytes(*b"scalar_f"),
                12345,
                40000,
                0,
                0,
                0,
                0,
                0,
            ],
        ),
    ] {
        let a: [u64; 8] = inp.try_into().unwrap();
        p2_vecs.push(serde_json::json!({"primitive":"poseidon2_permute_t8",
            "input":a,"output":poseidon2_permute_t8(&a),"note":note}));
    }
    for (note, inp) in [
        ("single", vec![42u64]),
        ("rate-4", vec![1u64, 2, 3, 4]),
        ("two-block", vec![10u64, 20, 30, 40, 50, 60, 70, 80]),
        (
            "commit-sim",
            vec![
                0x1111111111111111u64,
                0x2222222222222222,
                0x3333333333333333,
                0x4444444444444444,
                0x5555555555555555,
                0x6666666666666666,
                0x7777777777777777,
                0x8888888888888888,
            ],
        ),
    ] {
        p2_vecs.push(serde_json::json!({"primitive":"poseidon2_hash_chained",
            "input":inp.clone(),"output":poseidon2_hash_chained(&inp),"note":note}));
    }
    let h4 = Poseidon2T8Hasher::hash_to_4(&[1u64, 2, 3, 4, 5]);
    p2_vecs.push(serde_json::json!({"primitive":"poseidon2_hash_to_4",
        "input":[1u64,2,3,4,5],"output":h4,"note":"hash_to_4 five elements"}));
    write_json("verifier-py/tests/vectors/poseidon2_vectors.json", &p2_vecs);

    // ── IMT ───────────────────────────────────────────────────────────────
    let mut imt_vecs: Vec<serde_json::Value> = Vec::new();
    let mut imt = IncrementalMerkleTree::new();
    imt_vecs.push(serde_json::json!({"primitive":"imt_root","leaves":[],"root_hex":hex::encode(imt.root()),"note":"empty IMT"}));
    let leaf0 = [0x42u8; 32];
    imt.append(&leaf0).unwrap();
    imt_vecs.push(serde_json::json!({"primitive":"imt_root","leaves":[hex::encode(leaf0)],"root_hex":hex::encode(imt.root()),"note":"1 leaf"}));
    let leaf1 = [0xABu8; 32];
    imt.append(&leaf1).unwrap();
    let root2 = imt.root();
    imt_vecs.push(serde_json::json!({"primitive":"imt_root","leaves":[hex::encode(leaf0),hex::encode(leaf1)],"root_hex":hex::encode(root2),"note":"2 leaves"}));
    for idx in 0u64..2 {
        let path = imt.prove_membership(idx).unwrap();
        let leaf = if idx == 0 { leaf0 } else { leaf1 };
        imt_vecs.push(serde_json::json!({"primitive":"imt_membership","leaf_hex":hex::encode(leaf),"leaf_index":idx,"root_hex":hex::encode(root2),"siblings":path.siblings.iter().map(hex::encode).collect::<Vec<_>>(),"note":format!("membership leaf {idx}")}));
    }
    let leaf2 = [0xCDu8; 32];
    let leaf3 = [0xEFu8; 32];
    imt.append(&leaf2).unwrap();
    imt.append(&leaf3).unwrap();
    let root4 = imt.root();
    imt_vecs.push(serde_json::json!({"primitive":"imt_root","leaves":[hex::encode(leaf0),hex::encode(leaf1),hex::encode(leaf2),hex::encode(leaf3)],"root_hex":hex::encode(root4),"note":"4 leaves"}));
    for idx in 0u64..4 {
        let path = imt.prove_membership(idx).unwrap();
        let leaf = [leaf0, leaf1, leaf2, leaf3][idx as usize];
        imt_vecs.push(serde_json::json!({"primitive":"imt_membership","leaf_hex":hex::encode(leaf),"leaf_index":idx,"root_hex":hex::encode(root4),"siblings":path.siblings.iter().map(hex::encode).collect::<Vec<_>>(),"note":format!("membership leaf {idx} in 4-leaf tree")}));
    }
    write_json("verifier-py/tests/vectors/imt_vectors.json", &imt_vecs);

    // ── QSMT ─────────────────────────────────────────────────────────────
    let mut qsmt_vecs: Vec<serde_json::Value> = Vec::new();
    let empty_ch = [[0u8; 32]; QSMT_ARITY];
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_node_hash","children":empty_ch.iter().map(hex::encode).collect::<Vec<_>>(),"output_hex":hex::encode(hash_qsmt_node(&empty_ch)),"note":"all-zero children"}));
    let mut ch1 = [[0u8; 32]; QSMT_ARITY];
    ch1[0] = [0xAAu8; 32];
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_node_hash","children":ch1.iter().map(hex::encode).collect::<Vec<_>>(),"output_hex":hex::encode(hash_qsmt_node(&ch1)),"note":"one non-zero child"}));
    for (note, null, epoch) in [
        ("leaf 0x11 epoch=0", [0x11u8; 32], 0u64),
        ("leaf 0x11 epoch=42", [0x11u8; 32], 42u64),
        ("leaf 0xAA epoch=1", [0xAAu8; 32], 1u64),
    ] {
        qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_leaf_hash","nullifier_hex":hex::encode(null),"epoch_id":epoch,"output_hex":hex::encode(hash_qsmt_leaf(&null,epoch)),"note":note}));
    }
    let mut qsmt = QuaternarySparseMerkleTree::new();
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_root","inserted":[],"root_hex":hex::encode(qsmt.root),"note":"empty QSMT"}));
    let null0 = [0x11u8; 32];
    qsmt.insert(&null0, 1);
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_root","inserted":[{"hex":hex::encode(null0),"epoch":1u64}],"root_hex":hex::encode(qsmt.root),"note":"1 insert"}));
    let null1 = [0x22u8; 32];
    qsmt.insert(&null1, 2);
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_root","inserted":[{"hex":hex::encode(null0),"epoch":1u64},{"hex":hex::encode(null1),"epoch":2u64}],"root_hex":hex::encode(qsmt.root),"note":"2 inserts"}));
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_contains","nullifier_hex":hex::encode(null0),"expected":true,"note":"null0 in tree"}));
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_contains","nullifier_hex":hex::encode([0x33u8;32]),"expected":false,"note":"null2 not in tree"}));
    write_json("verifier-py/tests/vectors/qsmt_vectors.json", &qsmt_vecs);

    // ── PI Constraint vectors (M3) ────────────────────────────────────────
    let mut pi_vecs: Vec<serde_json::Value> = Vec::new();

    let cases: Vec<(&str, TransferPublicInputsP3, bool)> = vec![
        // Valid cases
        (
            "valid: baseline",
            pi(
                40,
                1_000_000_040,
                1_000_000_000,
                VALID_CRYPTO_VERSION,
                1000,
                1000,
                true,
                true,
                true,
                true,
            ),
            true,
        ),
        (
            "valid: fee=floor exact",
            pi(
                FEE_FLOOR_SSCL,
                FEE_FLOOR_SSCL,
                0,
                VALID_CRYPTO_VERSION,
                5,
                5,
                true,
                true,
                true,
                true,
            ),
            true,
        ),
        (
            "valid: validity=1 (boundary spillover)",
            pi(
                40,
                1040,
                1000,
                VALID_CRYPTO_VERSION,
                101,
                100,
                true,
                true,
                true,
                true,
            ),
            true,
        ),
        (
            "valid: large values",
            pi(
                100,
                2_000_000_100,
                2_000_000_000,
                VALID_CRYPTO_VERSION,
                999,
                999,
                true,
                true,
                true,
                true,
            ),
            true,
        ),
        // Invalid cases
        (
            "invalid: CD conservation violated",
            pi(
                40,
                1_000_000_000,
                1_000_000_000,
                VALID_CRYPTO_VERSION,
                1000,
                1000,
                true,
                true,
                true,
                true,
            ),
            false,
        ),
        (
            "invalid: fee below floor",
            pi(
                39,
                1039,
                1000,
                VALID_CRYPTO_VERSION,
                1000,
                1000,
                true,
                true,
                true,
                true,
            ),
            false,
        ),
        (
            "invalid: wrong crypto_version",
            pi(40, 1040, 1000, 0x02, 1000, 1000, true, true, true, true),
            false,
        ),
        (
            "invalid: CG-ARITH stale (validity=2)",
            pi(
                40,
                1040,
                1000,
                VALID_CRYPTO_VERSION,
                102,
                100,
                true,
                true,
                true,
                true,
            ),
            false,
        ),
        (
            "invalid: CG-ARITH order violation (current < target)",
            pi(
                40,
                1040,
                1000,
                VALID_CRYPTO_VERSION,
                99,
                100,
                true,
                true,
                true,
                true,
            ),
            false,
        ),
        (
            "invalid: CB not verified",
            pi(
                40,
                1040,
                1000,
                VALID_CRYPTO_VERSION,
                1000,
                1000,
                false,
                true,
                true,
                true,
            ),
            false,
        ),
        (
            "invalid: CC not verified",
            pi(
                40,
                1040,
                1000,
                VALID_CRYPTO_VERSION,
                1000,
                1000,
                true,
                false,
                true,
                true,
            ),
            false,
        ),
        (
            "invalid: output is zero",
            pi(
                40,
                1040,
                1000,
                VALID_CRYPTO_VERSION,
                1000,
                1000,
                true,
                true,
                false,
                true,
            ),
            false,
        ),
        (
            "invalid: dual UTXO source",
            pi(
                40,
                1040,
                1000,
                VALID_CRYPTO_VERSION,
                1000,
                1000,
                true,
                true,
                true,
                false,
            ),
            false,
        ),
    ];

    for (note, p, expect_valid) in &cases {
        let result = check_all_constraints(p);
        let got_valid = result.is_ok();
        let fail_idx = result.err();
        pi_vecs.push(serde_json::json!({
            "primitive": "pi_check_all_constraints",
            "pi": pi_to_json(p),
            "expected_valid": expect_valid,
            "got_valid": got_valid,
            "fail_constraint_idx": fail_idx,
            "note": note,
        }));
    }
    write_json(
        "verifier-py/tests/vectors/pi_constraint_vectors.json",
        &pi_vecs,
    );

    // ── GF(p^3) extension field vectors (M4a) ──────────────────────────────
    let mut ef_vecs: Vec<serde_json::Value> = Vec::new();
    let p: u64 = 0xFFFF_FFFF;
    for (note, a, b) in [
        &("mul [1,2,3]x[4,5,6]", [1u64, 2, 3], [4u64, 5, 6]),
        &("mul [1,2,3]x[7,0,0]", [1u64, 2, 3], [7u64, 0, 0]),
        &("square [1,2,3]", [1u64, 2, 3], [1u64, 2, 3]),
        &("mul [p,p-1,p-2]x[3,7,11]", [p, p - 1, p - 2], [3u64, 7, 11]),
        &("mul [0,0,1]x[0,0,1]", [0u64, 0, 1], [0u64, 0, 1]),
        &("mul identity", [1u64, 0, 0], [4u64, 5, 6]),
    ] {
        let ea = ef(a[0], a[1], a[2]);
        let eb = ef(b[0], b[1], b[2]);
        ef_vecs.push(
            serde_json::json!({"primitive":"ef_mul","a":a,"b":b,"result":ef_u(ea*eb),"note":note}),
        );
    }
    ef_vecs.push(serde_json::json!({"primitive":"ef_add","a":[1u64,2,3],"b":[4u64,5,6],"result":ef_u(ef(1,2,3)+ef(4,5,6)),"note":"add [1,2,3]+[4,5,6]"}));
    ef_vecs.push(serde_json::json!({"primitive":"ef_add","a":[p,p,p],"b":[1u64,1,1],"result":ef_u(ef(p,p,p)+ef(1,1,1)),"note":"add [p,p,p]+[1,1,1]"}));
    for (note, a) in [
        ("inv [1,2,3]", [1u64, 2, 3]),
        ("inv [7,0,0]", [7u64, 0, 0]),
        ("inv [p,p-1,p-2]", [p, p - 1, p - 2]),
    ] {
        let ea = ef(a[0], a[1], a[2]);
        let inv = ea.inverse();
        ef_vecs.push(serde_json::json!({"primitive":"ef_inv","a":a,"result":ef_u(inv),"verify":ef_u(ea*inv),"note":note}));
    }
    for (note, a) in [
        ("frobenius [1,2,3]", [1u64, 2, 3]),
        ("frobenius [0,1,0]", [0u64, 1, 0]),
    ] {
        let ea = ef(a[0], a[1], a[2]);
        ef_vecs.push(serde_json::json!({"primitive":"ef_frobenius","a":a,"result":ef_u(ea.frobenius()),"note":note}));
    }
    write_json("verifier-py/tests/vectors/ef_vectors.json", &ef_vecs);
    println!(
        "Done: {} p2, {} imt, {} qsmt, {} pi vectors",
        p2_vecs.len(),
        imt_vecs.len(),
        qsmt_vecs.len(),
        pi_vecs.len()
    );
}

fn write_json(path: &str, vecs: &[serde_json::Value]) {
    let doc = serde_json::json!({"version":"2.0","source":"scalar impl#1 (Rust)","vectors":vecs});
    let mut f = std::fs::File::create(path).expect("create");
    f.write_all(serde_json::to_string_pretty(&doc).unwrap().as_bytes())
        .unwrap();
    println!("Written: {path} ({} vectors)", vecs.len());
}
// Note: perlu tambah ke main() — tulis ulang
