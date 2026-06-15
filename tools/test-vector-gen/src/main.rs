//! Test vector generator for GAP-16 Python verifier cross-check.
//! [SCALAR-SECURITY §5.3 Tier 2]

use scalar_crypto::{
    imt::IncrementalMerkleTree,
    poseidon2_t8::{poseidon2_hash_chained, poseidon2_permute_t8, Poseidon2T8Hasher},
};
use scalar_nullifier::smt_quaternary::{
    hash_qsmt_leaf, hash_qsmt_node, QuaternarySparseMerkleTree, QSMT_ARITY,
};
use std::io::Write;

fn main() {
    // ── Poseidon2 ─────────────────────────────────────────────────────────
    let mut p2_vecs: Vec<serde_json::Value> = Vec::new();
    for (note, inp) in [
        ("zero state",       vec![0u64;8]),
        ("sequential 1..8",  vec![1,2,3,4,5,6,7,8]),
        ("near-max",         vec![0xFFFF_FFFFu64,0xFFFF_FFFE,0xFFFF_FFFD,0xFFFF_FFFC,
                                  0xFFFF_FFFB,0xFFFF_FFFA,0xFFFF_FFF9,0xFFFF_FFF8]),
        ("CF-PREMIUM",       vec![u64::from_le_bytes(*b"scalar_f"),12345,40000,0,0,0,0,0]),
    ] {
        let a: [u64;8] = inp.try_into().unwrap();
        p2_vecs.push(serde_json::json!({"primitive":"poseidon2_permute_t8",
            "input":a,"output":poseidon2_permute_t8(&a),"note":note}));
    }
    for (note, inp) in [
        ("single",    vec![42u64]),
        ("rate-4",    vec![1u64,2,3,4]),
        ("two-block", vec![10u64,20,30,40,50,60,70,80]),
        ("commit-sim",vec![0x1111111111111111u64,0x2222222222222222,
                           0x3333333333333333,0x4444444444444444,
                           0x5555555555555555,0x6666666666666666,
                           0x7777777777777777,0x8888888888888888]),
    ] {
        p2_vecs.push(serde_json::json!({"primitive":"poseidon2_hash_chained",
            "input":inp.clone(),"output":poseidon2_hash_chained(&inp),"note":note}));
    }
    let h4 = Poseidon2T8Hasher::hash_to_4(&[1u64,2,3,4,5]);
    p2_vecs.push(serde_json::json!({"primitive":"poseidon2_hash_to_4",
        "input":[1u64,2,3,4,5],"output":h4,"note":"hash_to_4 five elements"}));
    write_json("verifier-py/tests/vectors/poseidon2_vectors.json", &p2_vecs);

    // ── IMT ───────────────────────────────────────────────────────────────
    let mut imt_vecs: Vec<serde_json::Value> = Vec::new();
    let mut imt = IncrementalMerkleTree::new();

    imt_vecs.push(serde_json::json!({"primitive":"imt_root",
        "leaves":serde_json::Value::Array(vec![]),
        "root_hex":hex::encode(imt.root()),"note":"empty IMT"}));

    let leaf0 = [0x42u8;32];
    imt.append(&leaf0).unwrap();
    imt_vecs.push(serde_json::json!({"primitive":"imt_root",
        "leaves":[hex::encode(leaf0)],
        "root_hex":hex::encode(imt.root()),"note":"1 leaf"}));

    let leaf1 = [0xABu8;32];
    imt.append(&leaf1).unwrap();
    let root2 = imt.root();
    imt_vecs.push(serde_json::json!({"primitive":"imt_root",
        "leaves":[hex::encode(leaf0),hex::encode(leaf1)],
        "root_hex":hex::encode(root2),"note":"2 leaves"}));

    for idx in 0u64..2 {
        let path = imt.prove_membership(idx).unwrap();
        let leaf = if idx==0 { leaf0 } else { leaf1 };
        imt_vecs.push(serde_json::json!({"primitive":"imt_membership",
            "leaf_hex":hex::encode(leaf),"leaf_index":idx,
            "root_hex":hex::encode(root2),
            "siblings":path.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            "note":format!("membership leaf {idx}")}));
    }

    // 4-leaf tree
    let leaf2 = [0xCDu8;32];
    let leaf3 = [0xEFu8;32];
    imt.append(&leaf2).unwrap();
    imt.append(&leaf3).unwrap();
    let root4 = imt.root();
    imt_vecs.push(serde_json::json!({"primitive":"imt_root",
        "leaves":[hex::encode(leaf0),hex::encode(leaf1),
                  hex::encode(leaf2),hex::encode(leaf3)],
        "root_hex":hex::encode(root4),"note":"4 leaves"}));
    for idx in 0u64..4 {
        let path = imt.prove_membership(idx).unwrap();
        let leaf = [leaf0,leaf1,leaf2,leaf3][idx as usize];
        imt_vecs.push(serde_json::json!({"primitive":"imt_membership",
            "leaf_hex":hex::encode(leaf),"leaf_index":idx,
            "root_hex":hex::encode(root4),
            "siblings":path.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            "note":format!("membership leaf {idx} in 4-leaf tree")}));
    }
    write_json("verifier-py/tests/vectors/imt_vectors.json", &imt_vecs);

    // ── QSMT ─────────────────────────────────────────────────────────────
    let mut qsmt_vecs: Vec<serde_json::Value> = Vec::new();

    // hash_qsmt_node with all-zero children
    let empty_ch = [[0u8;32];QSMT_ARITY];
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_node_hash",
        "children":empty_ch.iter().map(hex::encode).collect::<Vec<_>>(),
        "output_hex":hex::encode(hash_qsmt_node(&empty_ch)),
        "note":"all-zero children"}));

    // hash_qsmt_node with one non-zero child
    let mut ch1 = [[0u8;32];QSMT_ARITY];
    ch1[0] = [0xAAu8;32];
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_node_hash",
        "children":ch1.iter().map(hex::encode).collect::<Vec<_>>(),
        "output_hex":hex::encode(hash_qsmt_node(&ch1)),
        "note":"one non-zero child at index 0"}));

    // hash_qsmt_leaf cases
    for (note, null, epoch) in [
        ("leaf 0x11*32 epoch=0",  [0x11u8;32], 0u64),
        ("leaf 0x11*32 epoch=42", [0x11u8;32], 42u64),
        ("leaf 0xAA*32 epoch=1",  [0xAAu8;32], 1u64),
    ] {
        qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_leaf_hash",
            "nullifier_hex":hex::encode(null),"epoch_id":epoch,
            "output_hex":hex::encode(hash_qsmt_leaf(&null, epoch)),
            "note":note}));
    }

    // QSMT root after inserts
    let mut qsmt = QuaternarySparseMerkleTree::new();
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_root",
        "inserted":[],"root_hex":hex::encode(qsmt.root),"note":"empty QSMT"}));

    let null0 = [0x11u8;32];
    qsmt.insert(&null0, 1);
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_root",
        "inserted":[{"hex":hex::encode(null0),"epoch":1u64}],
        "root_hex":hex::encode(qsmt.root),"note":"1 insert"}));

    let null1 = [0x22u8;32];
    qsmt.insert(&null1, 2);
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_root",
        "inserted":[{"hex":hex::encode(null0),"epoch":1u64},
                    {"hex":hex::encode(null1),"epoch":2u64}],
        "root_hex":hex::encode(qsmt.root),"note":"2 inserts"}));

    // contains check
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_contains",
        "nullifier_hex":hex::encode(null0),"expected":true,"note":"null0 in tree"}));
    qsmt_vecs.push(serde_json::json!({"primitive":"qsmt_contains",
        "nullifier_hex":hex::encode([0x33u8;32]),"expected":false,"note":"null2 not in tree"}));

    write_json("verifier-py/tests/vectors/qsmt_vectors.json", &qsmt_vecs);

    println!("Done: {} p2, {} imt, {} qsmt vectors",
        p2_vecs.len(), imt_vecs.len(), qsmt_vecs.len());
}

fn write_json(path: &str, vecs: &[serde_json::Value]) {
    let doc = serde_json::json!({"version":"2.0","source":"scalar impl#1 (Rust)","vectors":vecs});
    let mut f = std::fs::File::create(path).expect("create");
    f.write_all(serde_json::to_string_pretty(&doc).unwrap().as_bytes()).unwrap();
    println!("Written: {path} ({} vectors)", vecs.len());
}
