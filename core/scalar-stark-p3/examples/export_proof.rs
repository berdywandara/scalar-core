//! Export proof artifacts untuk interop test impl#2.
use scalar_stark_p3::batch_transfer_p3::{build_bench_transfer_input, prove_batch_transfer};
use std::fmt::Write as FmtWrite;
use std::fs;

fn main() {
    fs::create_dir_all("proofs").unwrap();

    println!("Building witnesses...");
    let (witnesses, claims, _root) = build_bench_transfer_input(1).expect("build failed");

    println!("Proving...");
    let proof = prove_batch_transfer(&witnesses, &claims).expect("prove failed");

    // Export CA proof (ownership sub-AIR)
    fs::write("proofs/transfer_ca.proof.bin", &proof.ca_proof).unwrap();
    fs::write("proofs/transfer_cb.proof.bin", &proof.cb_proof).unwrap();
    fs::write("proofs/transfer_cc.proof.bin", &proof.cc_proof).unwrap();
    fs::write("proofs/transfer_cdcecg.proof.bin", &proof.cdcecg_proof).unwrap();

    // Export Goldilocks field elements (44 elements)
    let pi = &claims.pi;
    let pi_fe = pi.to_goldilocks();
    use p3_field::PrimeField64;
    let pi_u64: Vec<u64> = pi_fe.iter().map(|fe| fe.as_canonical_u64()).collect();

    // Write JSON manually — no serde_json dep needed
    let mut json = String::from("[");
    for (i, v) in pi_u64.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        let _ = write!(json, "{v}");
    }
    json.push(']');
    fs::write("proofs/pi_field_elements.json", &json).unwrap();

    println!("=== PROOF ARTIFACTS EXPORTED ===");
    println!(
        "proofs/transfer_ca.proof.bin     {} bytes",
        proof.ca_proof.len()
    );
    println!(
        "proofs/transfer_cb.proof.bin     {} bytes",
        proof.cb_proof.len()
    );
    println!(
        "proofs/transfer_cc.proof.bin     {} bytes",
        proof.cc_proof.len()
    );
    println!(
        "proofs/transfer_cdcecg.proof.bin {} bytes",
        proof.cdcecg_proof.len()
    );
    println!("proofs/public_inputs.json        44 field elements");
    println!("proofs/pi_field_elements.json    raw u64 array");
    println!();
    println!("poseidon2_test_vector = {{");
    println!("    'input': [0] * 8,");
    println!("    'output': [4904961330882102773, 6914533505831728251,");
    println!("               16060085509051262978, 161169382960502813,");
    println!("               8610401995229161121, 6947968519022847962,");
    println!("               9668808541865791489, 7055543217974479047]");
    println!("}}");
}
