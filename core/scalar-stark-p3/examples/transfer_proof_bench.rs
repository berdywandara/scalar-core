// examples/transfer_proof_bench.rs
// B1.1: Transfer proof prove+verify latency — COMPLETE
//
// Run:
//   cargo run --release -p scalar-stark-p3 --example transfer_proof_bench \
//     2>&1 | tee -a benchmark_raw_$(date +%Y%m%d).txt

use scalar_stark_p3::transfer_air_p3::{prove_transfer_p3, verify_transfer_p3};
use scalar_stark_p3::transfer_public_inputs::{TransferPublicInputsP3, FEE_FLOOR_SSCL};
use std::time::Instant;

const RUNS: usize = 10;
const WARMUP: usize = 2;

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}
fn p95(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)]
}

/// Minimal valid TransferPublicInputsP3 for benchmarking.
fn make_pi(fee_extra: u64) -> TransferPublicInputsP3 {
    let fee = FEE_FLOOR_SSCL + fee_extra;
    let sum_inputs = 1_000_000_000 + fee;
    TransferPublicInputsP3 {
        fee_total_sscl: fee,
        sum_inputs_sscl: sum_inputs,
        sum_outputs_sscl: sum_inputs - fee,
        crypto_version: 0x01,
        current_subepoch_id: 1_000,
        target_subepoch_id: 1_000,
        utxo_set_root: [0x42u8; 32],
        cb_membership_verified: true,
        nullifier_active_root: [0x11u8; 32],
        nullifier_archived_root: [0x22u8; 32],
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
        commitment_hash: [0u64; 4],
        nullifier_hash: [0u64; 4],
    }
}

fn main() {
    println!("B1.1: Transfer Proof Prove+Verify Latency");
    println!("Runs    : {} (+{} warmup)", RUNS, WARMUP);
    println!(
        "Cores   : {}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!();

    let pi = make_pi(0);

    // Warmup
    print!("Warmup ({} runs)... ", WARMUP);
    let _ = std::io::Write::flush(&mut std::io::stdout());
    for _ in 0..WARMUP {
        let _ = prove_transfer_p3(&pi).expect("prove failed");
    }
    println!("done.");

    // Prove benchmark
    println!("Benchmarking prove ({} runs)...", RUNS);
    let mut prove_ms: Vec<u64> = Vec::with_capacity(RUNS);
    let mut last_proof = Vec::new();
    for _ in 0..RUNS {
        let t = Instant::now();
        last_proof = prove_transfer_p3(&pi).expect("prove failed");
        prove_ms.push(t.elapsed().as_millis() as u64);
    }

    // Verify benchmark
    println!("Benchmarking verify ({} runs)...", RUNS);
    let mut verify_ms: Vec<u64> = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t = Instant::now();
        verify_transfer_p3(&last_proof, &pi).expect("verify failed");
        verify_ms.push(t.elapsed().as_millis() as u64);
    }

    let prove_med = median(prove_ms.clone());
    let prove_p95 = p95(prove_ms);
    let verify_med = median(verify_ms.clone());
    let verify_p95 = p95(verify_ms);
    let proof_kb = last_proof.len() / 1024;

    println!();
    println!("=== B1.1 RESULTS ===");
    println!("prove_median_ms   : {}", prove_med);
    println!("prove_p95_ms      : {}", prove_p95);
    println!("verify_median_ms  : {}", verify_med);
    println!("verify_p95_ms     : {}", verify_p95);
    println!("proof_size_kb     : {}", proof_kb);
    println!();

    // PARAM-C recalc with real proof_time
    let timeout_s = 300u64;
    let prove_s = prove_med as f64 / 1000.0;
    let max_tx = (timeout_s as f64 / prove_s).floor() as u64;
    let trigger_tx = max_tx.min(50);

    println!("=== PARAM-C (with real proof_time) ===");
    println!("proof_time_s              : {:.3}", prove_s);
    println!("max_tx_in_300s            : {}", max_tx);
    println!(
        "MICROCOMMITMENT_TRIGGER_TX: {} (min(max_tx, 50))",
        trigger_tx
    );
    println!();
    println!("=== IMPACT ===");
    println!(
        "D-023: prove_median={}ms — primary MicroCommitment sizing parameter.",
        prove_med
    );
    println!(
        "D-024: verify_median={}ms — aggregator verification overhead.",
        verify_med
    );
    println!(
        "D-025: proof_size={}KB — network propagation budget.",
        proof_kb
    );
}
