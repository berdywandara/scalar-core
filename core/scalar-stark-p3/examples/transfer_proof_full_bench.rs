// examples/transfer_proof_full_bench.rs
// B1.1-FULL: Full BatchTransferProof (CA+CB+CC+CD/CE/CG) latency
//
// Run:
//   cargo run --release -p scalar-stark-p3 --example transfer_proof_full_bench \
//     2>&1 | tee -a benchmark_raw_$(date +%Y%m%d).txt

use scalar_stark_p3::batch_transfer_p3::{
    build_bench_transfer_input, prove_batch_transfer, verify_batch_transfer,
};
use std::time::Instant;

const RUNS: usize = 5;
const WARMUP: usize = 1;

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}
fn p95(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)]
}

fn main() {
    println!("B1.1-FULL: Full BatchTransferProof (CA+CB+CC+CD/CE/CG)");
    println!("Runs    : {} (+{} warmup)", RUNS, WARMUP);
    println!(
        "Cores   : {}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!();

    println!("Building witnesses...");
    let (witnesses, claims, _root) =
        build_bench_transfer_input(1).expect("build_bench_transfer_input failed");
    println!("  OK.");

    // Warmup
    print!("Warmup ({} run)... ", WARMUP);
    let _ = std::io::Write::flush(&mut std::io::stdout());
    for _ in 0..WARMUP {
        let _ = prove_batch_transfer(&witnesses, &claims).expect("prove failed");
    }
    println!("done.");

    // Prove benchmark
    println!("Benchmarking prove ({} runs)...", RUNS);
    let mut prove_ms: Vec<u64> = Vec::with_capacity(RUNS);
    let mut last_proof = None;
    for _ in 0..RUNS {
        let t = Instant::now();
        let proof = prove_batch_transfer(&witnesses, &claims).expect("prove failed");
        prove_ms.push(t.elapsed().as_millis() as u64);
        last_proof = Some(proof);
    }

    // Verify benchmark
    println!("Benchmarking verify ({} runs)...", RUNS);
    let proof = last_proof.unwrap();
    let mut verify_ms: Vec<u64> = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t = Instant::now();
        verify_batch_transfer(&proof, &claims).expect("verify failed");
        verify_ms.push(t.elapsed().as_millis() as u64);
    }

    // Proof sizes
    let ca_kb = proof.ca_proof.len() / 1024;
    let cb_kb = proof.cb_proof.len() / 1024;
    let cc_kb = proof.cc_proof.len() / 1024;
    let cg_kb = proof.cdcecg_proof.len() / 1024;
    let total_kb = ca_kb + cb_kb + cc_kb + cg_kb;

    let prove_med = median(prove_ms.clone());
    let prove_p95 = p95(prove_ms);
    let verify_med = median(verify_ms.clone());
    let verify_p95 = p95(verify_ms);

    println!();
    println!("=== B1.1-FULL RESULTS ===");
    println!("prove_median_ms    : {}", prove_med);
    println!("prove_p95_ms       : {}", prove_p95);
    println!("verify_median_ms   : {}", verify_med);
    println!("verify_p95_ms      : {}", verify_p95);
    println!("proof_ca_kb        : {}", ca_kb);
    println!("proof_cb_kb        : {}", cb_kb);
    println!("proof_cc_kb        : {}", cc_kb);
    println!("proof_cdcecg_kb    : {}", cg_kb);
    println!("proof_total_kb     : {}", total_kb);
    println!();

    let timeout_s = 300u64;
    let prove_s = prove_med as f64 / 1000.0;
    let max_tx = (timeout_s as f64 / prove_s).floor() as u64;
    let trigger_tx = max_tx.min(50);

    println!("=== PARAM-B + PARAM-C (full proof) ===");
    println!("proof_time_s              : {:.3}", prove_s);
    println!(
        "subepoch_duration_s       : {:.0} ({:.1} min)",
        prove_s * 5.0 * 100.0,
        prove_s * 5.0 * 100.0 / 60.0
    );
    println!("max_tx_in_300s            : {}", max_tx);
    println!(
        "MICROCOMMITMENT_TRIGGER_TX: {} (min(max_tx, 50))",
        trigger_tx
    );
    println!();
    println!("=== IMPACT ===");
    println!("B1.1-FULL vs B1.1 sub-AIR:");
    println!(
        "  Full={}ms vs CD/CE/CG-only=1075ms — overhead = {}ms (CA+CB+CC)",
        prove_med,
        prove_med.saturating_sub(1075)
    );
    println!(
        "D-023: full proof {}ms — {} tx fit in 300s timeout.",
        prove_med, max_tx
    );
    println!("D-025: total proof {}KB across 4 sub-AIRs.", total_kb);
}
