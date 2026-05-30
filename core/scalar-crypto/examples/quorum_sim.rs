// examples/quorum_sim.rs
// B4-SIM: Quorum formation simulation — COMPLETE, zero deps
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const VALIDATORS: usize = 10;
const QUORUM_THRESHOLD: usize = 7;
const SLHDSA_VERIFY_MS: u64 = 1; // B2.1 actual: verify_median=0.479ms → round up to 1ms

fn simulate(latency_ms: u64, runs: usize) -> Vec<u64> {
    let mut times = Vec::with_capacity(runs);
    for _ in 0..runs {
        let sigs = Arc::new(Mutex::new(0usize));
        let quorum: Arc<Mutex<Option<Duration>>> = Arc::new(Mutex::new(None));
        let start = Instant::now();
        let mut handles = Vec::new();
        for id in 0..VALIDATORS {
            let sigs = Arc::clone(&sigs);
            let quorum = Arc::clone(&quorum);
            let jitter = (id as u64 % 5) * (latency_ms / 5 + 1);
            let net = latency_ms + jitter;
            handles.push(thread::spawn(move || {
                thread::sleep(Duration::from_millis(net));
                thread::sleep(Duration::from_millis(SLHDSA_VERIFY_MS));
                thread::sleep(Duration::from_millis(net / 2));
                let mut c = sigs.lock().unwrap();
                *c += 1;
                if *c == QUORUM_THRESHOLD {
                    let mut q = quorum.lock().unwrap();
                    if q.is_none() {
                        *q = Some(start.elapsed());
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let q = quorum.lock().unwrap();
        times.push(q.unwrap_or_else(|| start.elapsed()).as_millis() as u64);
    }
    times
}

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}
fn p95(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)]
}

fn main() {
    println!("B4-SIM: Quorum Formation Simulation");
    println!(
        "Config  : {}/{} validators | SLH-DSA verify={}ms (placeholder)",
        QUORUM_THRESHOLD, VALIDATORS, SLHDSA_VERIFY_MS
    );
    println!();
    let conditions = [
        ("LOCAL", 1u64, 50usize),
        ("WAN_50", 50, 50),
        ("WAN_200", 200, 50),
    ];
    let mut results: Vec<(&str, u64, u64, u64)> = Vec::new();
    for (name, lat, runs) in &conditions {
        print!("  {} ({}ms, {} runs)... ", name, lat, runs);
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let times = simulate(*lat, *runs);
        let med = median(times.clone());
        let p95 = p95(times);
        println!("median={}ms p95={}ms", med, p95);
        results.push((name, *lat, med, p95));
    }
    println!();
    println!("=== B4-SIM RESULTS ===");
    println!(
        "{:<10} {:>10} {:>10} {:>8}",
        "condition", "latency_ms", "median_ms", "p95_ms"
    );
    println!("{}", "-".repeat(42));
    for (n, l, m, p) in &results {
        println!("{:<10} {:>10} {:>10} {:>8}", n, l, m, p);
    }
    println!();
    if let Some((_, _, med, _)) = results.iter().find(|(n, _, _, _)| *n == "WAN_50") {
        println!("quorum_time_50ms_WAN  : {}ms", med);
        println!(
            "quorum_under_30s      : {}",
            if *med < 30_000 { "YES ✓" } else { "NO ✗" }
        );
        let proof_s = 3.801f64;
        let timeout_s = 300.0f64;
        let max_tx = (timeout_s / proof_s).floor() as u64;
        let trigger = max_tx.min(50);
        let timeout_rec = ((*med as f64 / 1000.0) * 3.0).ceil() as u64;
        println!();
        println!("=== PARAM-C (partial — proof_time ESTIMATE) ===");
        println!("MICROCOMMITMENT_TRIGGER_TX      : {}", trigger);
        println!("MICROCOMMITMENT_TRIGGER_TIMEOUT : {}s", timeout_rec.max(60));
        println!("NOTE: Re-run setelah B1.1 dengan proof_time nyata.");
    }
    println!();
    println!("=== IMPACT ===");
    println!("D-023: quorum_time menentukan floor MICROCOMMITMENT_TRIGGER_TIMEOUT_S.");
    println!("D-024: LOCAL quorum konfirmasi intra-DC MicroCommitment feasible.");
    println!("NOTE: Update SLHDSA_VERIFY_MS dengan verify_median_ms dari B2.1.");
}
