// examples/slhdsa_latency.rs — B2.1: SLH-DSA sign/verify latency
use scalar_crypto::sphincs::{generate_keypair, sign_message, verify_signature};
use std::time::Instant;

const RUNS: usize         = 100;
const WARMUP: usize       = 10;
const PAYLOAD_SIZE: usize = 1024;
const EXPECTED_SIG_BYTES: usize = 7856;

fn median(mut v: Vec<u64>) -> u64 { v.sort_unstable(); v[v.len() / 2] }
fn p95(mut v: Vec<u64>)    -> u64 { v.sort_unstable(); v[((v.len() as f64 * 0.95) as usize).min(v.len()-1)] }

fn main() {
    println!("B2.1: SLH-DSA-SHAKE-128s Sign/Verify Latency");
    println!("Payload : {} bytes", PAYLOAD_SIZE);
    println!("Runs    : {} (+{} warmup)", RUNS, WARMUP);
    println!("Cores   : {}", std::thread::available_parallelism().map_or(0, |n| n.get()));
    println!();
    let keypair  = generate_keypair().expect("SLH-DSA keygen failed");
    let sk_bytes = &keypair.secret;
    let pk_bytes = &keypair.public;
    println!("Keys: SK={}B, PK={}B", sk_bytes.len(), pk_bytes.len());
    let payload = vec![0xABu8; PAYLOAD_SIZE];
    print!("Warmup ({} runs)... ", WARMUP);
    for _ in 0..WARMUP { let _ = sign_message(&payload, sk_bytes).unwrap(); }
    println!("done.");
    println!("Benchmarking sign ({} runs)...", RUNS);
    let mut sign_ns: Vec<u64> = Vec::with_capacity(RUNS);
    let mut last_sig = Vec::new();
    for _ in 0..RUNS {
        let t = Instant::now();
        last_sig = sign_message(&payload, sk_bytes).expect("sign failed");
        sign_ns.push(t.elapsed().as_nanos() as u64);
    }
    println!("Benchmarking verify ({} runs)...", RUNS);
    let mut verify_ns: Vec<u64> = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t = Instant::now();
        let ok = verify_signature(&payload, &last_sig, pk_bytes).expect("verify error");
        verify_ns.push(t.elapsed().as_nanos() as u64);
        assert!(ok, "verify_signature returned false");
    }
    let sign_med   = median(sign_ns.clone())  as f64 / 1_000_000.0;
    let sign_p95   = p95(sign_ns)              as f64 / 1_000_000.0;
    let verify_med = median(verify_ns.clone()) as f64 / 1_000_000.0;
    let verify_p95 = p95(verify_ns)            as f64 / 1_000_000.0;
    let sig_size   = last_sig.len();
    println!();
    println!("=== B2.1 RESULTS ===");
    println!("sign_median_ms    : {:.3}", sign_med);
    println!("sign_p95_ms       : {:.3}", sign_p95);
    println!("verify_median_ms  : {:.3}", verify_med);
    println!("verify_p95_ms     : {:.3}", verify_p95);
    println!("signature_size_b  : {} (spec={}, match={})",
             sig_size, EXPECTED_SIG_BYTES,
             if sig_size == EXPECTED_SIG_BYTES { "YES" } else { "NO — update PARAM-A" });
    println!("verify_under_10ms : {}", if verify_med < 10.0 { "YES ✓" } else { "NO ✗ — D-024 risk" });
    println!();
    println!("=== IMPACT ===");
    if verify_med < 10.0 {
        println!("D-024: {:.1}ms verify < 10ms threshold — OK.", verify_med);
    } else {
        println!("D-024: {:.1}ms verify EXCEEDS 10ms — factor into heartbeat budget.", verify_med);
    }
    if sig_size != EXPECTED_SIG_BYTES {
        println!();
        println!("=== PARAM-A RECALC (actual sig={}B) ===", sig_size);
        for &ivl in &[600u64, 120, 60, 30, 10] {
            let bw = (sig_size as f64 * 1_000.0) / ivl as f64;
            println!("  interval={:4}s  bw={:8.0} B/s  tier_c={}", ivl, bw,
                     if bw < 125_000.0 { "YES" } else { "NO " });
        }
    }
}
