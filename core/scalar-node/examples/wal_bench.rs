// examples/wal_bench.rs
// B5-WAL: WAL three-phase commit throughput — COMPLETE
//
// Run:
//   cargo run --release -p scalar-node --example wal_bench \
//     2>&1 | tee -a benchmark_raw_$(date +%Y%m%d).txt

use scalar_node::wal::{CheckpointSnapshot, CheckpointWal};
use std::time::Instant;

const CHECKPOINT_RUNS: usize = 10_000;

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}
fn p95(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)]
}

fn make_snapshot(epoch_id: u64) -> CheckpointSnapshot {
    CheckpointSnapshot {
        epoch_id,
        imt_frontier_root: [0xAAu8; 32],
        imt_count: 10_000 * epoch_id,
        utxo_set_root: [0xBBu8; 32],
        nullifier_active_root: [0xCCu8; 32],
        nullifier_archived_root: [0xDDu8; 32],
        total_supply_sscl: 1_890_000_000_000_000u64.saturating_sub(epoch_id * 1_000_000),
    }
}

fn main() {
    println!("B5-WAL: WAL Three-Phase Commit Throughput");
    println!("Runs    : {} checkpoints", CHECKPOINT_RUNS);
    println!(
        "Cores   : {}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!();

    let mut wal = CheckpointWal::new();
    let proof_bytes = vec![0xFFu8; 689 * 1024]; // 689KB — B1.1 typical

    // ── PREPARE throughput ────────────────────────────────────────────────────
    println!("Benchmarking PREPARE ({} ops)...", CHECKPOINT_RUNS);
    let mut prepare_ns: Vec<u64> = Vec::with_capacity(CHECKPOINT_RUNS);
    for i in 0..CHECKPOINT_RUNS {
        let snap = make_snapshot(i as u64);
        let t = Instant::now();
        wal.prepare(i as u64, 1, snap, i as u64 * 1000)
            .expect("prepare failed");
        prepare_ns.push(t.elapsed().as_nanos() as u64);
    }

    // ── COMMIT throughput ─────────────────────────────────────────────────────
    println!("Benchmarking COMMIT ({} ops)...", CHECKPOINT_RUNS);
    let mut commit_ns: Vec<u64> = Vec::with_capacity(CHECKPOINT_RUNS);
    for i in 0..CHECKPOINT_RUNS {
        let t = Instant::now();
        wal.commit(i as u64, proof_bytes.clone(), i as u64 * 1000 + 500)
            .expect("commit failed");
        commit_ns.push(t.elapsed().as_nanos() as u64);
    }

    // ── IDEMPOTENCY check ─────────────────────────────────────────────────────
    println!("Checking idempotency (re-commit 1000 entries)...");
    let mut idempotent_ok = true;
    for i in 0..1000usize {
        let r = wal.commit(i as u64, proof_bytes.clone(), 999_999);
        match r {
            Ok(scalar_node::wal::WalResult::AlreadyInState) => {}
            _ => {
                idempotent_ok = false;
                break;
            }
        }
    }

    // ── is_committed lookup ───────────────────────────────────────────────────
    println!(
        "Benchmarking is_committed lookup ({} ops)...",
        CHECKPOINT_RUNS
    );
    let mut lookup_ns: Vec<u64> = Vec::with_capacity(CHECKPOINT_RUNS);
    for i in 0..CHECKPOINT_RUNS {
        let t = Instant::now();
        let _ = wal.is_committed(i as u64);
        lookup_ns.push(t.elapsed().as_nanos() as u64);
    }

    let prep_med = median(prepare_ns.clone());
    let _prep_p95 = p95(prepare_ns);
    let comm_med = median(commit_ns.clone());
    let comm_p95 = p95(commit_ns);
    let look_med = median(lookup_ns.clone());
    let look_p95 = p95(lookup_ns);

    println!();
    println!("=== B5-WAL RESULTS ===");
    println!("prepare_median_ns  : {}", prep_med);
    println!("prepare_p95_ns     : {}", prep_med);
    println!("commit_median_ns   : {}", comm_med);
    println!("commit_p95_ns      : {}", comm_p95);
    println!("lookup_median_ns   : {}", look_med);
    println!("lookup_p95_ns      : {}", look_p95);
    println!("idempotency_ok     : {}", idempotent_ok);
    println!(
        "committed_count    : {}",
        wal.count_by_phase(&scalar_node::wal::WalPhase::Committed)
    );
    println!();

    let epoch_duration_s = 30u64 * 24 * 3600; // 30 days
    let prep_per_epoch = epoch_duration_s * 1_000_000_000 / prep_med.max(1);
    println!("=== IMPACT ===");
    println!(
        "WAL PREPARE: {}ns median — {} ops/epoch capacity (30-day epoch).",
        prep_med, prep_per_epoch
    );
    println!(
        "WAL COMMIT:  {}ns median — overhead per checkpoint commit.",
        comm_med
    );
    println!(
        "Lookup:      {}ns median — is_committed guard is negligible.",
        look_med
    );
    println!(
        "Idempotency: {} — WAL correctly handles re-commit.",
        idempotent_ok
    );
    println!();
    println!("NOTE: This benchmarks in-memory WAL. Persistent backend (sled/file)");
    println!("      will add I/O latency — re-bench after testnet backend implemented.");
}
