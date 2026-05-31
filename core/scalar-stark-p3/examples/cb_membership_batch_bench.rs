// examples/cb_membership_batch_bench.rs
// B1.2-BATCH: CB MembershipAir batch proving — amortized per-tx cost
//
// Run:
//   cargo run --release -p scalar-stark-p3 --example cb_membership_batch_bench \
//     2>&1 | tee -a benchmark_raw_$(date +%Y%m%d).txt
//
// PARAM-C gate: jika per_tx_amortized > 1.2s → MICROCOMMITMENT_TRIGGER_TX
//   harus diturunkan dari 41 ke floor(60s / per_tx_amortized_parallel)

use scalar_crypto::imt::IncrementalMerkleTree;
use scalar_stark_p3::membership_air_p3::{
    prove_membership_p3, verify_membership_p3, MembershipPublicClaim, MembershipWitness, IMT_DEPTH,
};
use std::time::Instant;

const BATCH_SIZES: &[usize] = &[1, 5, 10, 20, 41];
const LEAF_POOL: usize = 100; // IMT pool size
const WARMUP: usize = 1;

/// Build merkle witnesses dari IMT untuk N leaf pertama.
fn build_witnesses(n: usize) -> (Vec<MembershipWitness>, MembershipPublicClaim, [u64; 4]) {
    assert!(n <= LEAF_POOL);
    let mut imt = IncrementalMerkleTree::new();
    let mut leaves = Vec::with_capacity(LEAF_POOL);
    for i in 0..LEAF_POOL {
        let mut leaf = [0u8; 32];
        leaf[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        leaves.push(leaf);
        imt.append(&leaf).unwrap();
    }
    let root_bytes = imt.root();
    // Convert [u8;32] root → [u64;4]
    let root_u64: [u64; 4] = core::array::from_fn(|i| {
        u64::from_le_bytes(root_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
    });

    let mut witnesses = Vec::with_capacity(n);
    let mut leaf_commitments = Vec::with_capacity(n);
    let mut leaf_indices = Vec::with_capacity(n);

    for (idx, &leaf) in leaves.iter().enumerate().take(n) {
        let path = imt.prove_membership(idx as u64).unwrap();
        let mut siblings = [[0u64; 4]; IMT_DEPTH];
        for (i, sib) in path.siblings.iter().enumerate() {
            siblings[i] = core::array::from_fn(|j| {
                u64::from_le_bytes(sib[j * 8..(j + 1) * 8].try_into().unwrap())
            });
        }
        witnesses.push(MembershipWitness {
            commitment: leaf,
            leaf_index: idx as u64,
            siblings,
        });
        leaf_commitments.push(leaf);
        leaf_indices.push(idx as u64);
    }

    let claim = MembershipPublicClaim {
        expected_root: root_u64,
        leaf_commitments,
        leaf_indices,
    };

    (witnesses, claim, root_u64)
}

fn bench_batch(batch_size: usize) -> (u64, u64, usize) {
    let (witnesses, claim, _root) = build_witnesses(batch_size);

    // Warmup
    for _ in 0..WARMUP {
        let _ = prove_membership_p3(&witnesses, &claim).unwrap();
    }

    // Benchmark prove
    let t = Instant::now();
    let proof = prove_membership_p3(&witnesses, &claim).unwrap();
    let prove_ms = t.elapsed().as_millis() as u64;

    // Benchmark verify
    let t = Instant::now();
    verify_membership_p3(&proof, &claim).unwrap();
    let verify_ms = t.elapsed().as_millis() as u64;

    let proof_kb = proof.len() / 1024;
    (prove_ms, verify_ms, proof_kb)
}

fn main() {
    println!("B1.2-BATCH: CB MembershipAir Batch Proving");
    println!("IMT pool : {} leaves (depth=32)", LEAF_POOL);
    println!("Warmup   : {} run per batch", WARMUP);
    println!(
        "Cores    : {}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!();

    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>14} gate",
        "batch_size", "prove_ms", "verify_ms", "proof_kb", "per_tx_ms"
    );
    println!("{}", "-".repeat(70));

    let mut results = Vec::new();

    for &size in BATCH_SIZES {
        print!("  batch={:<6} running... ", size);
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let (prove_ms, verify_ms, proof_kb) = bench_batch(size);
        let per_tx_ms = prove_ms / size as u64;
        let gate = if per_tx_ms <= 1_200 {
            "✅ <1.2s"
        } else {
            "❌ >1.2s"
        };
        println!(
            "{:<12} {:>12} {:>12} {:>12} {:>14} {}",
            size, prove_ms, verify_ms, proof_kb, per_tx_ms, gate
        );
        results.push((size, prove_ms, verify_ms, proof_kb, per_tx_ms));
    }

    println!();
    println!("=== B1.2-BATCH RESULTS ===");

    // PARAM-C gate for MICROCOMMITMENT_TRIGGER_TX = 41
    let trigger_tx: u64 = 41;
    if let Some(&(_, prove_ms, _, _, per_tx_ms)) = results
        .iter()
        .find(|(s, _, _, _, _)| *s == trigger_tx as usize)
    {
        println!("At MICROCOMMITMENT_TRIGGER_TX={}:", trigger_tx);
        println!("  total_prove_ms   : {}", prove_ms);
        println!("  per_tx_amortized : {}ms", per_tx_ms);
        println!("  timeout_budget   : 60_000ms");
        println!(
            "  fits_in_60s      : {}",
            if prove_ms <= 60_000 {
                "YES ✅"
            } else {
                "NO ✗"
            }
        );
        println!();
        if per_tx_ms > 1_200 {
            let new_trigger = 60_000u64 / per_tx_ms;
            println!("PARAM-C REVISION NEEDED:");
            println!("  per_tx={}ms > 1_200ms threshold", per_tx_ms);
            println!("  New MICROCOMMITMENT_TRIGGER_TX = {}", new_trigger);
        } else {
            println!("PARAM-C CONFIRMED:");
            println!("  MICROCOMMITMENT_TRIGGER_TX = {} validated ✅", trigger_tx);
        }
    }

    println!();
    println!("=== IMPACT ===");
    println!("D-023: CB membership batch time menentukan floor MICROCOMMITMENT batch sizing.");
    println!("NOTE: Nilai ini untuk CB sub-AIR saja. Full BatchTransferProof lebih lambat.");
}
