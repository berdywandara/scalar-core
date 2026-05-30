// examples/imt_depth32_bench.rs — B3.1: IMT depth-32 path generation benchmark
use scalar_crypto::imt::{imt_membership_verify, IncrementalMerkleTree};
use std::time::Instant;

const LEAF_COUNT: usize = 10_000;
const QUERY_RUNS: usize = 50;

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}
fn p95(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)]
}

fn main() {
    println!("B3.1: IMT depth-32 Path Generation Benchmark");
    println!("Leaves  : {}", LEAF_COUNT);
    println!("Queries : {}", QUERY_RUNS);
    println!(
        "Cores   : {}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!();
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(LEAF_COUNT);
    for i in 0..LEAF_COUNT {
        let mut leaf = [0u8; 32];
        leaf[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        leaves.push(leaf);
    }
    println!("Building IMT ({} leaves)...", LEAF_COUNT);
    let t_build = Instant::now();
    let mut imt = IncrementalMerkleTree::new();
    for leaf in &leaves {
        imt.append(leaf).expect("IMT append failed");
    }
    let root = imt.root();
    let build_ms = t_build.elapsed().as_millis();
    println!("  done. {}ms | root[0..4]={:02x?}", build_ms, &root[..4]);
    println!("Querying {} random paths...", QUERY_RUNS);
    let count_u64 = LEAF_COUNT as u64;
    let mut path_ns: Vec<u64> = Vec::with_capacity(QUERY_RUNS);
    let mut path_size_bytes = 0usize;
    let mut all_valid = true;
    let mut rng: u64 = 0xDEAD_BEEF_CAFE_0001;
    for _ in 0..QUERY_RUNS {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = (rng >> 33) % count_u64;
        let t = Instant::now();
        let path = imt.prove_membership(idx).expect("prove_membership failed");
        path_ns.push(t.elapsed().as_nanos() as u64);
        if path_size_bytes == 0 {
            path_size_bytes = path.siblings.len() * 32;
        }
        let valid = imt_membership_verify(&leaves[idx as usize], &path, &root, count_u64);
        if !valid {
            eprintln!("  VERIFY FAILED idx={}", idx);
            all_valid = false;
        }
    }
    let med = median(path_ns.clone()) as f64 / 1_000_000.0;
    let p95 = p95(path_ns) as f64 / 1_000_000.0;
    println!();
    println!("=== B3.1 RESULTS ===");
    println!("imt_build_ms         : {}", build_ms);
    println!("path_gen_median_ms   : {:.3}", med);
    println!("path_gen_p95_ms      : {:.3}", p95);
    println!(
        "path_size_bytes      : {} (depth={})",
        path_size_bytes,
        path_size_bytes / 32
    );
    println!("verify_all_correct   : {}", all_valid);
    println!();
    println!("=== IMPACT ===");
    println!(
        "D-023: path_gen {:.3}ms/tx — witness overhead per MicroCommitment batch.",
        med
    );
    println!(
        "Status: {}",
        if med < 1.0 {
            "VALIDATES — not a bottleneck (<1ms)"
        } else {
            "NOTE — >1ms, factor into batch sizing"
        }
    );
}
