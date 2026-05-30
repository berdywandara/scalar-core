#!/usr/bin/env bash
# ============================================================
# SCALAR PROTOCOL — BENCHMARK RUNNER
# Serahkan ke Benchmark Engineer, jalankan dari root repo:
#   bash run_benchmarks.sh 2>&1 | tee benchmark_raw_$(date +%Y%m%d).txt
# ============================================================
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT="docs/reports/benchmark_run_${TIMESTAMP}.txt"
mkdir -p docs/reports

log() { echo "$1" | tee -a "$OUTPUT"; }

log "======================================================"
log "SCALAR PROTOCOL BENCHMARK RUN"
log "Timestamp : $TIMESTAMP"
log "Commit    : $(git rev-parse HEAD)"
log "Hardware  : $(nproc) core(s), $(free -h | awk '/^Mem:/{print $2}') RAM"
log "Rust      : $(rustc --version)"
log "======================================================"
log ""

run_bench() {
    local ID="$1" CRATE="$2" EXAMPLE="$3"
    log "--- [$ID] ---"
    cargo run --release -p "$CRATE" --example "$EXAMPLE" 2>&1 | tee -a "$OUTPUT"
    log ""
}

log "=== PREREQUISITE: invariant_poseidon2_alignment ==="
cargo test -p scalar-stark-p3 invariant_poseidon2_alignment 2>&1 \
    | grep -E "test result|FAILED|ok" | tee -a "$OUTPUT"
log ""

run_bench "B2.1"      scalar-crypto    slhdsa_latency
run_bench "B3.1"      scalar-crypto    imt_depth32_bench
run_bench "B4-SIM"    scalar-crypto    quorum_sim
run_bench "B5-WAL"    scalar-node      wal_bench
run_bench "B1.1"      scalar-stark-p3  transfer_proof_bench
run_bench "B1.1-FULL" scalar-stark-p3  transfer_proof_full_bench

log "======================================================"
log "DONE. Output saved: $OUTPUT"
log "======================================================"
