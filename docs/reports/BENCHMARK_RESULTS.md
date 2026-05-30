# SCALAR BENCHMARK RESULTS
**Date:** 2026-05-30  
**Hardware:** AMD EPYC (Codespace), 4 vCPU, --release

---

## B2.1 — SLH-DSA-SHAKE-128s Latency

| Metric | Value | Spec | Status |
|--------|-------|------|--------|
| sign_median_ms | **394.211** | — | ⚠️ 1×/epoch anchor, acceptable |
| sign_p95_ms | **415.574** | — | |
| verify_median_ms | **0.479** | <10ms | ✅ D-024 OK |
| verify_p95_ms | **0.511** | | |
| signature_size_b | **7856** | 7856 | ✅ match |

**Impact D-024:** verify 0.479ms << 10ms threshold. Tidak menjadi bottleneck per heartbeat.  
**Note:** Heartbeat MAC pakai BLAKE3 (bukan SLH-DSA). SLH-DSA hanya untuk EpochAnchor (1×/epoch).

---

## B3.1 — IMT depth-32 Path Generation

| Metric | Value | Status |
|--------|-------|--------|
| imt_build_ms (10K leaves) | **19** | ✅ |
| path_gen_median_ms | **9.034** | ⚠️ |
| path_gen_p95_ms | **10.099** | |
| path_size_bytes | **1024** (depth=32) | ✅ |
| verify_all_correct | **true** | ✅ |

**Impact D-023:** path_gen 9ms/tx adalah overhead witness per MicroCommitment batch.  
Untuk batch 50 tx: ~450ms path generation overhead (masih dalam 300s timeout).  
Jika batch > 33 tx/s needed: perlu optimasi Poseidon2 atau parallelisasi path gen.

---

## B4-SIM — Quorum Formation (7/10 validators)

| Condition | latency_ms | median_ms | p95_ms | Status |
|-----------|-----------|-----------|--------|--------|
| LOCAL | 1 | **11** | 11 | ✅ intra-DC feasible |
| WAN_50 | 50 | **129** | 129 | ✅ <30s |
| WAN_200 | 200 | **489** | 489 | ✅ <30s |

**SLHDSA_VERIFY_MS used:** 1ms (B2.1 actual: 0.479ms)

**PARAM-C (partial — awaiting B1.1 proof_time):**
- MICROCOMMITMENT_TRIGGER_TX: 50
- MICROCOMMITMENT_TRIGGER_TIMEOUT: max(3×quorum, 60) = 60s minimum

**Impact D-023/D-024:** Quorum < 30s confirmed across all conditions.  
LOCAL quorum confirms intra-DC MicroCommitment feasible.

---

## PENDING BENCHMARKS

| ID | Description | Blocker |
|----|-------------|---------|
| B1.1 | Transfer proof end-to-end | Harness needed |
| B5-WAL | WAL checkpoint throughput | Harness needed |

## PARAMETER UPDATES NEEDED

After B1.1:
- Update `proof_time` in PARAM-C calculation
- Re-run quorum_sim with actual proof_time for MICROCOMMITMENT_TRIGGER_TX
