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

**PARAM-C (final — B1.1 proof_time=1.075s):**
- MICROCOMMITMENT_TRIGGER_TX: 50
- MICROCOMMITMENT_TRIGGER_TIMEOUT: max(3×quorum, 60) = 60s minimum

**Impact D-023/D-024:** Quorum < 30s confirmed across all conditions.  
LOCAL quorum confirms intra-DC MicroCommitment feasible.

---

## ALL BENCHMARKS COMPLETE ✅

| ID | Description | Status |
|----|-------------|--------|
| B1.1 | Transfer proof prove+verify | ✅ prove=1075ms, verify=3ms, 77KB |
| B2.1 | SLH-DSA sign/verify latency | ✅ sign=394ms, verify=0.479ms |
| B3.1 | IMT depth-32 path generation | ✅ path_gen=9.034ms |
| B4-SIM | Quorum formation simulation | ✅ WAN_50=129ms |
| B5-WAL | WAL three-phase throughput | ✅ prepare=90ns, commit=326μs |

## PARAMETER UPDATES NEEDED

After B1.1:
- Update `proof_time` in PARAM-C calculation
- Re-run quorum_sim with actual proof_time for MICROCOMMITMENT_TRIGGER_TX

---

## B1.1 — Transfer Proof Prove+Verify (CD/CE/CG sub-AIR)

| Metric | Value | Status |
|--------|-------|--------|
| prove_median_ms | **1075** | ⚠️ ~1.1s per proof |
| prove_p95_ms | **1091** | |
| verify_median_ms | **3** | ✅ fast |
| verify_p95_ms | **3** | |
| proof_size_kb | **77** | ✅ reasonable |

**PARAM-C (final, real proof_time):**
- proof_time_s: 1.075
- max_tx_in_300s: 279
- **MICROCOMMITMENT_TRIGGER_TX: 50** (min(279, 50))
- **MICROCOMMITMENT_TRIGGER_TIMEOUT: 60s** (max(3×129ms, 60s) = 60s minimum)

**Impact:**
- D-023: 1075ms prove — MicroCommitment batch of 50 tx ≈ 53.75s proving (feasible in 60s timeout)
- D-024: 3ms verify — aggregator can verify 100 proofs/s
- D-025: 77KB proof — well within 1MB network budget

**Note:** This measures CD/CE/CG sub-AIR only. Full BatchTransferProof (CA+CB+CC+CD/CE/CG)
is ~3.8s per spec MTS benchmark (P3-R9, commit 5aa8be7). Transfer AIR alone = 1.075s.

---

## B5-WAL — WAL Three-Phase Commit Throughput

| Metric | Value | Status |
|--------|-------|--------|
| prepare_median_ns | **90** | ✅ negligible |
| commit_median_ns | **325,597** (~326μs) | ✅ acceptable* |
| lookup_median_ns | **140** | ✅ negligible |
| idempotency_ok | **true** | ✅ ADR-SEC-002 |
| committed_count | **10,000** | ✅ |

*commit 326μs because it copies 689KB proof bytes. In production: store path/hash only.

**Impact:**
- WAL overhead is negligible vs proof generation (1075ms prove >> 326μs WAL commit)
- is_committed guard at 140ns is zero-cost for proof gating
- Idempotency verified for 1000 re-commit operations

---

## PARAMETER SUMMARY (D-023/D-024/D-025)

| Parameter | Value | Source |
|-----------|-------|--------|
| MICROCOMMITMENT_TRIGGER_TX | **50** | B1.1 + B4-SIM |
| MICROCOMMITMENT_TRIGGER_TIMEOUT_S | **60** | B4-SIM quorum×3 |
| slhdsa_verify_ms (actual) | **0.479** | B2.1 |
| transfer_prove_ms | **1075** | B1.1 |
| transfer_verify_ms | **3** | B1.1 |
| proof_size_kb | **77** | B1.1 |
| imt_path_gen_ms | **9.034** | B3.1 |
| quorum_wan50_ms | **129** | B4-SIM |


---

## B1.1-FULL — Full BatchTransferProof (CA+CB+CC+CD/CE/CG)

| Metric | Value | Status |
|--------|-------|--------|
| prove_median_ms | **7280** | ⚠️ 7.28s (Codespace 4vCPU) |
| prove_p95_ms | **7379** | |
| verify_median_ms | **20** | ✅ |
| proof_ca_kb | 191 | |
| proof_cb_kb | 283 | |
| proof_cc_kb | 138 | |
| proof_cdcecg_kb | 83 | |
| **proof_total_kb** | **695** | ✅ <1MB budget |

**Perbandingan hardware:**
- Codespace 4vCPU: 7280ms
- Dedicated EPYC (P3-R9): ~3800ms
- Codespace ~1.9× lebih lambat dari dedicated

**PARAMETER UPDATE — FINAL:**

| Parameter | Lama | Baru | Basis |
|-----------|------|------|-------|
| MICROCOMMITMENT_TRIGGER_TX | 50 | **41** | floor(300/7.28) |
| SUBEPOCH_DURATION_S (Codespace) | 1900 | **3640** (~61 min) | 7.28×5×100 |
| SUBEPOCH_DURATION_S (dedicated EPYC) | 1900 | **1900** | 3.8×5×100 (P3-R9) |

**Impact D-023/D-025:**
- D-023: 41 tx per MicroCommitment batch (turun dari 50)
- D-025: 695KB total proof — well within 1MB network budget
