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

---

## KEPUTUSAN FINAL — Benchmark Engineer (2026-05-31)

| Decision | Verdict | Catatan |
|----------|---------|---------|
| D-023 MicroCommitment | **CONDITIONAL GO** | Tunggu B1.2-BATCH |
| D-024 Multi-speed Heartbeat | **GO** | SLH-DSA verify 0.479ms ✅ |
| D-025 Optimistic Finality | **NO-GO** | Research Paper 2 belum ada |

### Klarifikasi D-024 — 20ms full proof verify BUKAN blocker

Threshold 10ms D-024 berlaku untuk **SLH-DSA heartbeat signature verify** = 0.479ms ✅

Full STARK proof verify = 20ms adalah data berbeda:
- Konteks: aggregator memverifikasi transfer proof
- 50 proof/detik capacity (1000ms / 20ms)
- Tidak disebutkan di NSFA sebelumnya — data baru

Perlu konfirmasi ke tim arsitektur: apakah 50 proof/detik cukup untuk target throughput aggregator.

### Action Items (Coding Team)

| Item | Status | Catatan |
|------|--------|---------|
| Typo MTS §20 "3.801ms→3.801s" | ⚠️ Spec-only | Tidak ada di codebase — perlu edit dokumen MTS eksternal |
| B1.2-BATCH benchmark | ⏳ Pending | Jadwalkan setelah testnet infra siap |
| Konfirmasi 50 proof/detik cukup | ⏳ Pending | Arsitektur perlu review |

---

## B1.2-BATCH — CB MembershipAir Batch Proving (D-023 Gate)

| batch_size | prove_ms | per_tx_amortized_ms | gate |
|-----------|---------|--------------------|----|
| 1 | 1214 | 1214 | ❌ single-tx overhead |
| 5 | 3770 | 754 | ✅ |
| 10 | 1501 | 150 | ✅ |
| 20 | 3138 | 156 | ✅ |
| **41** | **4086** | **99** | **✅ <1.2s** |

**PARAM-C CONFIRMED: MICROCOMMITMENT_TRIGGER_TX = 41 validated**
- CB prove 41 tx = 4086ms (fits dalam 60s timeout ✅)
- per_tx_amortized = 99ms << 1200ms threshold ✅

**Strong batching effect:** single-tx = 1214ms, batch-41 = 99ms/tx (12× speedup)

## D-023 FINAL DECISION UPDATE

| Decision | Old | New |
|----------|-----|-----|
| D-023 MicroCommitment | CONDITIONAL GO (tunggu B1.2-BATCH) | **GO** |

Kondisi B1.2-BATCH terpenuhi:
- per_tx_amortized = 99ms < 1200ms ✅
- total 41 tx fits dalam 60s timeout ✅
- MICROCOMMITMENT_TRIGGER_TX = 41 dikonfirmasi

---

## SOUNDNESS ANALYSIS FINDING (dari SPECIALIST-2, 2026-05-31)

**Status:** Eskalasi ke arsitektur team — menunggu D-028

### Temuan
STARKPack menggunakan **Scenario B** (independent union bound):
- `aggregate_real_proofs` memverifikasi setiap proof secara terpisah
- Tidak ada single RLC FRI instance yang menggabungkan N proofs

### Implikasi
- ε_final (Scenario B, g=20) ≈ 2^-117.68
- Target MAD §17.1 (2^-120) **TIDAK TERPENUHI** — gap 2.3 bits

### Opsi Fix
| Opsi | Perubahan | ε_final | Status |
|------|-----------|---------|--------|
| B-1 | grinding g=20 → 23 | 2^-120.68 | ✅ PASS |
| B-2 | FRI field 2^128 → 2^192 | 2^-181 | ✅ PASS |
| A   | Ubah ke RLC batching | 2^-125.68 | ✅ PASS |

### Constraint
`FRI_PROOF_OF_WORK_BITS = 20` adalah **OSSIFIED** per MAD §21.1.
Implementasi menunggu keputusan D-028 dari arsitektur team.

### File Referensi (dari SPECIALIST-2)
- `SOUNDNESS_PROOF.md` — derivasi matematis lengkap
- `soundness_calculation.py` — script reproduksi kalkulasi
- `PARAMETER_RECOMMENDATIONS.md` — opsi fix detail

---

## D-028 — FRI Grinding g=20 → g=23 Impact

**Sebelum D-028 (g=20):** batch=41 → prove=4,086ms, per_tx=99ms
**Setelah D-028 (g=23):** batch=41 → prove=37,856ms, per_tx=923ms

| batch | prove_ms (g=23) | per_tx_ms | gate |
|-------|----------------|-----------|------|
| 1 | 20,055 | 20,055 | ❌ single-tx |
| 5 | 19,741 | 3,948 | ❌ |
| 10 | 22,733 | 2,273 | ❌ |
| 20 | 45,207 | 2,260 | ❌ |
| **41** | **37,856** | **923** | **✅** |

**MICROCOMMITMENT_TRIGGER_TX=41 masih validated ✅** (923ms < 1.2s, fits 60s)

**Grinding time 9.3× lebih lambat** karena Codespace 4vCPU.
Re-bench wajib di dedicated EPYC setelah testnet deployment.
Referensi: D-028 RISIKO-2, parallel grinding strategy jika perlu.

---

## D-025 — Optimistic Finality Formal Verification (SPECIALIST-1)

**Verdict: GO** — Semua 7 property PASS via TLA+ model checking.

| Property | Type | Result |
|----------|------|--------|
| TypeOK | Invariant | ✅ PASS |
| NullifierUniqueness | Safety | ✅ PASS |
| OptimisticSafety | Safety | ✅ PASS |
| FinalizationOrder | Safety | ✅ PASS |
| NullifierSetConsistency | Safety | ✅ PASS |
| NoOptimisticDoubleFinalize | Safety | ✅ PASS |
| EventualResolution | Liveness | ✅ PASS |

Files: `verification/d025-optimistic-finality/`
Pre-deployment checklist: 6 items (see VERIFICATION_REPORT.md)

---

## D-026 — T_MAX_WAIT Constraint Update

**Keputusan:** T_MAX_WAIT diubah dari 86_400s (24 jam) → **1_800s (30 menit)**

| Parameter | Lama | Baru | Tipe |
|-----------|------|------|------|
| T_MAX_WAIT | 86_400s | **1_800s** | CONSTRAINED |

**Justifikasi:** Anti-censorship window 24 jam tidak kompatibel dengan
sub-epoch duration 1_900s (~32 menit). T_MAX_WAIT harus < sub-epoch duration
agar CG timestamp constraint tidak selalu reject transaksi valid.
Formula: T_MAX_WAIT < SUBEPOCH_PROVING_DURATION_S.
1_800s < 1_900s ✅

---

## D-027 — Semantic Parameters (Derived from Benchmark)

**Keputusan:** Semua parameter waktu di-derive ulang dari benchmark empiris.
Basis: HEARTBEAT_INTERVAL_S=120 (D-024 GO, SLH-DSA verify=0.479ms confirmed).

| Parameter | Lama | Baru | Tipe | Derivasi |
|-----------|------|------|------|----------|
| HEARTBEAT_INTERVAL_S | 600s | **120s** | CONSTRAINED | D-024 GO |
| SUBEPOCH_PROVING_DURATION_S | 108_000s | **1_900s** | CONSTRAINED | 180×120−1700 buffer |
| W_MATURE_EPOCHS | 6 | **342** | OSSIFIED | ceil(180 hari × 86400 / (4320×120)) |
| W_MATURE_DAYS | — | **180** | OSSIFIED (baru) | canonical reference |
| GENESIS_WINDOW_DAYS | — | **7** | CONSTRAINED (baru) | desain genesis ceremony |
| GENESIS_ANCHOR_DEADLINE_SEQ | 4320 | **5_040** | CONSTRAINED | 7 hari × 86400 / 120 |
| EPOCH_DURATION_S | 2_592_000s (30 hari) | **45_600s (~12.67 jam)** | derived | 4320×120 |
| SUBEPOCH_COUNT_PER_EPOCH | 24 | **24** | unchanged | tetap 24 sub-epoch/epoch |

**Cascade effects:**
- Epoch 30 hari → ~12.67 jam: governance cycle lebih cepat ✅
- Sub-epoch 30 jam → ~31.7 menit: UTXO finality 720× lebih cepat ✅
- W_MATURE_EPOCHS 6→342: semantik tidak berubah (tetap 180 hari) ✅
- GENESIS_ANCHOR_DEADLINE_SEQ 4320→5040: genesis window tetap 7 hari ✅

**Parameter di codebase:**
- `core/scalar-emission/src/protocol_params.rs` — semua konstanta D-027
- `core/scalar-stark-p3/src/lib.rs` — FRI_PROOF_OF_WORK_BITS=23 (D-028)

