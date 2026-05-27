# Empirical Test Plan — Pre-Genesis to Mainnet

This document lists all items that require **empirical testing, formal
verification, or external audit** — not just coding. Each item includes
the required method, tools, milestone, and current status.

---

## Testnet Readiness

### E1 — Hardware Spec Benchmark: Proving Time (§15.6)

**Method:** Run `prove_batch_transfer` (2-in/2-out) on hardware meeting
the spec: 8 GB RAM, standard server CPU, no GPU.

**Tools:**
cargo test -p scalar-stark-p3 --features bench-hardware --release 
-- bench:: --nocapture

**Success criteria (spec §15.6, D-010):** No hard time limit.
Proving time is an empirical reference, not a pass/fail gate.
FRI params OSSIFIED (blowup=8, queries=84, grinding=20) must not change.

**Milestone:** Testnet
**Status:** ✅ COMPLETE (P3-R9, commit 5aa8be7)

**Recorded results — AMD EPYC 7763, 4 vCPU, 16 GB RAM, --release, CPU-only:**

| Circuit | Prove | Verify | Size |
|---|---|---|---|
| BatchTransferProof 2-in/2-out | 3,801 ms | 20 ms | 689 KB |
| MintNullifierAir MC2 | 192 ms | 5 ms | 186 KB |
| MintLinearAir MC1+MC3+MC4+MC5 | 307 ms | 1 ms | 50 KB |
| STARKPack N=1 transcript | 3 ms | — | — |
| STARKPack N=4 transcript | 13 ms | — | — |

All tiers (A/B/C) confirmed able to prove without GPU. Spec §15.6 satisfied.
See `BENCHMARK.md` for full details.

---

### E2 — Production Trace: Full In-Circuit Constraint Verification

**Method:** Verify that all constraint groups (CA–CG, MC1–MC5) are
evaluated in-circuit via Plonky3 AIR, not pre-flight Rust checks.
Confirm falsifiability: tampered witness → proof rejected by STARK.

**Tools:** Existing test suite (`cargo test -p scalar-stark-p3`)

**Success criteria:** All falsifiability tests pass (wrong secret → rejected,
wrong nullifier → rejected, wrong path → rejected, supply cap violated → rejected).

**Milestone:** Testnet
**Status:** ✅ COMPLETE (P3-R1..R7, 107 tests passing)

Plonky3 `check_constraints` detects violations at prove time (panic or Err),
not just pre-flight. All sub-AIRs (CA/CB/CC/CD/CE/CG, MC1–MC5) are in-circuit.
Constraint counts: CA 2×Poseidon2, CB 33×Poseidon2 per input, CC 32 SMT levels×2,
CD/CE/CG 12-column linear AIR.

---

## Pramainnet Readiness

### E3 — Model-Checking: Invariant CC (§15.4)

**Method:** Run TLC on `verification/invariant_cc.tla` with the
configuration defined in `MODEL_CHECKING_PROCEDURE.md`. Verify the
theorem `Spec => []InvariantCC` holds.

**Tools:** TLA+ Tools (TLC), Java 17+.

**Success criteria:** TLC reports no errors; all states explored;
invariants hold for model size Nullifiers=5, MaxEpoch=5.

**Milestone:** Pramainnet
**Status:** NOT STARTED (TLC unavailable in Codespace — requires external auditor)

---

### E4 — Model-Checking: Deferred Emission Pool (§15.5)

**Method:** Run TLC with `deferred_pool.cfg` to verify all five invariants.

**Tools:** TLA+ Tools (TLC), Java 17+.

**Success criteria:** All invariants hold (Inv1–Inv5); no deadlock.

**Milestone:** Pramainnet
**Status:** NOT STARTED (TLC unavailable in Codespace — requires external auditor)

---

### E5 — Fuzz Testing: STARKPack Adversarial (TV5.15)

**Method:** Run the fuzz target
`fuzz/fuzz_targets/fuzz_starkpack_adversarial.rs` for 10 million
iterations using `cargo fuzz` (nightly compiler). The target covers
adversarial proof bytes, wrong PI, order manipulation, element skipping,
batch size boundary, determinism checks.

**Tools:** `cargo fuzz`, Rust nightly, libfuzzer.

**Note:** Fuzz target migrated from scalar-stark (Winterfell) to
scalar-stark-p3 (Plonky3) in P3-R8 (commit cea7040).

**Success criteria:** No crashes, no assertion failures after 10M iterations.

**Milestone:** Pramainnet
**Status:** TARGET READY (migrated P3-R8), NOT YET EXECUTED (requires nightly)

```bash
# To run (requires nightly):
rustup install nightly
cargo +nightly fuzz run fuzz_starkpack_adversarial -- -max_total_time=3600
```

---

## Genesis / Mainnet Readiness

### E6 — Dual Verification: Cross-Implementation (§15.3)

**Method:** Two independent Plonky3-based implementations must verify
the same proofs and reach identical accept/reject decisions.

**Current status:** scalar-stark-p3 is the primary implementation.
A second independent implementation (different codebase, same spec) is
required before mainnet.

**Tools:** Independent Plonky3 implementation, test vector suite (docs/TEST_VECTORS.md).

**Success criteria:** 100% agreement on all valid and invalid proofs.

**Milestone:** Mainnet
**Status:** NOT STARTED (scalar-stark-p3 is implementation #1)

---

### E7 — Two Independent Firm Audits (§15.1)

**Method:** Engage two independent cryptography/formal-verification firms
to audit:
- TLA+ models and TLC/Apalache results
- STARK circuit implementation (Transfer CA–CG, Mint MC1–MC5)
- NullifierSet dual-layer architecture
- IMT lifecycle and epoch transition atomicity
- Supply cap enforcement (MC3 in-circuit)
- STARKPack aggregator soundness

**Tools:** External auditors; provide full source, spec, BENCHMARK.md, test results.

**Success criteria:** Both firms issue signed reports confirming
compliance with the Scalar Master Technical Specification.

**Milestone:** Mainnet
**Status:** NOT STARTED

---

## Status Summary

| Item | Milestone   | Status                        |
|------|-------------|-------------------------------|
| E1   | Testnet     | ✅ COMPLETE (P3-R9, BENCHMARK.md) |
| E2   | Testnet     | ✅ COMPLETE (P3-R1..R7, 107 tests) |
| E3   | Pramainnet  | NOT STARTED (needs TLC/auditor) |
| E4   | Pramainnet  | NOT STARTED (needs TLC/auditor) |
| E5   | Pramainnet  | TARGET READY (needs nightly fuzz run) |
| E6   | Mainnet     | NOT STARTED (needs 2nd implementation) |
| E7   | Mainnet     | NOT STARTED (needs external firms) |

Plonky3 migration (P3-R1..R9) complete. All in-circuit constraints verified.
Remaining: FASE B (epoch orchestrator), E3–E7 (external verification).
