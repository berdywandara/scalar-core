# Empirical Test Plan — Pre-Genesis to Mainnet

This document lists all items that require **empirical testing, formal
verification, or external audit** — not just coding. Each item includes
the required method, tools, milestone, and current status.

---

## Testnet Readiness

### E1 — Hardware Spec Benchmark: Proving Time (§15.6)

**Method:** Run `TransferProver::prove_transfer` with a production-size
trace (10-in/10-out) on hardware meeting the spec: 8 GB RAM, standard
server CPU. Measure wall-clock time over at least 100 runs.

**Tools:** `cargo test --features bench-hardware -- bench_proving_time --nocapture`

**Success criteria:** Mean proving time ≤500 ms; no run exceeds 700 ms.

**Milestone:** Testnet  
**Status:** NOT STARTED (only compact trace benchmarked in Codespace)

---

### E2 — Production Trace Integration & Stress Test

**Method:** Replace the current compact constraint-encoding trace (width 9,
length 16) with the full arithmetised production trace. Verify constraint
counts match spec (§4.4: ~52k for 2-in/2-out, ~260k for 10-in/10-out).
Run under increasing load (1 to 10 inputs).

**Tools:** Winterfell prover, custom test harness.

**Success criteria:** Constraint counts within ±1% of spec; proving time
remains ≤500 ms on hardware spec; no constraint evaluation failures.

**Milestone:** Testnet  
**Status:** NOT STARTED (compact trace in use)

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
**Status:** NOT STARTED (TLC unavailable in Codespace)

---

### E4 — Model-Checking: Deferred Emission Pool (§15.5)

**Method:** Complete the scaffolding in `verification/deferred_pool.tla`
(state transitions for add_residual, release_from_pool, advance_epoch).
Run TLC with `deferred_pool.cfg` to verify all five invariants.

**Tools:** TLA+ Tools (TLC), Java 17+.

**Success criteria:** All invariants hold (Inv1–Inv5); no deadlock;
model covers full cycle of defer and release.

**Milestone:** Pramainnet  
**Status:** NOT STARTED (scaffolding incomplete)

---

### E5 — Fuzz Testing: STARKPack Adversarial (TV5.15)

**Method:** Run the existing fuzz target
`fuzz/fuzz_targets/fuzz_starkpack_adversarial.rs` for 10 million
iterations using `cargo fuzz` (nightly compiler). The target covers
8 attack modes: correlation injection, transcript reset, element
skipping, order manipulation, domain separation bypass, determinism,
batch size boundary.

**Tools:** `cargo fuzz`, Rust nightly, libfuzzer.

**Success criteria:** No crashes, no assertion failures, no
soundness violations detected after 10M iterations.

**Milestone:** Pramainnet  
**Status:** TARGET READY, NOT YET EXECUTED (requires nightly + runtime)

---

## Genesis / Mainnet Readiness

### E6 — Dual Verification: Cross-Crypto-Family (§15.3)

**Method:** Implement a second FRI verifier from scratch using a
different cryptographic library (e.g., a pure Rust FRI implementation
independent of Winterfell). Both implementations must agree on all
valid proofs from the test vector suite and reject all invalid proofs.

**Tools:** Independent FRI library, test vector suite.

**Success criteria:** 100% agreement on valid proofs; 100% agreement
on invalid proofs; no case where one implementation accepts and the
other rejects for a spec-compliant proof.

**Milestone:** Mainnet  
**Status:** NOT STARTED (current Path 2 is parameter-level, not full FRI)

---

### E7 — Two Independent Firm Audits (§15.1)

**Method:** Engage two independent cryptography/formal-verification firms
to audit:
- TLA+ models and TLC/Apalache results
- STARK circuit implementation (Transfer, Mint)
- NullifierSet dual-layer architecture
- IMT lifecycle and epoch transition atomicity
- Supply cap enforcement (MC3)

**Tools:** External auditors; provide full source, spec, and test results.

**Success criteria:** Both firms issue signed reports confirming
compliance with the Scalar Master Technical Specification and
PraGenesis optimisation document.

**Milestone:** Mainnet  
**Status:** NOT STARTED

---

## Status Summary

| Item | Milestone   | Status          |
|------|-------------|-----------------|
| E1   | Testnet     | NOT STARTED     |
| E2   | Testnet     | NOT STARTED     |
| E3   | Pramainnet  | NOT STARTED     |
| E4   | Pramainnet  | NOT STARTED     |
| E5   | Pramainnet  | TARGET READY    |
| E6   | Mainnet     | NOT STARTED     |
| E7   | Mainnet     | NOT STARTED     |

All coding foundations for these tests are complete (FASE A–E).
Remaining work is execution, verification, and external validation.
