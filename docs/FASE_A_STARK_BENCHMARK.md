# FASE A — STARK Proving System: Benchmark & Limitations

Status: Transfer (CA-CG) and Mint (MC1-MC5) circuits implemented as real
Winterfell AIR. Verifier performs real FRI/DEEP-ALI verification. Arbitrary,
tampered, and wrong-public-input proofs are rejected.

## Parameters (OSSIFIED, spec 4.4)

| Parameter        | Value                        |
|------------------|------------------------------|
| Field            | Goldilocks (2^64 - 2^32 + 1) |
| Field extension  | Quadratic                    |
| FRI queries      | 84                           |
| FRI blowup       | 8                            |
| Grinding bits    | 20                           |
| FRI folding      | 4                            |
| Remainder degree | 7                            |
| Trace length     | 16 (power of two)            |
| Conjectured sec. | ~120 bits                    |

With FieldExtension::None the 64-bit Goldilocks base field yields only ~52-56
bits of conjectured security. The Quadratic extension raises this to ~120 bits,
matching spec 4.4 (epsilon ~ 2^-128 classical soundness).

## Proving-time benchmark (spec 15.6)

The proving-time test is gated behind the `bench-hardware` cargo feature and is
#[ignore]d by default so CI on shared runners does not assert hardware timing
(per the FASE A decision: benchmark on hardware spec, not Codespace).

Run on hardware spec (8 GB RAM, standard server CPU):

    cargo test -p scalar-stark --features bench-hardware -- bench_proving_time --nocapture

### Recorded runs

| Environment                       | Transfer prove | Limit (15.6) | Pass |
|-----------------------------------|----------------|--------------|------|
| GitHub Codespace (~2 vCPU shared) | 367-370 ms     | <= 700 ms    | yes  |

Even on a shared 2-vCPU Codespace (below the 15.6 reference hardware), the
2-in/2-out-class circuit proves in ~370 ms, within the 400-700 ms hardware
variance band and below the 500 ms target. A run on dedicated 8 GB/server-CPU
hardware is expected to be at or under the 500 ms target.

NOTE: The trace here is the constraint-encoding trace (width 9, length 16), not
a full 2^20-row production trace. The 15.6 target applies to the production
circuit; this benchmark establishes the AIR/prover/verifier stack is real and
well within budget for the encoded constraint system.

## Open limitations (declared, not hidden)

1. STARKPack (A.5 / K7-02): aggregate_real_proofs verifies every proof with the
   real Winterfell verifier and derives global_fri_root from the real proof
   commitments (no longer caller-supplied). It is aggregation OVER verified
   proofs, not a single recursive low-degree FRI proof that re-proves all N at
   once. Full recursive FRI folding remains future work (Research Package 3.4).

2. Dual verification (A.7 / 15.3): dual_verify_real_proof runs the Winterfell
   verifier (impl 1) and the independent semantic verifier (impl 2) and requires
   agreement; a proof rejected by either is rejected overall. The two
   implementations check overlapping but not byte-identical statements.
   True constraint-for-constraint multi-client STARK agreement remains future
   work.

3. Production trace sizing: constraint counts in air.rs
   (compute_total_constraints) describe the spec target circuit (~40k-202k
   constraints). The current AIR encodes constraint results into a compact
   trace; mapping each constraint group to a full arithmetized sub-trace at
   production row counts is a follow-on task.
