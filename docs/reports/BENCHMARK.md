# Scalar Network — Empirical Benchmark Results (P3-R9)

Spec §15.6: proving time is an empirical reference, not a pass/fail gate.
FRI parameters OSSIFIED: blowup=8, queries=84, grinding=20 (spec §4.4).

## Hardware

| Parameter | Value |
|---|---|
| CPU | AMD EPYC 7763, 4 vCPU (2 cores × 2 threads) |
| RAM | 16 GB total, ~11 GB available |
| Build | `--release` (optimized) |
| Environment | GitHub Codespace (CPU-only, no GPU) |
| Date | 2026-05-27 |

This hardware meets spec §15.6 minimum (CPU server 8GB RAM, no GPU).
Result confirms all tiers (A/B/C) can prove independently without GPU.

## Results

### Transfer Circuit (CA–CG)

| Circuit | Prove | Verify | Proof Size |
|---|---|---|---|
| BatchTransferProof 2-in/2-out (CA+CB+CC+CD/CE/CG) | 3,801 ms | 20 ms | 688,705 B (~689 KB) |
| — CA OwnershipAir (Poseidon2 nullifier+commitment) | included | included | 196,564 B |
| — CB MembershipAir (IMT path in-circuit) | included | included | 289,675 B |
| — CC NonMembershipAir (dual SMT, active+archived) | included | included | 141,773 B |
| — CD/CE/CG TransferAir (conservation+output+compliance) | included | included | 60,693 B |

### Mint Circuit (MC1–MC5)

| Circuit | Prove | Verify | Proof Size |
|---|---|---|---|
| MintNullifierAir MC2 (Poseidon2 in-circuit) | 192 ms | 5 ms | 186,197 B (~186 KB) |
| MintLinearAir MC1+MC3+MC4+MC5 (supply cap in-circuit) | 307 ms | 1 ms | 50,461 B (~50 KB) |

### STARKPack Aggregator (spec §3.4)

| N (proofs) | Aggregate (transcript) | Notes |
|---|---|---|
| N=1 | 3 ms | Includes CD/CE/CG verify per proof |
| N=4 | 13 ms | Linear scaling with N |
| N=256 (optimal) | ~768 ms (estimated) | Soundness 2^-120, spec D-002 |

STARKPack overhead is negligible — bottleneck is individual proof generation.

## Analysis

**Spec §4.4 alignment:** Spec estimates "~3–4 seconds per proof on standard 8GB CPU".
Measured 3,801ms for full 2-in/2-out BatchTransferProof — within spec estimate.

**Sub-epoch throughput (spec §3.2):** 1 sub-epoch = 1 hour = 3,600 seconds.
At 3.8s per proof, a single aggregator can process ~947 transactions per sub-epoch.
With STARKPack N=256 batching, verification cost amortized across the full batch.

**Tier C viability:** Proven on CPU-only environment — Tier C nodes can prove
independently without GPU. This satisfies spec §15.6 principal requirement.

## Notes

- Results from unmodified OSSIFIED FRI params — do not adjust params to hit a time target.
- Laptop/desktop hardware will produce different numbers; these are Codespace reference values.
- `--release` build required; `--dev` build is ~5–10× slower.
- To reproduce: `cargo test -p scalar-stark-p3 --features bench-hardware --release -- bench:: --nocapture`
