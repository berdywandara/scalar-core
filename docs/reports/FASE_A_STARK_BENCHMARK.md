# FASE A — STARK Proving System: Migration to Plonky3 Complete

**Status:** Plonky3 migration P3-R1..R9 complete (commit 32490f1).
Winterfell (scalar-stark) removed from workspace (commit 1bcec9d).
All circuits now run on scalar-stark-p3 (Plonky3 0.5).

---

## Migration Summary

| Sub-phase | Description | Status |
|---|---|---|
| P3-R1..R2 | Setup, ScalarP3Config (OSSIFIED FRI params) | ✅ |
| P3-R3 | Poseidon2Air in-circuit | ✅ |
| P3-R4a..f | TransferAir CA–CG, BatchTransferProver | ✅ |
| P3-R5 | MintAir MC1–MC5 in-circuit | ✅ |
| P3-R6 | ZK blinding (HidingFriPcs) | ✅ |
| P3-R7 | Winterfell removed, all consumers migrated | ✅ |
| P3-R8 | STARKPack native Plonky3 (N=256, soundness 2^-120) | ✅ |
| P3-R9 | Empirical benchmark documented | ✅ |

---

## Parameters (OSSIFIED, spec §4.4)

| Parameter | Value |
|---|---|
| Field | Goldilocks (p = 2^64 − 2^32 + 1) |
| Hash (in-circuit) | Poseidon2 t=8, R_F=8, R_P=22, α=7 |
| FRI log_blowup | 3 (blowup=8) |
| FRI queries | 84 |
| FRI grinding bits | 20 |
| FRI folding | 4 (max_log_arity=4) |
| Soundness classical | ε ~ 2^-128 |
| ZK blinding | HidingFriPcs (feature: zk-blinding, required before mainnet) |

---

## Circuit Architecture

### Transfer Circuit (CA–CG) — BatchTransferProver

Four independent sub-AIRs, each a full Plonky3 proof:

| Sub-AIR | Constraint Group | In-circuit |
|---|---|---|
| OwnershipAir | CA: Poseidon2(nullifier + commitment) | ✅ Poseidon2 via p3-poseidon2-air |
| MembershipAir | CB: IMT_MembershipVerify (depth-32) | ✅ 33×Poseidon2 per input |
| NonMembershipAir | CC: dual SMT_NonMembershipVerify (depth-32×2) | ✅ 32 levels × 2 trees |
| TransferAir | CD/CE/CG: conservation, output, compliance | ✅ 12-column linear AIR |

### Mint Circuit (MC1–MC5) — MintAir

| Sub-AIR | Constraint Group | In-circuit |
|---|---|---|
| MintNullifierAir | MC2: Poseidon2 nullifier | ✅ 2×Poseidon2 |
| MintLinearAir | MC1+MC3+MC4+MC5: supply cap, version, auth | ✅ 5-column linear AIR |

MC3 supply cap: `total_minted + reward ≤ S_E` enforced via public_values
binding to Fiat-Shamir transcript — prover cannot fake values.

---

## Benchmark Results (spec §15.6)

Hardware: AMD EPYC 7763, 4 vCPU, 16 GB RAM, `--release`, CPU-only.
See `BENCHMARK.md` for full details.

| Circuit | Prove | Verify | Size |
|---|---|---|---|
| BatchTransferProof 2-in/2-out | 3,801 ms | 20 ms | 689 KB |
| MintNullifierAir MC2 | 192 ms | 5 ms | 186 KB |
| MintLinearAir MC1+MC3+MC4+MC5 | 307 ms | 1 ms | 50 KB |
| STARKPack N=1 | 3 ms | — | — |
| STARKPack N=4 | 13 ms | — | — |

Spec §4.4 estimate (~3–4 s per proof on standard CPU) confirmed at 3.8 s.
All tiers (A/B/C) can prove without GPU — spec §15.6 satisfied.

---

## Falsifiability (spec §4 DoD pt7)

- Wrong secret → Poseidon2 output mismatch → `check_constraints` panic at prove time
- Wrong IMT path → reconstructed root mismatch → proof rejected by FRI
- Nullifier in SMT → non-zero leaf → root mismatch → rejected
- Supply cap exceeded → public_values mismatch → rejected
- Tampered proof bytes → FRI/DEEP-ALI rejection

---

## Open Items

1. **ZK blinding** — `HidingFriPcs` implemented (feature `zk-blinding`).
   Must be enabled before mainnet (spec §2.1 D-E1).

2. **Second independent implementation** (spec §15.3) — scalar-stark-p3
   is implementation #1. A second Plonky3-based implementation from a
   different codebase is required before mainnet.

3. **UtxoSetSMT sequential hash** (D3) — pre-genesis temporary.
   Must be replaced with IMT-based EpochSMT before testnet
   (Scalar_Optimalisasi_PraGenesis §3.1).

4. **FASE B** — Epoch orchestrator atomicity (IMT reset, EpochState
   integration) not yet implemented.
