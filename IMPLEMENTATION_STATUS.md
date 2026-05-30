# SCALAR IMPLEMENTATION STATUS
**Updated:** 2026-05-31
**HEAD:** $(git rev-parse --short HEAD)

---

## TIER 1 — COMPLETE ✅ (before Genesis Ceremony)

| Component | Commit | Status |
|-----------|--------|--------|
| Poseidon2 alignment + CI gate (D-010, D-011) | `515b6ed` | ✅ |
| D-026 T_MAX_WAIT CONSTRAINED clarification | `c50443e` | ✅ |
| OSSIFIED constants TAU_CONVICTION + NODESCORE weights | `acb2b83` | ✅ |
| WAL Three-Phase Commit (ADR-SEC-002) | `8024c6a` | ✅ |
| MC3-DEP + MC3-VEST circuit flags | `2087e2a` | ✅ |
| Conviction dual-impl + monotonicity | `ea8a1a4` | ✅ |
| Genesis Ceremony two-phase + GVP-1..4 (ADR-SEC-009) | `99d24b6` | ✅ |

## TIER 2 — COMPLETE ✅ (before External Testnet)

| Component | Commit | Status |
|-----------|--------|--------|
| NodeScore formula + OSSIFIED test vectors | `72c3708` | ✅ |
| ML-KEM-768 real impl + Hybrid X25519 (D-016) | `3e06c67` | ✅ |
| Anchor Rate Limiting A-1/A-2/A-3 (ADR-SEC-008) | `2495dbb` | ✅ |

## TIER 3 — COMPLETE ✅ (before Mainnet)

| Component | Commit | Status |
|-----------|--------|--------|
| Dandelion++ Reduced Anonymity Mode (ADR-SEC-018) | `45f4d9c` | ✅ |
| Crypto-Agility Framework (D-014) | `f06a2f4` | ✅ |
| MEV Protection commit-reveal + redistribution (D-018) | `41a6bcf` | ✅ |
| Privacy Layer — value commitment + stealth + ZK-KYC (D-017) | `5d61872` | ✅ |
| Formal Verification INV-SUPPLY/NULLIFIER/EPOCH/GOVERNANCE (D-021) | `b709d3a` | ✅ |

---

## BENCHMARK STATUS — ALL COMPLETE ✅

| Benchmark | Key Result | Commit |
|-----------|-----------|--------|
| B1.1 Transfer proof (sub-AIR) | prove=1075ms, verify=3ms, 77KB | `9b1c611` |
| B1.1-FULL BatchTransferProof | prove=7280ms, verify=20ms, 695KB | `195062d` |
| B2.1 SLH-DSA latency | sign=394ms, verify=0.479ms, 7856B | `92f6aa5` |
| B3.1 IMT depth-32 path gen | 9.034ms/path, all correct | `92f6aa5` |
| B4-SIM Quorum formation | WAN_50=129ms, LOCAL=11ms | `92f6aa5` |
| B5-WAL checkpoint throughput | prepare=90ns, commit=326μs | `9b1c611` |

## BENCHMARK ENGINEER DECISIONS

| Decision | Verdict |
|----------|---------|
| D-023 MicroCommitment | CONDITIONAL GO (TRIGGER_TX=41, await B1.2-BATCH) |
| D-024 Multi-speed Heartbeat | GO (SLH-DSA verify=0.479ms << 10ms) |
| D-025 Optimistic Finality | NO-GO (Research Paper 2 pending) |

---

## PENDING (Tier 4 / External)

| Item | Owner | Notes |
|------|-------|-------|
| B1.2-BATCH recursive CB proving | BE | After testnet infra |
| B5-WAL-PERSISTENT re-bench | Coding Team | After sled/file backend |
| Research Paper 2 TLA+/Alloy | Research Track | For D-025 GO |
| Formal Soundness Proof STARKPack | External ZK researchers | ADR-SEC-023 |
| Security audit ≥2 independent firms | External | Before mainnet |
| Multi-client STARK (2nd impl) | External | MAD §15.3 |
