# SCALAR PROTOCOL — COMPATIBILITY REPORT (FINAL)
**Generated:** 2026-05-29 (post manual verification)
**Repository:** scalar-core
**Against:** MAD v2.0 (binding) > MTS > OPG

> Automated scan + manual verification on 6 flagged items.
> False positives corrected. See notes per item.

---

## EXECUTIVE SUMMARY

| Status     | Count |
|------------|-------|
| COMPATIBLE | 14    |
| CONFLICT   | 7     |
| MISSING    | 5     |

**All 13 crates present.** Crypto OSSIFIED params (Goldilocks, Poseidon2, FRI) all MATCH.
Poseidon2 alignment (T1.1 core) is largely DONE — only CI test missing.
CB MembershipAir depth-32 is implemented.

---

## CHECK-1: Component Compatibility

### COMPATIBLE

| Component | File | Notes |
|-----------|------|-------|
| Poseidon2 single permutation | `core/scalar-crypto/src/poseidon2_t8.rs` | p3-goldilocks RC, D-010/D-011 compliant |
| IMT hash function | `core/scalar-crypto/src/imt.rs` | Single permutation, correct |
| CA OwnershipAir (P3-R4c) | `core/scalar-stark-p3/src/` | In-circuit Poseidon2, DONE |
| CB MembershipAir (P3-R4d) | `core/scalar-stark-p3/src/membership_air_p3.rs` | depth-32 real implementation |
| TransferAir CD/CE (P3-R4b) | `core/scalar-stark-p3/src/batch_transfer_p3.rs` | DONE |
| SLH-DSA dep | `Cargo.toml` | Present |
| ML-KEM-768 dep | `Cargo.toml` | Present |
| Byzantine Validator Detection | `core/scalar-consensus/` or `core/scalar-network/` | Found |
| BLS pairing | `core/scalar-network/src/subepoch.rs` | FALSE POSITIVE — comment only, no BLS crypto |
| HorizenLabs RC | (not found) | CLEAN |
| 13/13 crates present | `core/`, `client/` | All src/lib.rs exist |
| COMMIT_THRESHOLD=75% | codebase | MATCH |
| W_MATURE_EPOCHS=6 | codebase | MATCH |
| Domain separators (5 checked) | `core/scalar-crypto/` | scalar_nullifier, scalar_commitment, scalar_imt_leaf, scalar_imt_node, scalar_genesis_bootstrap — all MATCH |

### CONFLICT

| # | Component | File | Conflict Detail | MAD Ref |
|---|-----------|------|-----------------|---------|
| C-1 | `winterfell` orphaned dep | `Cargo.toml:21` | In workspace deps but **zero `.rs` files import it** — must be removed to avoid ambiguity | MAD §1.1 |
| C-2 | CF Fee Floor — no bit-decomp | `core/scalar-stark-p3/src/transfer_air/` | `fee_floor` referenced but range proof via bit decomposition absent in AIR | MAD §5.2 D-012 |
| C-3 | CG Timestamp — no bit-decomp / no overflow guard | `core/scalar-stark-p3/src/transfer_air/` | T_MAX_WAIT_EFFECTIVE present but missing: bit-decomp range proof + `current_ts >= entry_ts` overflow guard | MAD §5.2 D-012 |
| C-4 | WAL — not three-phase | `core/scalar-node/src/` | WAL exists but missing: three-phase commit (Prepare/Commit/Abort), snapshot-in-CheckpointWalEntry, idempotency, `proving_key_version` field | ADR-SEC-002 revised |
| C-5 | MC3-DEP/MC3-VEST — circuit pattern unclear | `core/scalar-stark-p3/src/mint_air/` | MC3 referenced, but vesting constraint must be **circuit flag**, not prover-conditional | MAD §20.2 |
| C-6 | Conviction lookup — missing dual-implementer | `client/scalar-governance/` | Table exists but dual-implementer verification (f64 + rug) and monotonicity check absent | MAD §11.3 |
| C-7 | Genesis Ceremony — one-phase only | `core/scalar-node/src/genesis/` | Genesis object structure exists but two-phase protocol (Phase 0 commitment → Phase 1 registration) absent | MAD §3.1 |

### MISSING

| # | Component | Target File | MAD Ref |
|---|-----------|-------------|---------|
| M-1 | `invariant_poseidon2_alignment` CI test | `core/scalar-crypto/tests/` or `core/scalar-stark-p3/tests/` | MAD §1.2 (wajib, CI gate) |
| M-2 | `TAU_CONVICTION = 60` named constant | `client/scalar-governance/src/constants.rs` | MAD §21.1 OSSIFIED |
| M-3 | `NODESCORE_UPTIME_W`, `NODESCORE_PROOF_W`, `NODESCORE_AGE_W` | `core/scalar-node/src/score.rs` | MAD §21.1 OSSIFIED |
| M-4 | P2P ML-KEM-768 **implementation** (dep present, impl absent) | `core/scalar-network/src/transport.rs` | MAD §1.1 D-016 |
| M-5 | Anchor Rate Limiting (A-1, A-2, A-3) | `core/scalar-network/src/anchor.rs` | ADR-SEC-008 |

---

## CHECK-2: OSSIFIED Parameter Values

| Status | Parameter | Expected | Note |
|--------|-----------|----------|------|
| MATCH | Goldilocks p | `0xFFFF_FFFF_0000_0001` | ✅ |
| MATCH | Poseidon2 WIDTH=8 | `8` | ✅ |
| MATCH | Poseidon2 ALPHA=7 | `7` | ✅ |
| MATCH | Poseidon2 R_F=8 | `8` | ✅ |
| MATCH | Poseidon2 R_P=22 | `22` | ✅ |
| MATCH | FRI_BLOWUP=8 | `8` | ✅ |
| MATCH | FRI_QUERIES=84 | `84` | ✅ |
| MATCH | FRI_GRINDING=20 | `20` | ✅ |
| MATCH | W_MATURE_EPOCHS=6 | `6` | ✅ |
| MATCH | COMMIT_THRESHOLD=75% | `75` | ✅ |
| MATCH | SLH-DSA | present | ✅ |
| MISSING | `TAU_CONVICTION` | `60` | Not defined as named const — see M-2 |
| MISSING | `NODESCORE_UPTIME_W` | `500_000` | Not defined as named const — see M-3 |
| MISSING | `NODESCORE_PROOF_W` | `300_000` | Not defined as named const — see M-3 |
| MISSING | `NODESCORE_AGE_W` | `200_000` | Not defined as named const — see M-3 |
| NOTE | `T_MAX_WAIT_MS = 1_800_000` | Layer 2 param (§9.3) | Different from circuit `T_MAX_WAIT_EFFECTIVE = 85_800s` (MAD §21.2) — verify circuit value separately |

---

## CHECK-3: Revoked Components

| Status | Component | Note |
|--------|-----------|------|
| CLEAN | HorizenLabs RC `0x3c7e805adba32e70` | Not found |
| CLEAN | Sponge construction | `poseidon2_t8.rs` explicitly single permutation |
| CLEAN | secp256k1 / ECDSA | Not found |
| CLEAN | BLS pairing (cryptographic) | `subepoch.rs` hit is comment word only |
| CLEAN | ECC EcPoint | Not found |
| NOTE | `Poseidon2T8Hasher` type name | False positive — implements single permutation correctly |

---

## RECOMMENDED WORK ORDER

### Phase A — Resolve CONFLICTS (before any benchmark)

**Urutan wajib — selesaikan conflict dulu:**
A-1  [30 min]  C-1: hapus winterfell dari workspace Cargo.toml
→ cargo build --workspace (verify clean)
A-2  [1 hr]    M-1: tambah invariant_poseidon2_alignment CI test
→ blocks semua circuit benchmark
A-3  [30 min]  M-2 + M-3: definisikan TAU_CONVICTION, NODESCORE_*_W
sebagai named OSSIFIED constants
A-4  [2-3 hr]  C-2 + C-3: CF bit-decomp + CG bit-decomp + overflow guard
→ Transfer proof benchmark BLOCKED sampai ini selesai
A-5  [4-6 hr]  C-4: WAL three-phase commit + CheckpointWalEntry + idempotency
→ Checkpoint benchmark BLOCKED sampai ini selesai
A-6  [2 hr]    C-5: MC3-DEP/MC3-VEST circuit flag pattern
+ verifikasi T_MAX_WAIT_EFFECTIVE=85_800s ada di circuit
A-7  [2 hr]    C-6: Conviction lookup dual-implementer + monotonicity check
A-8  [3-4 hr]  C-7: Genesis Ceremony two-phase protocol
A-9  [2 hr]    NodeScore OSSIFIED test vectors (MAD §22)

### Phase B — Implement MISSING (setelah semua A selesai)
B-1  M-4: P2P ML-KEM-768 implementation (dep sudah ada di Cargo)
B-2  M-5: Anchor Rate Limiting A-1/A-2/A-3

### Phase C — Tier 2 remaining → Tier 3

Per MAD §20.2 order.

---

## BENCHMARK ENGINEER — NOTIFICATION

> **Forward section ini sebelum benchmark dimulai.**
STATUS: 7 CONFLICT, 5 MISSING
Semua benchmark DIBLOKIR sampai Phase A selesai.
Specifically:

Poseidon2 alignment benchmark   → tunggu A-2 (CI test)
Transfer proof full constraints → tunggu A-4 (CF/CG bit-decomp)
WAL checkpoint throughput       → tunggu A-5
Mint circuit MC3                → tunggu A-6
CB recursive proving (B1.2)     → READY — depth-32 implemented

Exception: CB MembershipAir (B1.2-BATCH) dapat di-benchmark
setelah A-2 selesai karena implementasi sudah ada.

---

*Report ini berdasarkan automated scan + manual verification 6 item.*
*Commit hash: run `git rev-parse HEAD` untuk referensi.*
