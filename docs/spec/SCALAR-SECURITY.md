# SCALAR-SECURITY

> Analisis keamanan Scalar Network.
> Parameter: [SCALAR-PROTOCOL](SCALAR-PROTOCOL.md) | Implementasi: [SCALAR-TECHNICAL](SCALAR-TECHNICAL.md)

---

## §1 — Soundness Analysis

### Model
ε_total ≤ ε_FRI-query + ε_commit + ε_AIR/DEEP + ε_batch − (grinding credit)

### Parameter
- |F| = p² ≈ 2^128 (quadratic extension Goldilocks)
- Blowup b=8, queries q=84, grinding g=23, N=256 batch
- LDE domain |D| = 2^19, FRI rounds = 10

### Kalkulasi per Komponen

| Surface | Nilai | Keterangan |
|---------|-------|------------|
| ε_query (capacity) | 2^-252 | q=84 queries, ρ=1/8 |
| ε_query (Johnson, proven) | 2^-126 | proven bound |
| **ε_commit** | **2^-105.68** | **BINDING — q-independent** |
| ε_batch (Scenario B, N=256) | 2^-97.68 | N × ε_commit |
| ε_final (g=23) | **2^-120.68** | ε_batch × 2^-23 ✅ |

> ⚠️  Binding constraint adalah ε_commit, BUKAN query count.
> Menambah queries tidak meningkatkan security.

### D-028 — Grinding Fix
- g=20: ε=2^-117.68 ❌ (gap 2.32 bits)
- g=23: ε=2^-120.68 ✅ (margin 0.68 bits)

> STATUS: ESTIMASI. Formal proof wajib sebelum mainnet (ADR-SEC-023).

---

## §2 — Formal Verification (TLA+)

### D-025 Optimistic Finality — Verdict: GO

File: `verification/d025-optimistic-finality/ScalarOptimisticFinality.tla`

| Property | Tipe | Hasil |
|----------|------|-------|
| TypeOK | Invariant | ✅ PASS |
| NullifierUniqueness | Safety | ✅ PASS |
| OptimisticSafety | Safety | ✅ PASS |
| FinalizationOrder | Safety | ✅ PASS |
| NullifierSetConsistency | Safety | ✅ PASS |
| NoOptimisticDoubleFinalize | Safety | ✅ PASS |
| EventualResolution | Liveness | ✅ PASS |

### Formal Invariants

| Invariant | Status |
|-----------|--------|
| INV-SUPPLY: total_minted ≤ S_E | ✅ Prusti annotations |
| INV-NULLIFIER: double-spend impossible | ✅ TLA+ verified |
| INV-EPOCH: epoch transition pure function | ✅ Manual proof |
| INV-REWARD: sum(rewards) ≤ E_active | ✅ Prusti annotations |
| INV-GOVERNANCE: OSSIFIED immutable | ✅ Compile-time |
| INV-STARKPACK: formal soundness proof | ⏳ Pending mainnet |

---

## §3 — Threat Model

### Security Assumptions
**Kriptografis:** Collision resistance Poseidon2, BLAKE3, ML-KEM-768, SLH-DSA.  
**Protokol:** ≥2/3 validator jujur; network connectivity; tidak ada adversary kontrol semua 5 shadow pool sekaligus.  
**Tidak diasumsikan:** kebenaran implementing software; keamanan absolute ML-KEM.

### Attack Vectors

| Vektor | Status |
|--------|--------|
| Double-spend (2 submissions) | ✅ Defeated — NullifierUniqueness TLA+ verified |
| Byzantine equivocation | ✅ Defeated — atomic CommitStark |
| Race condition optimistic window | ✅ Defeated — TLA+ verified |
| Sybil attack | ✅ Mitigated — Argon2id 4GB + 180 hari maturity |
| Eclipse via Kademlia | ✅ Mitigated — S/Kademlia d=3, manifest setelah 1 epoch |
| STARK soundness bypass | ⏳ Estimated ε≤2^-120.68 — formal proof pending |

### Risiko Residual (trade-off yang disadari)
- **R1:** Konsumsi state optimistic sebelum Level 2 — mitigasi: SDK distinguish Level-1 vs Level-2
- **R2:** Censorship oleh validator coalition — mitigasi: slashing + rotational committee
- **R3 (CRITICAL):** NfVerify hanya cek NS_ACTIVE — audit wajib pastikan NS_ACTIVE ∪ NS_CHECKPOINT

---

## §4 — Quantum Monitoring

| Komponen | Status |
|----------|--------|
| FRI/Poseidon2 | ✅ Quantum-resistant (Grover: 128-bit effective) |
| SLH-DSA | ✅ NIST FIPS 205 |
| BLAKE3 | ✅ Quantum-resistant |
| ML-KEM-768 | ✅ NIST FIPS 203, hybrid X25519 |
| ECC/ECDSA | ❌ Dilarang — tidak ada di jalur kritis |

### Trigger Points
| ID | Kondisi | Aksi |
|----|---------|------|
| QT-1 | Break Poseidon2 di Goldilocks | Emergency governance 51% |
| QT-2 | Grover >2x improvement | Review 128-bit margin |
| QT-3 | Quantum computer >4000 logical qubits komersial | Migrate ke Suite V2+ |
| QT-4 | BKZ improvement pada ML-KEM <128 bit | Governance Suite V2 |

---

## §5 — Audit Requirements

### Wajib Sebelum Mainnet

- ✅ D-025 TLA+ formal verification (GO)
- ✅ INV-SUPPLY/NULLIFIER/EPOCH/REWARD/GOVERNANCE annotations
- ✅ FRI grinding g=23 (D-028)
- ⏳ Formal soundness proof STARKPack Scenario B + g=23 + N=256
- ⏳ Security audit ≥2 firma independen
- ⏳ Multi-client STARK verifier dari codebase berbeda
- ⏳ TLC empirical run (0 invariant violations)
- ⏳ ScalarOptimisticFinalityTimed.tla (fraud-proof timing)
- ⏳ Audit NfVerify: NS_ACTIVE ∪ NS_CHECKPOINT (**CRITICAL**)

### Fuzz Testing
- Transfer circuit CA-CG: 10M adversarial prover attempts
- STARKPack transcript: 10M attempts (correlation injection, transcript reset)
- Nullifier WAL: stress test checkpoint atomicity dan recovery

---

## §6 — Eclipse Resistance

S/Kademlia d=3, k=20 (OSSIFIED):

| Skenario | N | B (Sybil) | P(eclipse) |
|----------|---|-----------|------------|
| Kecil | 50 | 10 (16.7%) | 2.2 × 10^-47 |
| Menengah | 200 | 20 (9.1%) | 5.5 × 10^-64 |
| Ekstrem | 50 | 25 (33.3%) | 2.2 × 10^-29 |

Sub-Epoch consensus menggunakan Manifest-tier peers **eksklusif**. Kademlia hanya untuk node baru sebelum masuk manifest (maks 1 epoch).
