# SCALAR-TECHNICAL

> Referensi implementasi Scalar Network.
> Parameter: [SCALAR-PROTOCOL](SCALAR-PROTOCOL.md) | Keamanan: [SCALAR-SECURITY](SCALAR-SECURITY.md)

---

## §1 — Crypto Suite V1

### Poseidon2 (in-circuit hash)
- Field: Goldilocks p = 2^64 − 2^32 + 1
- t=8, alpha=7, R_F=8, R_P=22
- RC source: p3-goldilocks v0.5.3 `GOLDILOCKS_POSEIDON2_RC_8_*`
- Struktur: 86 RC total (32 external_init + 22 internal + 32 external_final)

**Test vector wajib (CI gate):**
Input:  [0, 0, 0, 0, 0, 0, 0, 0]
Output: [4904961330882102773, 6914533505831728251, 16060085509051262978,
161169382960502813, 8610401995229161121, 6947968519022847962,
9668808541865791489, 7055543217974479047]

### SLH-DSA: NIST FIPS 205, sign=394ms, verify=0.479ms, sig=7856B
### BLAKE3: non-ZK operations, selalu dengan domain separator

---

## §2 — Transfer Circuit (CA–CG)

**4 sub-AIR dalam BatchTransferProof:**

| Sub-AIR | Constraint | Waktu (g=23, Codespace) |
|---------|------------|------------------------|
| CA | Ownership via Poseidon2 | ~1.5s |
| CB | UTXO membership IMT depth-32 | ~7.3s (batch=41) |
| CC | Nullifier non-membership dual-layer | ~2.1s |
| CD/CE/CG | Conservation + output + timestamp | ~1.1s |

**Benchmark B1.1-FULL:** prove=7,280ms, verify=20ms, total=695KB

### Public Inputs (OSSIFIED, 44 elemen)
[0] fee_total_sscl | [1] sum_inputs | [2] sum_outputs | [3] crypto_version  
[4..5] entry_ts | [6..7] current_ts | [8..15] utxo_root | [16] cb_verified  
[17..24] null_active_root | [25..32] null_archived_root | [33] cc_verified  
[34] output_nonzero | [35] single_utxo_src | [36..39] commit_hash | [40..43] null_hash

### Constraint Detail
- **CA:** `N[i] = Poseidon2(DOMAIN_NULL || secret || key)`, commitment verified
- **CB:** IMT_MembershipVerify depth-32 atau EpochSMT MerkleVerify
- **CC:** NonMembership NS_ACTIVE AND NS_CHECKPOINT
- **CD:** `sum(inputs) == sum(outputs) + fee_total` (u128)
- **CF:** `fee >= FLOOR = max(40, (in+out)×10)` via bit decomposition
- **CG:** `entry_ts ∈ [current_ts - 1800, current_ts]` via bit decomposition

---

## §3 — Mint Claim Circuit (MC1–MC5)

| Constraint | Deskripsi |
|------------|-----------|
| MC1 | Reward Inclusion: MerkleVerify reward manifest |
| MC2 | Anti Double-Claim: mint_nullifier non-membership |
| MC3 | Supply Cap: serial processing dengan pro-rata reduction |
| MC3-DEP | Deferred Pool: maks 10% E0/epoch, maks 12 epoch |
| MC3-VEST | Bootstrap Vesting epoch 1-6: max_vested = S_E × k/6 |
| MC4 | Reward Validity: amount == floor(E_active × w / W_effective) |
| MC5 | Node Authorization: SLH-DSA verify(NodeKey, claim_message) |

---

## §4 — Incremental Merkle Tree (IMT)

- Depth: 32, Field: Goldilocks
- Leaf: `Poseidon2("scalar_imt_leaf" || leaf || leaf_index)`
- Node: `Poseidon2("scalar_imt_node" || left || right)`
- Genesis: frontier=[0u8;32], count=0
- Reset: atomic — arsipasi EpochSMT → reset IMT → sub-epoch 0 baru

**IMT_MembershipVerify (OSSIFIED):**

leaf_hash = Poseidon2("scalar_imt_leaf" || leaf || leaf_index)
current   = leaf_hash
Untuk level 0..31:
is_right = (leaf_index >> level) & 1
current  = Poseidon2("scalar_imt_node" || [sibling, current] atau [current, sibling])
Return current == root


**Benchmark B3.1:** path_gen=9.034ms, path_size=1024B

---

## §5 — STARKPack Aggregator

- Batch size N=256 (OSSIFIED)
- **Scenario B** (independent union bound): setiap proof diverifikasi terpisah
- ε_final (Scenario B, g=23) ≤ 2^-120.68
- Lihat [SCALAR-SECURITY §1](SCALAR-SECURITY.md) untuk analisis soundness

**Fiat-Shamir transcript:**
Phase 1 per proof: absorb(DOMAIN_SUBEPOCH_FS || proof_hash || pi_hash || constraint_count)
Phase 2: xi_seed = transcript.finalize()
Phase 3: global_fri_root = BLAKE3(DOMAIN_STARK_BATCH || n || xi_seed || proof_hashes[])

---

## §6 — NullifierSet dan WAL

**2-Layer Architecture:**
- NS_ACTIVE: SMT depth-32, ~15MB, 3 epoch terakhir
- NS_CHECKPOINT: Recursive STARK proof, ~150KB

**WAL Three-Phase Commit:**
- Phase 1: Snapshot + WAL write + FSYNC
- Phase 2: STARK proof generation
- Phase 3: Database transaction atomic commit

**Benchmark B5-WAL:** prepare=90ns, commit=326μs, idempotency=✅

---

## §7 — Conviction Lookup Table

τ = 60 hari. Formula: `conviction_fp(t) = floor(1_000_000 × (1 - exp(-t/60)))`

| Hari | conviction_fp |
|------|---------------|
| 1 | 16,529 |
| 30 | 393,469 |
| 60 | 632,121 |
| 180 | 950,213 |
| 365 | 997,772 |

Monotonicity check wajib pass sebagai CI gate.

---

## §8 — Arsitektur Kodebase

**Dependency chain:**
scalar-crypto -> scalar-nullifier -> scalar-emission -> scalar-stark-p3
-> scalar-network -> scalar-node
scalar-sdk   -- API publik saja
scalar-audit -- read-only

**Benchmark summary:**

| Benchmark | Metric | Nilai |
|-----------|--------|-------|
| B1.1-FULL BatchTransferProof | prove | 7,280ms |
| B1.1-FULL | verify | 20ms |
| B1.2-BATCH CB (batch=41, g=23) | per_tx | 923ms ✅ |
| B2.1 SLH-DSA | verify | 0.479ms |
| B3.1 IMT depth-32 | path_gen | 9.034ms |
| B4-SIM Quorum | WAN_50 | 129ms |
| B5-WAL | commit | 326μs |
