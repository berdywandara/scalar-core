# Appendix B — Test Vectors and Cryptographic Reference

**Document:** `SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY`  
**Specification:** `SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY` (2026-07-15)  
**Status:** Final — mandatory verification by two independent implementations before mainnet

> All test vectors MUST be verified by at least two independent implementations  
> (e.g., scalar-stark-p3 Rust/Plonky3 dan satu reference implementation independen) before mainnet launch.

---

## B.1 Introduction

This appendix provides concrete test vectors for every cryptographic primitive and serialization format used in Scalar Network. The goal is to ensure byte-compatibility across independent implementations so that all nodes can communicate without ambiguity.

Each test vector includes:
- **Input** (hexadecimal or descriptive)
- **Expected output** (hexadecimal)
- **Associated parameters** (domain separator, salt, etc.)

---

## B.2 Prerequisites and Conventions

### B.2.1 Hexadecimal Conventions

- All values are represented in **lowercase hexadecimal without `0x` prefix** unless otherwise stated.
- Byte strings are written as concatenated hex. Example: `b"scalar"` → `7363616c6172`
- Integers: **little-endian** for wire serialization; **big-endian** for documentation representation

### B.2.2 Fixed Parameters

| Parameter | Value |
|---|---|
| Field modulus (Goldilocks) | `p = 0xffffffff00000001` (`2⁶⁴ − 2³² + 1`) |
| BLAKE3 output length | 32 bytes |
| Poseidon2 state width | 8 field elements |
| Poseidon2 rate | 4 field elements |
| Poseidon2 full rounds | 8 |
| Poseidon2 partial rounds | 22 |
| Poseidon2 S-box degree | 7 |
| SLH-DSA parameter set | SHAKE-128s (NIST FIPS 205) |
| SLH-DSA signature size | 7,856 bytes |
| Argon2id memory (wallet) | 65,536 KiB (64 MB) |
| Argon2id iterations (wallet) | 3 |
| Argon2id parallelism (wallet) | 1 |
| Argon2id output length (wallet) | 64 bytes |

### B.2.3 Domain Separators

All domain separators are **OSSIFIED** — they cannot change without a hard fork.

| Name | Hex Value | Length (bytes) |
|---|---|---|
| `DOMAIN_NULLIFIER` | `7363616c61725f6e756c6c6966696572` | 16 |
| `DOMAIN_UTXO_COMMITMENT` | `7363616c61725f636f6d6d69746d656e74` | 17 |
| `DOMAIN_SALT` | `7363616c61725f73616c74` | 11 |
| `DOMAIN_SEED` | `7363616c61725f73656564` | 11 |
| `DOMAIN_NMT` | `7363616c61725f6e6d74` | 10 |
| `DOMAIN_NODE_SHORT` | `7363616c61725f6e6f64655f73686f7274` | 17 |
| `DOMAIN_ANCHOR` | `7363616c61725f616e63686f72` | 13 |
| `DOMAIN_VOTE` | `7363616c61725f766f7465` | 11 |
| `DOMAIN_STARK_FS` | `7363616c61725f737461726b5f6673` | 15 |
| `DOMAIN_CHECKPOINT_FS` | `7363616c61725f636865636b706f696e745f6673` | 20 |
| `DOMAIN_BEACON` | `7363616c61725f626561636f6e` | 13 |
| `DOMAIN_TX_ORDER` | `7363616c61725f74785f6f72646572` | 15 |
| `DOMAIN_SEED_KDF` | `7363616c61725f77616c6c65745f6b6466` | 17 |

> **Source:** `core/scalar-crypto/src/domain.rs` — OSSIFIED, verified by assert tests in CI.
> Decode hex to ASCII to confirm. Reference: [SCALAR-PROTOCOL §13.1](../spec/SCALAR-PROTOCOL.md).

---

## B.3 Test Vector Set 1 — Seed Derivation (SCL-SPEC-SEED-001)

**Specification reference:** §13.1–§13.2

### B.3.1 Description

Validates key derivation from a mnemonic using Argon2id, BLAKE3, and the domain separators specified in §13.1–§13.2.

### B.3.2 Input

| Variable | Value |
|---|---|
| `mnemonic` | `scalar abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| `genesis_hash` | `0000000000000000000000000000000000000000000000000000000000000000` (32 zero bytes, for testing) |

**Mnemonic note:** The first word is always `scalar` (0 entropy bits — fixed by protocol). The 11 `abandon` words provide minimum entropy for testing. The final word `about` is the BIP-39 checksum.

**Argon2id parameters for wallet seed derivation:**

```
password    = UTF-8(mnemonic)
salt        = SEED_SALT_PREFIX || genesis_hash
            = 7363616c61725f7632
              || 0000000000000000000000000000000000000000000000000000000000000000
memory      = 65536 KiB (64 MB)
iterations  = 3
parallelism = 1
output_len  = 64 bytes
```

### B.3.3 Expected Output

> **Status:** Placeholder values. MUST be computed by a certified constant-time Argon2id implementation before testnet.  
> Execution time variance must be < ±1% across runs.

| Variable | Length | Expected Value |
|---|---|---|
| `seed` | 64 bytes | `[computed by reference implementation]` |
| `MasterKey` | 32 bytes | `BLAKE3(seed \|\| "scalar_master")` |
| `AccountKey_0` | 32 bytes | `BLAKE3(MasterKey \|\| "account" \|\| 0x0000000000000000)` |
| `SpendKey` | 32 bytes | `BLAKE3(AccountKey_0 \|\| "spend")` |
| `ViewKey` | 32 bytes | `BLAKE3(AccountKey_0 \|\| "view")` |
| `NodeKey` | 32 bytes | `BLAKE3(AccountKey_0 \|\| "node")` |
| `DuressKey_0` | 32 bytes | `BLAKE3(AccountKey_0 \|\| "duress" \|\| 0x0000000000000000)` |

### B.3.4 Verification Checklist

- [ ] Implementation A (Rust/argon2) produces `seed` value X
- [ ] Implementation B (independent) produces identical `seed` value X
- [ ] `BLAKE3(seed || "scalar_master")` matches `MasterKey` in both implementations
- [ ] All derived keys match between implementations
- [ ] Execution time variance < ±1%

---

## B.4 Test Vector Set 2 — Poseidon2 Hash (SCL-SPEC-POSEIDON2-001)

**Specification reference:** §2.1, §3.4, §4.3

**Configuration:** width=12, rate=8, full_rounds=8, partial_rounds=22, sbox_degree=7, field=Goldilocks

### B.4.1 Test 1 — All-Zero Input

| Parameter | Value |
|---|---|
| Input | `[0, 0, 0, 0, 0, 0, 0, 0]` (8 field elements, all zero — t=8) |
| Output (field elements) | `[4904961330882102773, 6914533505831728251, 16060085509051262978, 161169382960502813, 8610401995229161121, 6947968519022847962, 9668808541865791489, 7055543217974479047]` |

### B.4.2 Test 2 — UTXO Commitment

Input is constructed from:

```
value_sscl  = 100000000000000  (100,000 SCL in sSCL; 8 bytes little-endian)
owner_pubkey = 0x0101...01     (32 bytes, all 0x01 — SLH-DSA pubkey field element representation)
secret       = 0x0202...02     (32 bytes, all 0x02)
salt         = 0x0303...03     (32 bytes, all 0x03)
domain       = DOMAIN_UTXO_COMMITMENT = 7363616c61725f636f6d6d69746d656e74 (17 bytes)

commitment = Poseidon2(domain || value_sscl || owner_pubkey || secret || salt)
```

| Parameter | Value |
|---|---|
| Output | `[computed by reference implementation]` |

### B.4.3 Test 3 — Nullifier

```
secret       = 0x0202...02  (32 bytes)
spending_key = 0x0303...03  (32 bytes)
domain       = DOMAIN_NULLIFIER = 7363616c61725f6e756c6c6966696572 (16 bytes)

nullifier = Poseidon2(domain || secret || spending_key)
```

| Parameter | Value |
|---|---|
| Output | `[computed by reference implementation]` |

### B.4.4 Test 4 — Large Input (1024 field elements)

| Parameter | Value |
|---|---|
| Input | Field elements with values `1, 2, 3, ..., 256` (sponge-absorbed in rate-4 chunks) |
| Output | `[computed by reference implementation]` |

### B.4.5 Verification Checklist

- [ ] Both implementations agree on Test 1 output (all-zero permutation)
- [ ] Both implementations agree on Test 2 (commitment construction matches §3.4)
- [ ] Both implementations agree on Test 3 (nullifier matches CA constraint §4.3)
- [ ] Both implementations agree on Test 4 (large input sponge)

---

## B.5 Test Vector Set 3 — SLH-DSA Signatures (SCL-SPEC-SLHDSA-001)

**Specification reference:** §2.1, §7.5  
**Standard:** NIST FIPS 205 — SLH-DSA-SHAKE-128s

### B.5.1 Test Vector

| Variable | Value |
|---|---|
| Keygen seed | `0x0101...01` (32 bytes, all 0x01) |
| Message | `b"scalar_anchor_v1" \|\| epoch_id(1) \|\| node_id_full(32 zero bytes) \|\| chain_head(32 zero bytes) \|\| hb_count(4320 as u64 LE)` |
| `sk` (secret key) | `[derived from seed per FIPS 205]` |
| `pk` (public key) | `[derived from seed per FIPS 205]` |
| `sig` | `[generated, must be exactly 7,856 bytes]` |
| `verify(pk, message, sig)` | `true` |

### B.5.2 Anchor Message Construction

```
chain_head     = BLAKE3(serialize(last_regular_heartbeat))
anchor_message = BLAKE3(DOMAIN_ANCHOR_V1 || epoch_id || node_id_full || chain_head || hb_count)
```

Where:
- `DOMAIN_ANCHOR` = `7363616c61725f616e63686f72` (13 bytes)
- `epoch_id` = 8 bytes little-endian
- `hb_count` = 8 bytes little-endian

### B.5.3 Verification Requirements

- [ ] Implementation matches NIST FIPS 205 official test vectors for SLH-DSA-SHAKE-128s
- [ ] Signature size is exactly 7,856 bytes
- [ ] `verify(pk, anchor_message, sig)` returns `true`
- [ ] Verification time: benchmark B2.1 confirmed 0.479ms (target < 10ms ✅)

---

## B.6 Test Vector Set 4 — STARK Proofs (SCL-SPEC-STARK-001)

**Specification reference:** §4.2–§4.4

### B.6.1 STARK Parameters (OSSIFIED)

| Parameter | Value |
|---|---|
| Field | Goldilocks (`p = 2⁶⁴ − 2³² + 1`) |
| FRI blowup factor | 8 |
| FRI queries | 84 |
| Grinding bits | 23 (D-028) |
| Folding factor | 4 |
| Soundness ε (Scenario B, g=23) | `≤ 2⁻¹²⁰·⁶⁸` (estimated) |

### B.6.2 Test Vector 1 — 2-in/2-out Transfer

**Public inputs:**

```
input_commitments[2]    : two valid UTXO commitments (Poseidon2 outputs on Goldilocks)
input_nullifiers[2]     : two nullifiers
output_commitments[2]   : two new output commitments
fee_total               : 40 sSCL (= 0x28 in u64 LE)
utxo_set_root           : root of SMT containing input commitments
current_active_root     : root of NS_ACTIVE
archived_smt_root       : root of NS_CHECKPOINT
timestamp               : u32 (test value: 1000)
entry_timestamp         : u32 (test value: 900)
crypto_version          : 0x01
```

**Private witness:** Omitted (prover-only).

**Expected output:**

```
proof_bytes         : [STARK proof bytes, target < 150 KB]
verification_result : true
constraint_count    : ~52,088 (2-in/2-out)
```

### B.6.3 Test Vector 2 — 10-in/10-out Transfer

Same structure as Test Vector 1 with 10 inputs and 10 outputs.

```
constraint_count : ~260,000 (10-in/10-out)
# Note: proving time benchmark empiris — lihat docs/reports/BENCHMARK_RESULTS.md
```

### B.6.4 Cross-Implementation Verification Requirement

> Proofs generated by scalar-stark-p3 MUST be verifiable by the second independent STARK implementation.

- [ ] scalar-stark-p3 generates proof for 2-in/2-out → second implementation verifies: `true`
- [ ] Second implementation generates proof → scalar-stark-p3 verifies: `true`
- [ ] Benchmark results: lihat docs/reports/BENCHMARK_RESULTS.md

---

## B.7 Test Vector Set 5 — Canonical Serialization (SCL-SPEC-SERIAL-001)

**Specification reference:** §8.3 (S1–S4), §7.3

### B.7.1 Rules S1–S4

```
S1: node_list sorted ascending by node_id_full (32 bytes)
S2: Manifest timestamp = first second of epoch
S3: All integers little-endian
S4: No optional fields
```

### B.7.2 Object 1: HeartbeatUnit — Regular

**Fields:**

```
node_id_short : deadbeef         (4 bytes)
seq_num       : 1                (u32 LE → 01000000)
timestamp     : 1000             (u32 LE → e8030000)
smt_root      : aa×32            (32 bytes)
prev_hash     : bb×32            (32 bytes)
mac           : cc×32            (32 bytes)
is_anchor     : false            (1 byte → 00)
```

**Expected serialization (hex):**

```
deadbeef 01000000 e8030000
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
00
```

**Total length:** `4 + 4 + 4 + 32 + 32 + 8 + 32 + 32 + 1 = 149 bytes` (v9.1 dengan imt_frontier + imt_count)

### B.7.3 Object 2: CheckpointProof

**Fields:**

```
proof_bytes           : [binary STARK proof data]
archived_smt_root     : 32 bytes
smt_depth             : 20      (1 byte → 14)
from_epoch            : 0       (u64 LE → 0000000000000000)
to_epoch              : 3       (u64 LE → 0300000000000000)
total_archived_count  : 50000   (u64 LE → 50c3000000000000)
```

**Expected serialization (hex suffix — after proof_bytes):**

```
[proof_bytes]
[32 bytes archived_smt_root]
14
0000000000000000
0300000000000000
50c3000000000000
```

### B.7.4 Object 3: EpochRewardManifest (3-node example)

> Full hex dump MUST be provided once reference implementation is stable.

**Structure:**

```rust
EpochRewardManifest {
    epoch_id: 1,                          // u64 LE: 0100000000000000
    reward_root: [u8; 32],               // Merkle root of node_list
    node_list: Vec<NodeRewardEntry>,      // sorted ascending by node_id_full
    spec_version: 0x01,                  // 1 byte
    total_emission_sscl: u64,
    deferred: false,                     // 1 byte: 00
    seed_k: [u8; 32],
    manifest_hash: [u8; 32],
    network_health_digest: [u8; 32],
}

NodeRewardEntry {
    node_id_full: [u8; 32],    // sorted key
    reward_sscl: u64,          // LE
    uptime_weight_fp: u64,     // LE
}
```

### B.7.5 Verification Checklist

- [ ] Two implementations produce byte-identical `HeartbeatUnit` serialization
- [ ] Two implementations produce byte-identical `CheckpointProof` serialization
- [ ] Two implementations produce byte-identical `EpochRewardManifest` serialization
- [ ] `manifest_hash = BLAKE3(serialize(manifest_without_hash_field))` verifies in both

---

## B.8 Test Vector Set 6 — NullifierSet Checkpoint (SCL-SPEC-NS-001)

**Specification reference:** §6.2–§6.3

### B.8.1 Description

Tests the checkpoint operation transitioning from NS_ACTIVE to NS_CHECKPOINT.

### B.8.2 Test Vector

| Parameter | Value |
|---|---|
| NS_ACTIVE initial state | SMT with 10,000 random nullifiers |
| NS_CHECKPOINT prior | Empty proof (epoch 0) |
| Operation | `checkpoint(current_epoch = 3)` |
| `archived_smt_root` | `[computed from 10,000 nullifier SMT]` |
| `total_archived_count` | `10,000` |
| `from_epoch` | `0` |
| `to_epoch` | `3` |
| `verify(checkpoint_proof, archived_smt_root)` | `true` |

### B.8.3 WAL Crash Recovery Test

Simulated crash points:

| Crash Point | Expected Recovery Behavior |
|---|---|
| Before WAL write | Checkpoint not started; NS_ACTIVE unchanged |
| After WAL write, before proof generation | WAL entry detected on restart; checkpoint retried |
| After proof generated, before atomic DB commit | Proof regenerated or reused; commit retried |
| After commit | NS_ACTIVE entries deleted; `active_since_epoch` updated |

**Zero-Gap Property:** At no point during recovery should a nullifier be absent from both NS_ACTIVE and NS_CHECKPOINT.

---

## B.9 Test Vector Set 7 — UTXO Transaction Ordering (SCL-SPEC-TXORDER-001)

**Specification reference:** §8.5

### B.9.1 Description

Validates that the canonical transaction ordering produces an identical `utxo_set_root` across all nodes.

### B.9.2 Test Vector

**Input:** Set of 100 valid transactions with known `tx_hash` values for `epoch_id = 1`

**Ordering key computation:**

```
tx_ordering_key = BLAKE3(
    DOMAIN_TX_ORDER || tx_hash || epoch_id_le64
)
// DOMAIN_TX_ORDER = 7363616c61725f74785f6f726465725f7631 (17 bytes)
// epoch_id = 0100000000000000 (u64 LE for epoch 1)
```

**Expected output:**

| Parameter | Value |
|---|---|
| Sorted transaction order | `[deterministic ordering by tx_ordering_key ascending]` |
| `utxo_set_root` after applying all 100 transactions | `[computed by reference implementation]` |

### B.9.3 Verification Checklist

- [ ] Node A and Node B produce identical `tx_ordering_key` for every transaction
- [ ] Both nodes process transactions in the same order
- [ ] Both nodes produce byte-identical `utxo_set_root`
- [ ] Result is stable across restarts (no randomness in ordering)

---

## B.10 Verification Procedure

### B.10.1 Manual Procedure

1. Reference implementation (Rust/scalar-stark-p3/Plonky3) computes all outputs for each test vector.
2. Second independent implementation (separate codebase) reads the same inputs and computes outputs.
3. Both outputs must be **byte-identical**. Any discrepancy must be investigated and resolved before testnet.

### B.10.2 Automation

Test vectors will be stored in JSON/TOML format in the `scalar-test-vectors` repository. CI scripts will:

```bash
# Example CI check structure
cargo test --package scalar-crypto -- poseidon2_test_vectors
cargo test --package scalar-nullifier -- checkpoint_test_vectors
cargo test --package scalar-stark -- stark_proof_test_vectors
# Cross-implementation comparison run separately
./scripts/cross_verify.sh
```

### B.10.3 Acceptance Criteria

| Test Set | Acceptance Condition |
|---|---|
| SCL-SPEC-SEED-001 | Both Argon2id implementations produce identical 64-byte seed |
| SCL-SPEC-POSEIDON2-001 | All 4 test outputs match between implementations |
| SCL-SPEC-SLHDSA-001 | FIPS 205 official test vectors pass; signature size = 7,856 bytes |
| SCL-SPEC-STARK-001 | Cross-verification passes; benchmark results in docs/reports/BENCHMARK_RESULTS.md |
| SCL-SPEC-SERIAL-001 | Byte-identical serialization for all 3 object types |
| SCL-SPEC-NS-001 | Checkpoint proof verifies; WAL recovery maintains Zero-Gap Property |
| SCL-SPEC-TXORDER-001 | Identical `utxo_set_root` across both implementations |

---

## B.11 Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-07-15 | Initial release — parameters confirmed per SCALAR-PROTOCOL / SCALAR-TECHNICAL. Concrete values are placeholders pending stable reference implementation. |
| 1.1 | (TBD) | Update with concrete values from scalar-stark-p3 and second implementation. |

> This appendix MUST be completed and verified before public testnet.  
> After finalization, any change must go through the Layer 2 governance process and be reflected in the specification.

---

*Aligned with SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY — 2026-07-15*
