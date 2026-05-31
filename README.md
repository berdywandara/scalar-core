# Scalar Network

> **"Truth by Mathematics, Not by Majority."**  
> **"Epoch by Sequence, Not by Clock."**  
> **"Governance by Genuine Operation, Not by Stakes."**  
> **"Hardened by Determinism, Secured by Analysis."**

Scalar Network is a **post-quantum, privacy-by-default digital cash system** that operates without a blockchain. Every transaction is proven valid by a zero-knowledge STARK proof; double-spend prevention is enforced by a two-layer Sparse Merkle Tree NullifierSet. Mathematical certainty replaces social agreement.

**Conceived and designed by [Berdy Wandara](https://github.com/berdywandara).**  
**Specification:** `SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY` — 2026-07-15

---

## Table of Contents

- [Core Philosophy](#core-philosophy)
- [Why Post-Quantum?](#why-post-quantum)
- [Cryptographic Stack](#cryptographic-stack)
- [Architecture Overview](#architecture-overview)
- [How a Transaction Works](#how-a-transaction-works)
- [Proof-of-Uptime Emission](#proof-of-uptime-emission)
- [NullifierSet (2-Layer)](#nullifierset-2-layer)
- [Supply Parameters](#supply-parameters)
- [Node Tiers](#node-tiers)
- [Governance](#governance)
- [Network Resilience](#network-resilience)
- [Repository Structure](#repository-structure)
- [Running a Node](#running-a-node)
- [Development Status](#development-status)
- [Design Principles](#design-principles)
- [License](#license)
- [Authors](#authors)

---

## Core Philosophy

Traditional blockchains ask: *"Do enough nodes agree this transaction is valid?"*

Scalar asks: *"Can the sender prove — mathematically, beyond doubt — that this transaction is valid?"*

If the zk-STARK proof verifies, the transaction is accepted. No miners. No validators. No majority vote. Three trust assumptions underpin the entire system:

1. **BLAKE3** collision resistance
2. **Poseidon2** collision resistance  
3. **Goldilocks field arithmetic** correctness (`p = 2⁶⁴ − 2³² + 1`)

No trusted setup. No elliptic curves. No administrator key.

---

## Why Post-Quantum?

Bitcoin and Ethereum rely on elliptic curve cryptography. A sufficiently powerful quantum computer running Shor's algorithm can break these schemes — deriving private keys from public keys. Scalar is built from the ground up with quantum-resistant hash-based primitives only.

---

## Cryptographic Stack

| Purpose | Algorithm | Standard / Note |
|---|---|---|
| ZK Proof System | zk-STARK (Plonky3 0.5) | Hash-based; no trusted setup; ZK blinding via HidingFriPcs |
| In-circuit Hash | Poseidon2 (Goldilocks field) | ZK-optimized; ~200–400 constraints/op |
| Out-of-circuit Hash | BLAKE3 | MAC, key derivation, Fiat-Shamir transcript |
| Post-Quantum Signatures | SLH-DSA-SHAKE-128s | NIST FIPS 205; 7,856-byte signature |
| Key Derivation (wallet) | Argon2id | 64 MB / 3 iter / 1 parallel |
| Key Derivation (node ID) | Argon2id | 4 GB / 3,600 iter (Tier A/B) |
| Channel Encryption | ChaCha20-Poly1305 | Dandelion++ stem phase |

**No elliptic curves anywhere in this stack.**

### Domain Separators (OSSIFIED)

All hash contexts use unique domain separators to prevent cross-context collisions.

| Context | Domain Separator |
|---|---|
| Sub-epoch hash | `scalar_subepoch` (15 bytes) |
| STARKPack Fiat-Shamir | `scalar_subepoch_fs` (18 bytes) |
| STARKPack batch | `scalar_stark_batch` (18 bytes) |
| UTXO set (CB constraint) | `scalar_utxo_set` (15 bytes) |
| IMT leaf | `scalar_imt_leaf` (15 bytes) |
| IMT node | `scalar_imt_node` (15 bytes) |
| Anchor signature | `scalar_anchor` (13 bytes) |
| Wallet KDF | `scalar_wallet_kdf` (17 bytes) |

Complete list of 25 OSSIFIED domain separators: [SCALAR-PROTOCOL §13.1](docs/spec/SCALAR-PROTOCOL.md)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SCALAR NETWORK NODE                         │
├─────────────────────────────────────────────────────────────────┤
│  scalar-node          — Boot, state machine, RPC (:7777)        │
├─────────────────────────────────────────────────────────────────┤
│  scalar-network       — P2P: gossipsub + Kademlia DHT           │
│    transport/internet — libp2p TCP + Noise + Yamux              │
│    transport/tor      — Tor 3-hop hidden services               │
│    transport/lora     — LoRa/HF radio (State Beacon 44 bytes)   │
│    dandelion++        — Stem 90% prob / ChaCha20 / 100–5000 ms  │
├─────────────────────────────────────────────────────────────────┤
│  scalar-consensus     — Epoch manifest, DMM, UTXO set ordering  │
├─────────────────────────────────────────────────────────────────┤
│  scalar-nullifier     — 2-Layer NullifierSet (NS_ACTIVE + NS_CHECKPOINT) │
├─────────────────────────────────────────────────────────────────┤
│  scalar-stark-p3      — Transfer Circuit (CA–CG) + Mint (MC1–MC5) │
│    constraints/       — Poseidon2 in-circuit only               │
├─────────────────────────────────────────────────────────────────┤
│  scalar-crypto        — Poseidon2, SLH-DSA, BLAKE3, Argon2id    │
├─────────────────────────────────────────────────────────────────┤
│  scalar-wallet-core   — Key derivation, coin selection, tx build │
├─────────────────────────────────────────────────────────────────┤
│  scalar-audit         — Read-only audit / ZK verification        │
├─────────────────────────────────────────────────────────────────┤
│  scalar-sdk           — Client-utility layer (public API only)   │
└─────────────────────────────────────────────────────────────────┘
```

**Crate dependency chain (strict):**
```
scalar-crypto → scalar-nullifier → scalar-emission → scalar-stark-p3
             → scalar-network → scalar-node
scalar-sdk   (public API only — no direct protocol crate imports)
scalar-audit (read-only; no private key access)
```

---

## How a Transaction Works

```
1. PROVE  (wallet, local)
   Commitment: C = Poseidon2(DOMAIN_COMMITMENT_V2 ‖ value ‖ owner_pubkey ‖ secret ‖ salt)
   Nullifier:  N = Poseidon2(DOMAIN_NULL ‖ secret ‖ spending_key)
   
   STARK proof satisfies 7 constraint groups:
     CA — Ownership: N and C computed correctly from private witness
     CB — UTXO membership: C ∈ utxo_set_root (snapshot of epoch k-1)
     CC — Dual non-membership: N ∉ NS_ACTIVE ∧ N ∉ NS_CHECKPOINT
     CD — Value conservation: Σ inputs = Σ outputs + fee_total
     CE — Output integrity: each output commitment valid, value ∈ D1–D17
     CF — Authorization: knowledge of owner_pubkey + SLH-DSA signature
     CG — Protocol compliance: crypto_version, anti-censorship timestamp

2. BROADCAST  (Dandelion++ privacy transport)
   Stem phase (90% probability): forward to single peer with random delay 100–5000 ms
   Fluff phase: gossipsub broadcast to all peers

3. VERIFY & RECORD  (every node, independently)
   a. Verify SLH-DSA signature (out-of-circuit)
   b. Verify STARK proof  (~5–20 ms)
   c. Check N ∉ NS_ACTIVE and N ∉ NS_CHECKPOINT
   d. Insert N into NS_ACTIVE → SMT root updates
   No vote. No coordination. Pure mathematics.
```

### STARK Parameters (OSSIFIED)

| Parameter | Value |
|---|---|
| Field | Goldilocks (`p = 2⁶⁴ − 2³² + 1`) |
| FRI blowup factor | 8 |
| FRI queries | 84 |
| Grinding bits | 23 (D-028) |
| Folding factor | 4 |
| Soundness ε (Scenario B, g=23) | ≤ 2⁻¹²⁰·⁶⁸ |
| Constraints (2-in/2-out) | ~52,088 |
| Constraints (10-in/10-out) | ~260,000 |
| Proving time (Codespace 4vCPU) | ~7.3s full proof; ~1.1s sub-AIR |

---

## Proof-of-Uptime Emission

Scalar rewards nodes for contributing to network liveness — not for computing power.

### Emission Formula

```
E(k)        = E₀ × (1 − M_E(k−1) / S_E)²
E_active(k) = max(E(k), E_TAIL)

E₀     = 126,000 SCL/epoch
E_TAIL = 1,000 SCL/epoch
```

### Epoch Structure

- **1 Epoch** = 45,600 seconds (~12.67 hours) = 24 sub-epochs
- **1 Sub-Epoch** = 1,900 seconds (~31.7 minutes) — UTXO finality unit
- Heartbeat interval: 120 seconds target, 300 seconds minimum (Rule T-4)
- Epoch boundaries determined by `seq_num` (Rule T-1), **not wall-clock time**

### Uptime Weight

```
w_i(k) = (700,000 × uptime_ratio + 300,000 × root_alignment) / 1,000,000
```

### Epoch Reward Manifest Consensus

1. **Aggregator selection** — deterministic from `seed_k = BLAKE3("scalar_seed_v1" ‖ committed_manifest_hash(k-1))`
2. **Validator quorum** — 7/10 validators must agree
3. **Fallback: DMM** — if no quorum, every synced node independently builds a Deterministic Minimal Manifest from local heartbeat data; output is bit-identical across all honest nodes
4. **UTXO set root** — transactions ordered by `tx_ordering_key = BLAKE3(DOMAIN_TX_ORDER ‖ tx_hash ‖ epoch_id)` before SMT update; ensures identical `utxo_set_root` across all nodes

---

## NullifierSet (2-Layer)

| Layer | Structure | Contents | Size |
|---|---|---|---|
| NS_ACTIVE | Sparse Merkle Tree depth-32 | Nullifiers from last 3 epochs | ~15 MB |
| NS_CHECKPOINT | Recursive STARK proof | All nullifiers before NS_ACTIVE | ~150 KB |

**Zero-Gap Property:** Checkpoint operation uses Write-Ahead Log (WAL) ensuring no nullifier can fall between the two layers during an atomic checkpoint transition.

**Checkpoint interval:** every 3 epochs. Max 200,000 nullifiers per checkpoint batch.

---

## Supply Parameters

```
S_MAX  = 21,000,000 SCL  = 2,100,000,000,000,000 sSCL   (hard cap, ossified)
S_E    = 18,900,000 SCL  = 1,890,000,000,000,000 sSCL   (PoU emission pool)
S_R    = 2,100,000  SCL  =   210,000,000,000,000 sSCL   (tail emission backstop)

1 SCL  = 100,000,000,000 sSCL (smallest unit)
```

**17 fixed denominations (D1–D17):** 1 sSCL → 10,000,000,000,000,000 sSCL  
Fungibility guarantee: two UTXOs of the same denomination are cryptographically indistinguishable.

**Bootstrap vesting:** first 6 epochs — linear vesting, only `(k+1)/6` of reward available.

---

## Node Tiers

| Tier | Hardware | Argon2id | NodeScore Cap | Aggregator | NMT Peer | Governance |
|---|---|---|---|---|---|---|
| A — Dedicated | 8 GB RAM, 50 GB SSD, 10 Mbps | 4 GB / 3,600 iter | 1,000,000 | ✅ | ✅ (score >800k) | Full (1,000,000 fp) |
| B — Cloud + TEE | Same + SGX/SEV | 4 GB / 3,600 iter | 1,000,000 | ✅ (with TEE) | ✅ (score >800k) | Full (1,000,000 fp) |
| C — Mobile | Low-resource | 16 MB / 100 iter | 600,000 | ❌ | ❌ (auto-excluded) | Capped (200,000 fp) |

**Tier C (prefix `0xFE`):** can send heartbeats and earn proportional rewards but is automatically excluded from NMT peer selection (threshold 800,000 > cap 600,000) and governance power is limited to 200,000 fp to prevent cheap-node Sybil attacks.

### Node ID Generation

```rust
node_id_full = Argon2id(
    input       = UTF8(mnemonic),
    salt        = b"scalar_nodeid" || genesis_hash,
    memory      = 4 GB,   // Tier A/B
    iterations  = 3600,
    parallelism = 1,
    output_len  = 32,
)
node_id_short = BLAKE3(b"scalar_node_short_v1" || node_id_full)[0..4]
```

---

## Governance

- **Voting identity:** `node_id_full` — no SCL stake required
- **Eligibility:** maturity ≥ 342 epochs (180 days) of active participation
- **Conviction factor:** smooth curve τ=60 days: day-1=16,529 fp → day-30=393,469 fp → day-365=997,772 fp; no cliff

```
GP(i,t) = min(
    conviction_factor(t_days) × min(maturity(i,k), W_MATURE) / 1_000_000,
    GOV_MAX_FP_FOR_TIER(i)
)

Tier A/B: GOV_MAX_FP = 1,000,000
Tier C:   GOV_MAX_FP = 200,000
```

**Fork thresholds:** commit 75% / abort 67% / emergency 51%

**Anti-Sybil cost:** running a mature Tier A/B node for >180 days at high uptime. No minimum SCL stake.

---

## Network Resilience

| Condition | Transport |
|---|---|
| Normal | Internet — libp2p TCP + Noise + Yamux |
| Censored | Tor 3-hop hidden services |
| Internet down | LoRa mesh radio (40 km range) / HF Radio (continental) |
| Local | State Beacon — 44-byte authenticated UDP-like messages |

**NMT (Network Median Time):** 23 deterministic peers + 1 random slot (ChaCha20 seeded from `BLAKE3(seed_k ‖ "nmt_random")`). Only nodes with NodeScore > 800,000 are eligible. Eclipse resistance: max 3 nodes per /24 subnet, 5 per ASN, 4 per region.

---

## Repository Structure

```
scalar-core/
├── core/                         # Protocol crates
│   ├── scalar-crypto/            # Poseidon2, SLH-DSA, BLAKE3, Argon2id
│   ├── scalar-nullifier/         # 2-layer NullifierSet
│   ├── scalar-stark-p3/          # Transfer Circuit (CA-CG) + Mint (MC1-MC5)
│   ├── scalar-stark-p3-verify/   # Independent verifier
│   ├── scalar-network/           # P2P networking, Dandelion++
│   ├── scalar-consensus/         # Epoch manifest, DMM, UTXO ordering
│   ├── scalar-emission/          # PoU emission formula, Deferred Pool
│   ├── scalar-fees/              # Fee model
│   ├── scalar-node/              # Node binary, state machine, RPC
│   └── scalar-compliance/        # Compliance hooks
├── client/                       # Client crates
│   ├── scalar-wallet-core/       # Key derivation, coin selection, tx builder
│   ├── scalar-audit/             # Read-only audit
│   ├── scalar-governance/        # Node-backed governance
│   ├── scalar-sdk/               # Client-utility layer
│   └── scalar-ffi/               # FFI bindings
├── docs/
│   ├── spec/                     # Canonical specification
│   │   ├── SCALAR-PROTOCOL.md
│   │   ├── SCALAR-TECHNICAL.md
│   │   └── SCALAR-SECURITY.md
│   ├── reports/                  # Benchmark & status reports
│   ├── architecture/
│   ├── testing/
│   └── verification/
├── verification/                 # TLA+ formal specs
│   └── d025-optimistic-finality/
├── scripts/                      # Operational scripts
│   ├── testnet.sh
│   └── run_benchmarks.sh
├── tools/
│   ├── genesis-tool/
│   └── circuit-bench/
├── apps/mobile/
├── fuzz/
└── tests/
```

---

## Running a Node

**Requirements:** Rust 1.82+, 8 GB RAM (Tier A/B), 50 GB SSD, 10 Mbps uplink

```bash
# Clone
git clone https://github.com/berdywandara/scalar-core
cd scalar-core

# Build (production — compile-time check enforces --features production)
cargo build --release --features production

# Run a node
cargo run --release --bin scalar-node --features production

# Query the node
curl http://localhost:7777              # node status
curl http://localhost:7777/smt_root    # current NullifierSet root
curl http://localhost:7777/node_state  # state: BOOTSTRAPPING→SYNCING→ACTIVE
```

**Note:** `cargo check` (without `--features production`) passes with warnings only for development. Mainnet binary requires `--features production` — compile-time enforcement.

---

## Development Status

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Core cryptography, zk-STARK foundation | ✅ Complete |
| Phase 2 | Network layer, multi-transport, gossip | ✅ Complete |
| Phase 3 | NullifierSet 2-layer + WAL checkpoint | ✅ Complete |
| Phase 4 | Wallet architecture, key management | ✅ Complete |
| Phase 5 | Protocol documentation consolidated (SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY) | ✅ Complete |
| Phase 6 | Test vectors, formal verification, testnet | 🔄 In Progress |
| Phase 7 | Mainnet launch | ⏳ Pending |

**Pre-mainnet requirements (mandatory):**
- [x] Plonky3 migration complete (P3-R1..R9) — scalar-stark-p3
- [x] D-025 Optimistic Finality — TLA+ formal verification: GO (all 7 properties PASS)
- [x] D-028 FRI grinding 20→23 — soundness ε≤2^-120.68 confirmed
- [x] Formal invariants INV-SUPPLY/NULLIFIER/EPOCH/REWARD/GOVERNANCE
- [ ] Formal soundness proof STARKPack Scenario B (ADR-SEC-023)
- [ ] Second independent STARK verifier (spec §15.3) — required before mainnet
- [ ] Two independent security audits of circuits and protocol
- [ ] All test vectors in `docs/testing/TEST_VECTORS.md` verified by both implementations

---

## Design Principles

**No blockchain.** No blocks, no chain, no longest-chain rule. State is a NullifierSet (SMT) and a set of Proof Objects.

**No majority vote.** A STARK proof is valid because mathematics says so — not because 51% of nodes agreed.

**No trusted setup.** zk-STARKs require no ceremony. Security assumption: hash function collision resistance only.

**No elliptic curves.** Not for signatures, not for key exchange, not anywhere.

**Privacy by default.** Transaction amounts, senders, and recipients are hidden. Only mathematical validity is public.

**Determinism over coordination.** Every critical computation (DMM, UTXO ordering, NMT peers, aggregator selection) is fully deterministic from shared public data — no coordination protocol needed, no ambiguity possible.

---

## License

Dual-licensed under **MIT** OR **Apache-2.0** at your option.

- [LICENSE-MIT](./LICENSE-MIT)
- [LICENSE-APACHE](./LICENSE-APACHE)

---

## Authors

See [AUTHORS.md](./AUTHORS.md).

Scalar Network protocol was conceived and designed by **Berdy Wandara** (Original Architect & Founder). Per the leaderless principle of the protocol, this attribution is purely historical — it confers no special allocation, privilege, or governance power within the running network.

---

## Further Reading

| Document | Location |
|---|---|
| Protocol Specification | [`docs/spec/SCALAR-PROTOCOL.md`](./docs/spec/SCALAR-PROTOCOL.md) |
| Technical Reference | [`docs/spec/SCALAR-TECHNICAL.md`](./docs/spec/SCALAR-TECHNICAL.md) |
| Security Analysis | [`docs/spec/SCALAR-SECURITY.md`](./docs/spec/SCALAR-SECURITY.md) |
| Benchmark Results | [`docs/reports/BENCHMARK_RESULTS.md`](./docs/reports/BENCHMARK_RESULTS.md) |
| Implementation Status | [`docs/reports/IMPLEMENTATION_STATUS.md`](./docs/reports/IMPLEMENTATION_STATUS.md) |
| Regulatory Framework | [`docs/REGULATORY_FRAMEWORK.md`](./docs/REGULATORY_FRAMEWORK.md) |
| Test Vectors | [`docs/testing/TEST_VECTORS.md`](./docs/testing/TEST_VECTORS.md) |
| Architecture Diagrams | [`docs/architecture/ARCHITECTURE_DIAGRAMS.md`](./docs/architecture/ARCHITECTURE_DIAGRAMS.md) |
| Security Policy | [`SECURITY.md`](./SECURITY.md) |
| Contributing Guide | [`CONTRIBUTING.md`](./CONTRIBUTING.md) |
