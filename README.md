# Scalar Network

> **"Truth by Mathematics, Not by Majority"**
> — Berdy Wandara, Original Architect & Founder

Scalar Network is post-quantum digital cash designed to last 100 years. No blockchain. No trusted setup. No founder allocation. Privacy is a mathematical property, not a feature.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE-APACHE)

[README](README.md) · [AUTHORS](AUTHORS.md) · [CONTRIBUTING](CONTRIBUTING.md) · [SECURITY](SECURITY.md) · [LICENSE](LICENSE)

---

## What Makes Scalar Different

| Property | How It Works |
|---|---|
| **No blockchain** | State = Proof Objects + NullifierSet. No blocks, no chain, no leader election. |
| **Privacy by default** | Transfer value, sender identity, and receiver identity are always private via zk-STARK proofs. |
| **Mathematical truth** | A transaction is valid because its STARK proof verifies — not because a majority agrees. |
| **Leaderless** | No founder allocation, no incorporated entity, no named operational leader. Code is law. |
| **Post-quantum** | SPHINCS+ (hash-based signatures), zk-STARKs, ML-KEM-768. No elliptic curve assumptions. |

---

## Architecture Overview

```
scalar-core/
├── crates/
│   ├── scalar-crypto/        # Poseidon2, SPHINCS+, ML-KEM, BLAKE3, CryptoVersion Registry
│   ├── scalar-nullifier/     # Hierarchical NullifierSet (HOT/WARM/COLD/ARCH)
│   ├── scalar-stark/         # Transfer Circuit (C1-C10), Mint Circuit (MC1-MC5)
│   ├── scalar-emission/      # Proof-of-Uptime formula, epoch consensus, manifest
│   ├── scalar-fees/          # Fee model (FLOOR + PREMIUM), batch protocol
│   ├── scalar-governance/    # Conviction factor, GovernanceID, AI-resistance
│   ├── scalar-network/       # Kuramoto gossip, pheromone reconciliation,
│   │                         # eclipse defense, Dandelion++, progressive sync
│   ├── scalar-node/          # State machine, RPC (port 7777), Argon2id Sybil defense
│   ├── scalar-nullifier/     # SMT depth-32, Bloom filters, NS_ARCH recursive STARK
│   ├── scalar-wallet-core/   # Key derivation chain, coin selection
│   ├── scalar-compliance/    # Ossified parameter verification suite
│   └── scalar-ffi/           # UniFFI-style bindings for Flutter/mobile
├── tools/
│   └── genesis-tool/         # Genesis object generation and verification
└── apps/
    └── mobile/               # Flutter wallet UI
```

---

## Cryptographic Stack

All Layer 0 primitives are **ossified** — they cannot change without a network fork.

| Component | Primitive | Notes |
|---|---|---|
| Signatures | SPHINCS+-SHAKE256s | NIST FIPS 205. Hash-based. 128-bit quantum security. |
| ZK Proofs | zk-STARKs (Winterfell) | No trusted setup. ε ≈ 2⁻⁶¹⁴⁴ soundness. |
| In-circuit hash | Poseidon2 | t=4, d=7, RF=8, RP=22. Goldilocks field. |
| Out-circuit hash | BLAKE3 | NullifierSet IDs, state hash. |
| Key exchange | ML-KEM-768 | NIST FIPS 203. Post-quantum transport. |
| Symmetric | ChaCha20-Poly1305 | All P2P channels. |
| Identity cost | Argon2id | 4 GB RAM, 1 hour CPU. Anti-Sybil. |

---

## Transfer Circuit: 10 Constraint Groups

Every transfer produces a STARK proof covering C1–C10:

| Constraint | Purpose |
|---|---|
| C1 — Commitment Validity | Every input coin is a valid Poseidon2 commitment. |
| C2 — Nullifier Validity | Two-layer nullifier: in-circuit (Poseidon2) + out-circuit (BLAKE3). |
| C3 — Genesis Membership | Every input coin originates from genesis via Merkle path. |
| C4 — Non-Membership | Anti-double-spend: nullifier is absent from NullifierSet. |
| C5 — Value Conservation | Σ inputs = Σ outputs + fee. **Ossified.** |
| C6 — Non-Negativity | All values > 0. Fee ≥ FLOOR. |
| C7 — Output Formation | Every output commitment uses a fresh random salt. |
| C8 — Authorization | SPHINCS+ signature verification. |
| C9 — Version Compatibility | Proof uses a currently valid CryptoVersion. |
| C10 — Censorship Resistance | Aggregator cannot exclude eligible transactions (T_MAX_WAIT = 30 min). |

**Performance:** ~40,650 constraints (2-in/2-out) · Proving time: 300ms ± 10ms · Soundness: ε ≈ 2⁻⁶¹⁴⁴

---

## Hierarchical NullifierSet

The only "ledger" in Scalar Network. Four layers optimized for storage and lookup speed.

```
NS_HOT   (SMT depth-32,  0–30 days)      ~29 MB   · ~0.50ms lookup
NS_WARM  (Bloom p=10⁻¹⁰, 30–365 days)   ~20 MB   · ~0.02ms lookup
NS_COLD  (Bloom p=10⁻¹⁵, >365 days)    ~866 MB   · ~0.03ms lookup
NS_ARCH  (Recursive STARK checkpoint)     <1 MB   · <100ms verify
─────────────────────────────────────────────────────────────────
TOTAL                                    ~916 MB   · ~0.55ms worst case
                                         vs 3.2 GB monolithic SMT (71.4% savings)
```

NS_ARCH generates a recursive STARK proof every 90 days, proving the entire nullifier history from genesis in a single ~150 KB proof. New nodes download this proof instead of replaying all history. Long-range reconstruction attacks are blocked (soundness ε ≈ 2⁻⁶¹⁴⁴).

---

## Proof-of-Uptime Emission

No mining. No staking. Nodes earn rewards proportional to verified uptime.

```
E(k) = E₀ × (1 - M_E(k) / S_E)²          # Emission per epoch k

w_i(k) = 0.60 × uptime_ratio
        + 0.30 × root_alignment_score
        + 0.10 × phase_coherence_score

R_i(k) = E(k) × (w_i(k) × B_i(k)) / W_equity(k)
        + longevity_boost_i(k)
        + fee_relay_i
```

**Supply:** 21,000,000 SCL hard cap · 18,900,000 SCL via PoU · 2,100,000 SCL reserve (year 3+)  
**Epoch:** 30 days · 4,320 expected heartbeats · E₀ = 126,000 SCL/epoch

Longevity multiplier rewards nodes that run for decades: +1% per year, capped at +50% at year 50. This creates an economic incentive to keep nodes running for generations.

---

## Network Protocol

**Gossip:** Kuramoto-enhanced phase synchronization. Adaptive fanout 3–15 (ossified max = 15) based on network order parameter r.

**Reconciliation:** Pheromone-based root selection. No "earlier timestamp wins" — removed because timestamps can be forged. Consensus is determined by weighted network agreement (67% threshold).

**Privacy routing:** Dandelion++ (STEM → FLUFF phases) + 3-hop geographic-diverse onion routing + message padding to 1/16/64/256 KB + random broadcast delay 0–10s.

**Eclipse defense (5 layers):**
- Layer 2: Pheromone entropy monitor (WARNING >60%, CRITICAL >80% from single peer)
- Layer 3: Geographic diversity (≥2 regions required)
- Layer 5: Anti-partition halt — CP property, node halts new tx processing if <67% peers connected

**Bootstrap:** 50 hardcoded peers (multi-jurisdiction) · Genesis object <1 KB · BLAKE3 hash hardcoded in binary · Checkpoint snapshots every 90 days

**Transport stack (5 tiers):** Internet (primary) → LoRa Mesh → HF Radio → Local Mesh → Visual QR. Network survives full internet censorship.

---

## Governance

Three-layer governance with strong anti-AI-attack safeguards:

| Layer | Mechanism |
|---|---|
| Layer 1 — Ossified | Cannot change without fork. Fundamental protocol parameters. |
| Layer 2 — Constrained | 75% nodes + 60% operators + 90-day timelock + 30-day review. Parameters within defined ranges only. |
| Layer 3 — Reserve | Protocol Reserve spending. Year 3+. |

**Governance power:** `conviction_factor(days) × maturity_weight` — no SCL balance (private witness, unverifiable without breaking privacy).

**Conviction factor:** Precomputed discrete table. t=7d: 52.2%, t=30d: 95.8%, t=365d: 100%. Flash loan immunity: CF(30d)/CF(1min) ≈ 13,118×.

**GovernanceID:** `BLAKE3(ViewKey ∥ "governance_scalar_v1")` — does not reset on SpendKey rotation, cannot be linked to balance or transactions.

---

## Wallet Key Derivation

```
seed          = PBKDF2-HMAC-SHA3(mnemonic, "scalar_v1", 2048)
                (first word MUST be "scalar" — BIP-39 wallets reject this)
MasterKey     = BLAKE3(seed ∥ "scalar_master")
AccountKey_i  = BLAKE3(MasterKey ∥ "account" ∥ i_le64)

SpendKey      = BLAKE3(AccountKey ∥ "spend")
ViewKey       = BLAKE3(AccountKey ∥ "view")
NodeKey       = BLAKE3(AccountKey ∥ "node")       ← separate from SpendKey
DuressKey     = BLAKE3(AccountKey ∥ "duress" ∥ index_le64)
GovernanceID  = BLAKE3(ViewKey   ∥ "governance_scalar_v1")
```

NodeKey is separate from SpendKey by design: a compromised node does not mean compromised coins.

---

## Hardware Requirements

Scalar runs on ordinary hardware. No data center required.

```
Minimum (full node, PoU eligible):
  RAM:       8 GB
  Storage:   50 GB SSD
  Bandwidth: 10 Mbps sustained

Mobile (partial validation):
  RAM:       8 GB (smartphone)
  Storage:   NS_HOT only (~29 MB)
```

100,000 home laptops provide stronger Byzantine fault tolerance than 1,000 dedicated VPS servers. Genuine decentralization cannot be built on centralized infrastructure.

---

## Development Status

| Crate | Status | Tests |
|---|---|---|
| scalar-crypto | ✅ Complete | 11 |
| scalar-nullifier | ✅ Complete | 19 |
| scalar-stark | ✅ Complete | 23 |
| scalar-emission | ✅ Complete | 21 |
| scalar-fees | ✅ Complete | 29 |
| scalar-governance | ✅ Complete | 9 |
| scalar-network | ✅ Complete | 75 |
| scalar-node | ✅ Complete | 7 |
| scalar-compliance | ✅ Complete | 11 |
| scalar-wallet-core | ✅ Complete | 3 |
| scalar-ffi | ✅ Complete | 20 |
| **Total** | **22/27 PRs** | **~228 tests** |

Remaining: Fork protocol, Institutional nodes, Succession protocol, Mycelium adaptive routing, Genesis CLI tool, Flutter integration.

---

## Building

```bash
# Standard build
cargo build --workspace

# Run all tests
cargo test --workspace

# Production Argon2id (4 GB RAM — do not run in Codespace)
cargo check -p scalar-node --features production

# Lint
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

> **Alpine Linux note:** `pqcrypto-sphincsplus` requires a GCC compatibility flag on musl systems.
> ```bash
> cat > /tmp/cc-wrapper.sh << 'EOF'
> #!/bin/sh
> exec gcc "-D__GNUC_PREREQ(x,y)=0" "$@"
> EOF
> chmod +x /tmp/cc-wrapper.sh && export CC=/tmp/cc-wrapper.sh
> ```

---

## Formal Verification

All C1–C10 and MC1–MC5 constraints are required to be formally specified in TLA+ or Coq before mainnet. Six mathematical invariants must be formally proved:

1. Supply conservation: `PoU_minted + Reserve_released ≤ 21,000,000 SCL`
2. Value conservation per transaction: `Σ inputs = Σ outputs + fee`
3. Nullifier uniqueness: every nullifier inserted exactly once
4. Privacy preservation: private witness not extractable from public inputs
5. Finality monotonicity: committed nullifiers cannot be removed without fork
6. Emission bound: `E(k) ≤ E₀ × (1 - M_E(k-1)/S_E)²`

---

## Security Model

Scalar requires only three trust assumptions:

1. SHA3/BLAKE3 collision resistance
2. Poseidon2 collision resistance
3. Goldilocks field arithmetic correctness

**No elliptic curve assumptions. No integer factorization. No trusted setup. No trusted party.**

Survival probability analysis (100-year horizon): **~42.6%** — 141× better than comparable systems without institutional node support.

---

## Reference

- **Specification:** `Scalar_Master_Technical_Spec_v5.0` — the single source of truth. If code conflicts with spec, spec wins.
- **PR Mapping:** `Scalar_PR_Mapping_L1_v5.3` — full development status and sprint planning.
- **License:** See `AUTHORS.md`

---

*Scalar is digital cash that can only be verified by mathematics — not by miners, validators, or majorities — and cannot be seized, inflated, traced, or destroyed even by a quantum computer.*