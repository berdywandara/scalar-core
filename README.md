# Scalar Network
 
> **"Truth by Mathematics, Not by Majority."**
> **"Epoch by Sequence, Not by Clock."**
> — Berdy Wandara, Original Architect & Founder
 
Scalar Network is a post-quantum digital cash designed for long-term resilience. No blockchain. No trusted setup. No founder allocation. Privacy is a mathematical property, not a feature.
 
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
| **Epoch by sequence** | Epoch boundaries determined by `seq_num`, not wall-clock. Clock-drift forks eliminated. |
 
---
 
## Architecture Overview
 
```
scalar-core/
├── crates/
│   ├── scalar-crypto/        # Poseidon2, SPHINCS+, ML-KEM, BLAKE3, CryptoVersion Registry
│   ├── scalar-nullifier/     # Hierarchical NullifierSet (HOT/WARM/COLD/ARCH), Layer Promotion
│   ├── scalar-stark/         # Transfer Circuit (C1-C10), Mint Circuit (MC1-MC5),
│   │                         # Independent Verifier (Goldilocks, dual STARK)
│   ├── scalar-emission/      # PoU formula, EpochAnchor, NodeHeartbeat MAC,
│   │                         # Tail Emission Backstop, Node Resumption Protocol
│   ├── scalar-fees/          # Fee model (FLOOR + PREMIUM), 95/5 distribution, W_FLOOR_FP
│   ├── scalar-governance/    # Conviction factor, GovernanceID, Anti-Sybil, fork governance
│   ├── scalar-network/       # GSS fanout, NMT (8 peers), StateBeacon, Dandelion++,
│   │                         # heartbeat_verifier, time_security (T-1..T-6), eclipse defense
│   ├── scalar-node/          # State machine, RPC (port 7777), Argon2id Sybil defense
│   ├── scalar-wallet-core/   # Key derivation chain (Argon2id v9.0), coin selection
│   ├── scalar-compliance/    # Ossified parameter verification suite (v5/v6/v7/v9)
│   ├── scalar-sdk/           # Client-Utility Layer — F1–F12 API (boundary: no protocol deps)
│   ├── scalar-governance/    # Conviction, GovernanceID, AI-resistance, anti-sybil
│   └── scalar-ffi/           # UniFFI-style bindings for Flutter/mobile
├── tools/
│   └── genesis-tool/         # Genesis object generation and verification (CLI)
└── apps/
    └── mobile/               # Flutter wallet UI (⏳ PENDING — awaiting UI/UX design)
```
 
---
 
## Cryptographic Stack
 
All Layer 0 primitives are **ossified** — they cannot change without a network fork.
 
| Component | Primitive | Notes |
|---|---|---|
| Signatures | SPHINCS+-SHAKE256s | NIST FIPS 205. Hash-based. 128-bit quantum security. |
| ZK Proofs | zk-STARKs (Winterfell + Independent) | No trusted setup. ε ≈ 2⁻⁶¹⁴⁴ soundness. Dual verifier. |
| In-circuit hash | Poseidon2 | t=4, d=7, RF=8, RP=22. Goldilocks field. **In-circuit ONLY.** |
| Out-circuit hash | BLAKE3 | NullifierSet IDs, state hash, MAC. **Out-circuit ONLY.** |
| Key exchange | ML-KEM-768 | NIST FIPS 203. Post-quantum transport. |
| Symmetric | ChaCha20-Poly1305 | All P2P channels. |
| Identity cost | Argon2id | 4 GB RAM, 1 hour CPU. Anti-Sybil. |
| Seed KDF | Argon2id | 64 MB RAM, t=3, p=1, output 64 bytes. (v9.0 — SCL-SPEC-SEED-001) |
| HB integrity | BLAKE3-MAC | NodeHeartbeat MAC — NOT SPHINCS+ (EpochAnchor only). |
 
---
 
## Transfer Circuit: 10 Constraint Groups
 
Every transfer produces a STARK proof covering C1–C10, verified independently by every node:
 
| Constraint | ~Constraints | Purpose |
|---|---|---|
| C1 — Commitment Validity | ~200/input | Every input coin is a valid Poseidon2 commitment. |
| C2 — Nullifier Validity | ~200/input | Two-layer nullifier: in-circuit (Poseidon2) + out-circuit (BLAKE3). Implicit binding via STARK proof. |
| C3 — Genesis Membership | ~6,464/input | Every input coin originates from genesis via Merkle path. |
| C4 — Non-Membership | ~12,800/input | Anti-double-spend: nullifier absent from NullifierSet. |
| C5 — Value Conservation | ~10 | Σ inputs = Σ outputs + fee. **Ossified.** |
| C6 — Non-Negativity | ~163/value | All values > 0. Fee ≥ FLOOR_MIN_ABSOLUTE = 40 sSCL. |
| C7 — Output Formation | ~200/output | Every output commitment uses a fresh random salt. |
| C8 — Authorization | ~200 | In-circuit: Poseidon2 auth_commit. Out-of-circuit: SPHINCS+ verify. Both required. |
| C9 — Version Compatibility | ~10 | Proof uses a currently valid CryptoVersion. |
| C10 — Censorship Resistance | ~50 | Aggregator cannot exclude eligible transactions (T_MAX_WAIT = 30 min). |
 
**Performance:** ~40,650 constraints (2-in/2-out) · ~202,000 (10-in/10-out) · Proving time: 300ms ± 10ms · Soundness: ε ≈ 2⁻⁶¹⁴⁴
 
---
 
## Hierarchical NullifierSet
 
The only "ledger" in Scalar Network. Four layers optimized for storage and lookup speed.
 
```
NS_HOT   (SMT depth-32,  0–30 days  / 1 epoch)   ~29 MB   · ~0.50ms lookup
NS_WARM  (Bloom p=10⁻¹⁰ k=33,  30–365 days)      ~20 MB   · ~0.02ms lookup
NS_COLD  (Bloom p=10⁻¹⁵ k=50,  >365 days)       ~866 MB   · ~0.03ms lookup
NS_ARCH  (Recursive STARK checkpoint)              <1 MB   · <100ms verify
──────────────────────────────────────────────────────────────────────────────
TOTAL                                             ~916 MB   · ~0.55ms worst case
                                                  vs 3.2 GB monolithic SMT (71.4% savings)
```
 
**Layer Promotion** (every epoch boundary):
1. Nullifiers from NS_HOT older than 1 epoch → promoted to NS_WARM
2. Nullifiers older than 12 epochs → also inserted into NS_COLD
3. NS_HOT compacted — contains only current epoch's nullifiers
4. Zero-Gap Property: no verification gap during promotion
 
NS_ARCH generates a recursive STARK proof every 90 days (3 epochs), proving the entire nullifier history from genesis in a single ~150 KB proof. New nodes download this proof instead of replaying all history.
 
---
 
## Proof-of-Uptime Emission
 
No mining. No staking. Nodes earn rewards proportional to verified uptime.
 
```
E(k)        = E₀ × (1 − M_E(k−1) / S_E)²         # Standard emission per epoch k
E_active(k) = max(E(k), E_TAIL)                    # Tail emission backstop (ossified)
 
w_i(k) = (700,000 × uptime_ratio_fp(i,k)
         + 300,000 × root_alignment_fp(i,k))
         / 1,000,000
 
R_total(i,k) = R_pou(i,k) + R_fee(i,k) + longevity_boost
R_pou(i,k)   = E_active(k) × w_i(k) / W(k)
R_fee(i,k)   = Fee_pool(k) × 0.95 × w_i(k) / W_effective(k)
```
 
**Supply:** 21,000,000 SCL hard cap · 18,900,000 SCL via PoU (S_E) · 2,100,000 SCL tail emission backstop (S_R)  
**Epoch:** 30 days · 4,320 expected heartbeats (seq_num based — Rule T-1) · E₀ = 126,000 SCL/epoch  
**Tail emission:** E_TAIL = 1,000 SCL/epoch — sustained operation ~286 years from genesis  
**Longevity boost:** +1% per year of operation, capped at +50% at year 50
 
---
 
## NodeHeartbeat v9.0
 
Compact 108-byte structure — BLAKE3-MAC only (no SPHINCS+ per heartbeat):
 
```
NodeHeartbeat {
  node_id:   [u8; 4]   // Compressed: first 4 bytes of BLAKE3(full_node_id)
  seq_num:   u32        // Monotonic per node. Epoch boundary = seq_num (Rule T-1)
  timestamp: u32        // Delta seconds from epoch_start (NOT absolute wall-clock)
  smt_root:  [u8; 32]  // Current SMT root
  prev_hash: [u8; 32]  // BLAKE3(previous heartbeat bytes)
  mac:       [u8; 32]  // BLAKE3(NodeKey_epoch ‖ node_id ‖ seq_num ‖ timestamp ‖ smt_root ‖ prev_hash)
}  // TOTAL: 4+4+4+32+32+32 = 108 bytes (vs 29,900 bytes v8.0 — 213× reduction)
```
 
**EpochAnchor:** One SPHINCS+ signature per node per epoch, covering the entire heartbeat chain via `chain_head = BLAKE3(last_HB)`. Sent at END of epoch before reward claim window opens.
 
**5-Step Heartbeat Verification:**
1. TTL check: `abs(NMT − HB.timestamp) ≤ T_HEARTBEAT_TTL_S` (use NMT, not wall-clock)
2. seq_num: strictly monotonic, anti-replay
3. prev_hash: chain integrity via BLAKE3
4. MAC: recompute and compare
5. Accept: update counters
 
---
 
## Time Security Rules (T-1 to T-6) — Ossified
 
| Rule | Summary |
|---|---|
| T-1 — Epoch Boundary | Epoch determined by `seq_num` ranges, NOT wall-clock. Clock-drift fork eliminated. |
| T-2 — HB Freshness | `abs(NMT − HB.timestamp) ≤ T_HEARTBEAT_TTL_S`. Rejects pre-computed fake uptime. |
| T-3 — Network Median Time | NMT = median of 8 peers. Robust against outliers. No NTP (trustless). |
| T-4 — Rate Limiting | Max 1 HB per `T_HB_MIN_INTERVAL_S` per node. Rejects heartbeat bunching. |
| T-5 — seq_num Monotonic | Strictly increasing per node. Gaps non-fillable. Anti-replay. |
| T-6 — Timestamp Role | Timestamp used for TTL, monitoring, beacon ONLY. NOT for epoch boundary or rewards. |
 
---
 
## Network Protocol
 
**Gossip:** GSS (Global Synchrony Score) fanout 3–15 (ossified max = 15). Adaptive based on network synchrony.
 
**Reconciliation:** Aggregator selected via `argmin BLAKE3(node_id ‖ seed_k)` where `seed_k` is unpredictable until epoch k−1 completes. 10 independent validators, quorum 7/10. Canonical serialization S1-S4 eliminates manifest grinding.
 
**Privacy routing:** Dandelion++ (STEM → FLUFF phases) + 3-hop geographic-diverse onion routing + message padding to 1/16/64/256 KB + random broadcast delay 0–10s.
 
**Eclipse defense (5 layers):**
- GSS entropy monitor: WARNING if GSS_fp < 400,000 from dominant peer
- Geographic diversity: ≥2 regions required
- NMT manipulation detection: alert if 5+ of 8 peers are attacker-controlled
- Anti-partition halt (CP property): node halts new tx processing if <67% peers connected
 
**Bootstrap:** Hardcoded peers (multi-jurisdiction) · Genesis object ≤1 KB · BLAKE3 hash hardcoded in binary · NS_ARCH checkpoint every 90 days
 
**Transport stack (5 tiers):** Internet (primary) → LoRa Mesh (StateBeacon only) → HF Radio → Local Mesh → Visual QR. Tiers 3–5 carry StateBeacon (44 bytes) — state synchronization only, NOT consensus.
 
---
 
## Governance
 
Three-layer governance with anti-AI-attack safeguards:
 
| Layer | Mechanism |
|---|---|
| Layer 1 — Ossified | Cannot change without fork. ≥75% nodes + 90-day timelock + 30-day review. |
| Layer 2 — Constrained | Parameters within defined ranges. Same quorum + timelock. |
| Layer 3 — Reserve | Tail emission backstop (S_R). Year 126+ automatic, not discretionary. |
 
**Governance power:** `conviction_factor(days) × maturity_weight` — no SCL balance (private witness, unverifiable without breaking privacy).
 
**Conviction factor:** Precomputed discrete table. t=7d: 52.2%, t=30d: 95.8%, t=365d: 100%. Flash loan immunity: CF(30d)/CF(1min) ≈ 13,118×.
 
**GovernanceID:** `BLAKE3(ViewKey ∥ "governance_scalar_v1")` — does not reset on SpendKey rotation, cannot be linked to balance or transactions.
 
**Anti-Sybil:** `GOVERNANCE_MIN_STAKE_SSCL = 100,000`. One SpendKey = one GovernanceID. Argon2id NodeID cost prevents Sybil nodes.
 
---
 
## Wallet Key Derivation (v9.0 — SCL-SPEC-SEED-001)
 
```
seed         = Argon2id(mnemonic, salt=b"scalar_v2"‖genesis_hash,
                        m=65536 KiB, t=3, p=1, len=64 bytes)
               (first word MUST be "scalar" — BIP-39 wallets reject this)
MasterKey    = BLAKE3(seed ‖ "scalar_master")
AccountKey_i = BLAKE3(MasterKey ‖ "account" ‖ i_le64)
 
SpendKey     = BLAKE3(AccountKey ‖ "spend")
ViewKey      = BLAKE3(AccountKey ‖ "view")
NodeKey      = BLAKE3(AccountKey ‖ "node")        ← separate from SpendKey
DuressKey    = BLAKE3(AccountKey ‖ "duress" ‖ index_le64)
GovernanceID = BLAKE3(ViewKey   ‖ "governance_scalar_v1")
```
 
NodeKey is separate from SpendKey by design: a compromised node does not mean compromised coins.
NodeKey_epoch_i = `BLAKE3(NodeKey_i ‖ epoch_id_le64)` — per-epoch key, compartmentalized.
 
> ⚠️ **Breaking change from v7.0:** Seed output differs from same mnemonic. Must be implemented before mainnet.
 
---
 
## scalar-sdk: Client-Utility Layer (F1–F12)
 
`scalar-sdk` is the **only** entry point for client applications. It MUST NOT import `scalar-emission`, `scalar-stark`, `scalar-nullifier`, or `scalar-network`.
 
| F# | Feature | Function | Cost |
|---|---|---|---|
| F1 | Scarcity Proof | `query_scarcity_proof()` | 0 |
| F2 | MPAS | `query_monetary_policy_score()` | 0 |
| F3 | NHI | `query_network_health()` | 0 |
| F4 | NRS | `query_node_reputation()` | 0 |
| F5 | STP | `build_threshold_proof()` | 0 |
| F6 | NCP | `build_negative_compliance_proof()` | 0 |
| F7 | PoP | `build_payment_proof()` | 0 |
| F8 | QR Stamp | `build_timestamp_record()` | 40 sSCL |
| F9 | SIR | `build_indelible_record()` | 40 sSCL |
| F10 | Credential | `build_credential_proof()` | 0 |
| F11 | SLA | `query_uptime_sla()` | 0 |
| F12 | DMS | `build_dead_man_switch()` | 0 |
 
```bash
# QA: verify SDK isolation
grep -r 'use scalar_emission\|use scalar_stark\|use scalar_nullifier\|use scalar_network' \
  crates/scalar-sdk/
# Expected output: empty (no results)
```
 
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
 
---
 
## Development Status
 
Based on **Scalar_PR_Mapping_L1_v10.0** — Layer 1 + SDK complete.
 
| Crate | Status | Tests |
|---|---|---|
| scalar-crypto | ✅ Complete | 3 |
| scalar-nullifier | ✅ Complete | 39 |
| scalar-stark | ✅ Complete | 46 (23 + 23 independent) |
| scalar-emission | ✅ Complete | 93 |
| scalar-fees | ✅ Complete | 52 |
| scalar-governance | ✅ Complete | 19 |
| scalar-network | ✅ Complete | 150 |
| scalar-node | ✅ Complete | 7 |
| scalar-compliance | ✅ Complete | 65 |
| scalar-wallet-core | ✅ Complete | 50 (v9.0 Argon2id) |
| scalar-ffi | ✅ Complete | 20 |
| scalar-sdk | ✅ Complete | 23 (F1–F12, 45 feature tests) |
| genesis-tool | ✅ Complete | 9 |
| Empirical Tests §22.5 | ✅ All 7/7 PASS | ~20 |
| **Total** | **Layer 1 + SDK: COMPLETE** | **~750+ tests** |
 
**Remaining:** PR-CS-17/18 Flutter Onboarding + Send/Receive (⏳ PENDING — awaiting UI/UX design) · PR-CS-19 Governance Circuit Qvoting (🔴 TODO — post-testnet)
 
---
 
## Building
 
```bash
# Standard build
cargo build --workspace
 
# Run all tests
cargo test --workspace
 
# Production Argon2id (4 GB RAM — do NOT run in Codespace)
cargo check -p scalar-node --features production
 
# Lint
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
 
> **Alpine Linux note:** `pqcrypto-sphincsplus` requires a GCC compatibility flag on musl systems.
> ```bash
> cat > /tmp/cc-wrapper.sh << 'WRAP'
> #!/bin/sh
> exec gcc "-D__GNUC_PREREQ(x,y)=0" "$@"
> WRAP
> chmod +x /tmp/cc-wrapper.sh && export CC=/tmp/cc-wrapper.sh
> ```
 
---
 
## Formal Verification
 
All C1–C10 and MC1–MC5 constraints must be formally specified in TLA+ or Coq before mainnet. Six mathematical invariants must be formally proved:
 
1. Supply conservation: `PoU_minted + Reserve_released ≤ 21,000,000 SCL`
2. Value conservation per transaction: `Σ inputs = Σ outputs + fee`
3. Nullifier uniqueness: every nullifier inserted exactly once
4. Privacy preservation: private witness not extractable from public inputs
5. Finality monotonicity: committed nullifiers cannot be removed without fork
6. Emission bound: `E(k) ≤ E₀ × (1 − M_E(k−1)/S_E)²`
 
---
 
## Security Model
 
Scalar requires only three trust assumptions:
 
1. SHA3/BLAKE3 collision resistance
2. Poseidon2 collision resistance
3. Goldilocks field arithmetic correctness
 
**No elliptic curve assumptions. No integer factorization. No trusted setup. No trusted party.**
 
Scalar is designed for long-term resilience through: (1) post-quantum hash-based cryptography (SPHINCS+, zk-STARK), (2) genuine decentralization via Argon2id anti-Sybil NodeID, (3) Succession Protocol for institutional nodes, (4) multi-layer governance with conviction cliff and AI-resistant safeguards, (5) tail emission backstop sustaining node operation ~286 years, and (6) economic self-balancing via uptime-weighted rewards.
 
---
 
## Reference
 
- **Specification:** `Scalar_Master_Technical_Spec_v9.0` — single source of truth. If code conflicts with spec, spec wins.
- **PR Mapping:** `Scalar_PR_Mapping_L1_v10.0` — full development status and sprint planning.
- **License:** See `AUTHORS.md`
 
---
 
*Scalar is digital cash verified by mathematics — not by miners, validators, or majorities.*