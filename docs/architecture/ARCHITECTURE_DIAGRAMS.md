# Appendix D — Architecture Diagrams and Protocol Flow

**Status:** Final  
**Reference:** [SCALAR-PROTOCOL](../spec/SCALAR-PROTOCOL.md) / [SCALAR-TECHNICAL](../spec/SCALAR-TECHNICAL.md) / [SCALAR-SECURITY](../spec/SCALAR-SECURITY.md)

> This appendix provides visual reference for the Scalar Network architecture, data flows,
> and protocol sequences. All diagrams are derived from the canonical specification.
> In case of any conflict, the written specification takes precedence.

---

## D.1 System Overview

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          SCALAR NETWORK — FULL NODE                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ┌────────────────────────────────────────────────────────────────────────┐  ║
║  │  APPLICATION LAYER                                                     │  ║
║  │  scalar-node  ──  RPC :7777  ──  scalar-sdk (public API only)         │  ║
║  └───────────────────────────────┬────────────────────────────────────────┘  ║
║                                  │                                           ║
║  ┌───────────────────────────────▼────────────────────────────────────────┐  ║
║  │  CONSENSUS / EPOCH LAYER                                               │  ║
║  │  scalar-consensus                                                      │  ║
║  │  ├── Epoch Reward Manifest (aggregator selection → quorum → DMM)       │  ║
║  │  ├── UTXO Set Root  (canonical tx ordering via tx_ordering_key)        │  ║
║  │  └── Heartbeat Collection + Uptime Weight Computation                  │  ║
║  └───────────────────────────────┬────────────────────────────────────────┘  ║
║                                  │                                           ║
║  ┌────────────────┬──────────────▼──────────────┬───────────────────────┐   ║
║  │  scalar-stark-p3│  scalar-nullifier            │  scalar-emission      │   ║
║  │  Transfer Ckt  │  NS_ACTIVE (SMT depth-32)    │  PoU formula          │   ║
║  │  CA–CG         │  NS_CHECKPOINT (STARK proof) │  Deferred Pool        │   ║
║  │  Mint Ckt      │  WAL checkpoint              │  Security Fund        │   ║
║  │  MC1–MC5       │  Zero-Gap Property           │                       │   ║
║  └────────────────┴──────────────┬──────────────┴───────────────────────┘   ║
║                                  │                                           ║
║  ┌───────────────────────────────▼────────────────────────────────────────┐  ║
║  │  CRYPTOGRAPHY LAYER  (scalar-crypto)                                   │  ║
║  │  Poseidon2 (in-circuit) │ BLAKE3 (out-of-circuit) │ SLH-DSA │ Argon2id │  ║
║  └───────────────────────────────┬────────────────────────────────────────┘  ║
║                                  │                                           ║
║  ┌───────────────────────────────▼────────────────────────────────────────┐  ║
║  │  NETWORK LAYER  (scalar-network)                                       │  ║
║  │  Tier A: libp2p (Noise + Yamux) + Tor 3-hop + Dandelion++             │  ║
║  │  Tier B: LoRa/HF radio → State Beacon (44 bytes)                      │  ║
║  │  NMT peers: 23 deterministic + 1 random (ChaCha20)                    │  ║
║  └────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## D.2 Crate Dependency Graph

```
                       scalar-crypto
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     scalar-nullifier  scalar-emission  (shared primitives)
            │              │
            └──────┬───────┘
                   │
             scalar-stark-p3
                   │
             scalar-network
                   │
             scalar-consensus
                   │
             scalar-node
                   │
         ┌─────────┴─────────┐
    scalar-sdk          scalar-audit
    (public API)        (read-only)

scalar-wallet-core ─── scalar-crypto
scalar-governance  ─── scalar-crypto, scalar-stark-p3
scalar-ffi         ─── scalar-wallet-core (UniFFI bindings)
```

> **Boundary rule:** `scalar-sdk` and `scalar-audit` MUST NOT import protocol crates directly.
> Only the public API surface is accessible.

---

## D.3 Transaction Lifecycle

```
WALLET (local)                    NETWORK                    ALL NODES
     │                               │                           │
     │  1. BUILD TRANSACTION         │                           │
     │  ─────────────────────        │                           │
     │  C = Poseidon2(               │                           │
     │    DOMAIN_COMMITMENT_V2 ‖     │                           │
     │    value ‖ pubkey ‖           │                           │
     │    secret ‖ salt)             │                           │
     │                               │                           │
     │  N = Poseidon2(               │                           │
     │    DOMAIN_NULL ‖              │                           │
     │    secret ‖ spending_key)     │                           │
     │                               │                           │
     │  2. GENERATE STARK PROOF      │                           │
     │  ─────────────────────        │                           │
     │  Proves: CA+CB+CC+CD+CE+CF+CG │                           │
     │  (~52,088 constraints 2in/2out│                           │
     │   target ≤ 500 ms)            │                           │
     │                               │                           │
     │  3. SIGN (SLH-DSA)            │                           │
     │  sig = SLH_DSA_sign(          │                           │
     │    NodeKey, tx_message)       │                           │
     │                               │                           │
     │  4. BROADCAST ──────────────► │                           │
     │                           Dandelion++ stem (70%)         │
     │                           delay: 100–5000 ms/hop         │
     │                               │                           │
     │                           Fluff: gossipsub ──────────────►
     │                               │                           │
     │                               │  5. VERIFY (each node)    │
     │                               │  a. Verify SLH-DSA sig    │
     │                               │  b. Verify STARK proof    │
     │                               │  c. Check N ∉ NS_ACTIVE   │
     │                               │  d. Check N ∉ NS_CHECKPOINT│
     │                               │  e. Insert N → NS_ACTIVE  │
     │                               │  f. Add output C → UTXO   │
     │                               │     set SMT               │
     │                               │                           │
     │  ◄────────────────────────────┤  6. CONFIRMED             │
```

---

## D.4 Transfer Circuit Constraint Groups (CA–CG)

```
┌─────────────────────────────────────────────────────────────────────┐
│                 TRANSFER CIRCUIT  (zk-STARK, Goldilocks)            │
│                                                                     │
│  PUBLIC INPUT                    PRIVATE WITNESS                   │
│  ─────────────────                ─────────────────────            │
│  input_commitments[]              input_secrets[]                  │
│  input_nullifiers[]               input_values[]                   │
│  output_commitments[]             output_values[]                  │
│  fee_total                        output_owner_pubkeys[]           │
│  utxo_set_root                    output_salts[]                   │
│  current_active_root              spending_key                     │
│  archived_smt_root                utxo_membership_paths[]         │
│  timestamp / entry_timestamp      nullifier_active_paths[]         │
│  crypto_version                   nullifier_checkpoint_paths[]     │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ CA — Ownership Proof                                         │  │
│  │   N[i] = Poseidon2(DOMAIN_NULL ‖ secret[i] ‖ spending_key)  │  │
│  │   C[i] = Poseidon2(DOMAIN_COMMITMENT_V2 ‖ value[i] ‖ ...)   │  │
│  │   constraint: input_nullifiers[i] == N[i]                   │  │
│  │   constraint: input_commitments[i] == C[i]                  │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ CB — UTXO Set Membership                                     │  │
│  │   MerkleVerify(C[i], path, utxo_set_root) == TRUE           │  │
│  │   (snapshot from end of epoch k-1, after canonical ordering) │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ CC — Dual Non-Membership  (~25,600 constraints/input)        │  │
│  │   SMT_NonMemberVerify(N[i], current_active_root)  == TRUE   │  │
│  │   SMT_NonMemberVerify(N[i], archived_smt_root)    == TRUE   │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ CD — Value Conservation                                      │  │
│  │   Σ input_values == Σ output_values + fee_total  (u128)     │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ CE — Output Integrity                                        │  │
│  │   Each output: commitment valid, value > 0, value ∈ D1–D17  │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ CF — Authorization                                           │  │
│  │   In-circuit:  knowledge of owner_pubkey                    │  │
│  │   Out-circuit: SLH-DSA_verify(pk, tx_message, sig)          │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ CG — Protocol Compliance                                     │  │
│  │   crypto_version == CRYPTO_VERSION_CURRENT (0x01)           │  │
│  │   entry_timestamp ≤ current_timestamp − T_MAX_WAIT          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  CONSTRAINT COUNT:  2-in/2-out ≈ 52,088  │  10-in/10-out ≈ 260,000│
└─────────────────────────────────────────────────────────────────────┘
```

---

## D.5 Epoch Reward Manifest Consensus Flow

```
EPOCH k STARTS
      │
      ▼
┌─────────────────────────────────────────────┐
│  HEARTBEAT COLLECTION PHASE                 │
│  Heartbeat: target 120 s, min 300 s          │
│  Regular: 148 bytes  │  Anchor: +extension  │
│  MAC = BLAKE3(NodeKey_epoch ‖ fields...)    │
└──────────────────────┬──────────────────────┘
                       │  (at epoch boundary: seq_num = k×380)
                       ▼
┌─────────────────────────────────────────────┐
│  AGGREGATOR SELECTION  (deterministic)      │
│  seed_k = BLAKE3(b"scalar_seed" ‖          │
│            committed_manifest_hash(k-1))   │
│  score_i = BLAKE3(b"scalar_subepoch_score" ‖      │
│             node_id_full_i ‖ seed_k)       │
│  aggregator = argmin(score_i)              │
│  validator_pool = next 10 lowest scores    │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│  PROPOSAL & VALIDATION                      │
│  Aggregator builds EpochRewardManifest      │
│  7/10 validators must approve (quorum)      │
│  Tie-break: argmin(BLAKE3(manifest_bytes))  │
└──────────────────────┬──────────────────────┘
                       │
            ┌──────────┴──────────┐
            │ quorum reached?      │
           YES                    NO (T_MANIFEST_DEADLINE_S elapsed)
            │                     │
            ▼                     ▼
┌───────────────────┐  ┌─────────────────────────────────────────┐
│  COMMIT MANIFEST  │  │  DMM — DETERMINISTIC MINIMAL MANIFEST   │
│  (normal path)    │  │  Each synced node independently builds: │
└───────────────────┘  │  1. Verify committed_manifest(k-1) hash  │
                       │  2. For each node in base_node_list:    │
                       │     - find_valid_anchor(node_id, data)  │
                       │     - SLH_DSA_verify + chain_integrity  │
                       │     - compute_reward(uptime_weight_fp)  │
                       │  3. Build manifest (ascending node_id)  │
                       │  4. manifest_hash = BLAKE3(serialize())  │
                       │                                         │
                       │  → All honest nodes: bit-identical DMM  │
                       │  MAX_CONSECUTIVE_DEFER = 2              │
                       └─────────────────────────────────────────┘
                                        │
                                        ▼
                       ┌─────────────────────────────────────────┐
                       │  UTXO SET ROOT UPDATE                   │
                       │  For all valid txns in epoch k:         │
                       │    tx_ordering_key = BLAKE3(            │
                       │      DOMAIN_TX_ORDER ‖ tx_hash ‖        │
                       │      epoch_id_le64)                     │
                       │  Process txns in ascending key order    │
                       │  → utxo_set_root (deterministic)        │
                       └─────────────────────────────────────────┘
```

---

## D.6 NullifierSet 2-Layer Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    NULLIFIERSET (2-LAYER)                    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  NS_ACTIVE  (Layer 1)                               │    │
│  │  Type: Sparse Merkle Tree, depth = 32               │    │
│  │  Contains: nullifiers from last 3 epochs            │    │
│  │  Size: ~15 MB                                       │    │
│  │  Lookup: O(log n), deterministic                    │    │
│  │                                                     │    │
│  │  current_active_root ──► used as public input in CC │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│        (every 3 epochs: checkpoint operation with WAL)       │
│                          │                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  NS_CHECKPOINT  (Layer 2)                           │    │
│  │  Type: Recursive STARK proof                        │    │
│  │  Contains: ALL nullifiers before NS_ACTIVE          │    │
│  │  Size: ~150 KB                                      │    │
│  │  Verification: check archived_smt_root              │    │
│  │                                                     │    │
│  │  archived_smt_root ──► used as public input in CC   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  CHECKPOINT OPERATION (WAL-protected, atomic):              │
│  1. Write WAL entry                                         │
│  2. Collect nullifiers > 3 epochs old (max 200,000)        │
│  3. Generate recursive STARK proof (timeout 300 s)         │
│  4. Verify proof                                            │
│  5. Atomic DB transaction:                                  │
│     - Update NS_CHECKPOINT                                  │
│     - Delete from NS_ACTIVE                                 │
│     - Update active_since_epoch                             │
│  6. Mark WAL complete                                       │
│                                                              │
│  ZERO-GAP PROPERTY: no nullifier is absent from both        │
│  layers at any point, including during crash recovery        │
└──────────────────────────────────────────────────────────────┘

TOTAL STORAGE: ~15.15 MB per node
```

---

## D.7 Wallet Key Derivation Chain

```
MNEMONIC (12 words: "scalar" + 11 free words from BIP-39)
    │
    │  Argon2id(
    │    password = UTF-8(mnemonic),
    │    salt     = SEED_SALT_PREFIX ‖ genesis_hash,
    │    memory   = 64 MB, iter = 3, parallel = 1,
    │    out_len  = 64 bytes
    │  )
    │
    ▼
seed (64 bytes)
    │
    ├─► MasterKey = BLAKE3(seed ‖ "scalar_master")
    │       │
    │       └─► AccountKey_i = BLAKE3(MasterKey ‖ "account" ‖ i_le64)
    │                   │
    │                   ├─► SpendKey  = BLAKE3(AccountKey_i ‖ "spend")
    │                   │             [funds control — keep secret]
    │                   │
    │                   ├─► ViewKey   = BLAKE3(AccountKey_i ‖ "view")
    │                   │             [read incoming txns — shareable for audit]
    │                   │
    │                   ├─► NodeKey   = BLAKE3(AccountKey_i ‖ "node")
    │                   │             [heartbeat MAC + anchor signature]
    │                   │             [isolated — node compromise ≠ funds loss]
    │                   │
    │                   └─► DuressKey_j = BLAKE3(AccountKey_i ‖ "duress" ‖ j_le64)
    │                                   [plausible deniability wallet]
    │
    └─► node_id_full = Argon2id(mnemonic,
                          salt = b"scalar_nodeid" ‖ genesis_hash,
                          memory = 4 GB, iter = 3600, out = 32 bytes)
                          [Tier A/B — anti-Sybil cost embedded in computation]

        node_id_short = BLAKE3(b"scalar_node_short" ‖ node_id_full)[0..4]
                          [used in regular gossip heartbeats]
```

---

## D.8 Network Transport Architecture

```
SCALAR NETWORK NODE
       │
       ├─────────── TIER A TRANSPORT (Consensus messages)
       │            libp2p TCP + Noise + Yamux
       │            OR  Tor 3-hop hidden service
       │            ├── Heartbeats (109–8000 bytes)
       │            ├── STARK proofs (< 150 KB)
       │            ├── Transactions
       │            ├── Epoch manifests
       │            └── NS_CHECKPOINT (~150 KB)
       │
       └─────────── TIER B TRANSPORT (Beacon only)
                    LoRa radio (40 km range) / HF Radio (continental)
                    State Beacon: 44 bytes only
                    ┌─────────────────────────────────┐
                    │  struct StateBeacon {            │
                    │    epoch_id: u64,     // 8 bytes │
                    │    smt_root: [u8;32], //32 bytes │
                    │    mac: [u8;4],       // 4 bytes │
                    │  }  // Total: 44 bytes           │
                    │  MAC = BLAKE3(NodeKey_epoch ‖    │
                    │    epoch_id ‖ smt_root)[0..4]   │
                    └─────────────────────────────────┘

ROUTING RULE: message size > 44 bytes → Tier A
              message size ≤ 44 bytes → Tier B eligible

DANDELION++ (Tier A privacy):
    ┌─ Stem phase (70% prob, DANDELION_REDUCED_STEM_PROB) ────┐
    │  Forward to single peer; random delay 100–5000 ms/hop   │
    │  Encryption: ChaCha20-Poly1305                          │
    │  Small network (<200 nodes): batch obfuscation mode     │
    └─────────────────────────────────────────────────────────┘
         │
         ▼ (fluff transition)
    gossipsub broadcast to all peers

NMT PEER SELECTION:
    24 slots total:
    ├── 23 deterministic: lowest nmt_rank from committed_manifest(k-1)
    │     nmt_rank(id) = BLAKE3(b"scalar_nmt" ‖ id ‖ seed_k)
    │     eligibility: NodeScore > 800,000
    │     diversity: max 3/24-subnet, 5/ASN, 4/region
    └──  1 random: ChaCha20(seed = BLAKE3(seed_k ‖ "nmt_random"))
              from eligible population (NodeScore > 800,000)
              → eclipse attack resistance
```

---

## D.9 Proof-of-Uptime Emission Flow

```
EPOCH k
  │
  ├── [Each node sends heartbeats: 380 per epoch × 120 s = ~12.67 hours]
  │
  ├── UPTIME WEIGHT COMPUTATION
  │   w_i(k) = (700,000 × uptime_ratio_fp
  │            + 300,000 × root_alignment_fp) / 1,000,000
  │
  ├── EMISSION FORMULA
  │   E(k)        = E₀ × (1 − M_E(k−1) / S_E)²
  │   E_active(k) = max(E(k), E_TAIL)
  │   E₀          = 126,000 SCL/epoch
  │   E_TAIL       = 1,000 SCL/epoch
  │
  ├── REWARD DISTRIBUTION
  │   R_pou(i,k) = floor(E_active(k) × w_i(k) / W_effective(k))
  │   R_fee(i,k) = floor(Fee_pool(k) × 0.95 × w_i(k) / W_effective(k))
  │
  ├── RESIDUAL ROUTING (no SCL destroyed)
  │   Emission residual ──► Deferred Emission Pool
  │                         (max 10% × E₀ per epoch; max 12 epochs)
  │   Fee residual (5% + rounding) ──► Security Fund
  │
  └── MINT CLAIM CIRCUIT (MC1–MC5)
      Each node calls Mint Claim to create new UTXO from reward:
      MC1: MerkleVerify(node_id_full, reward, reward_root)
      MC2: Anti-double-claim via mint_nullifier (Poseidon2)
      MC3: Supply cap check: total_pou_minted ≤ S_E
           (pro-rata reduction if needed)
      MC4: Reward amount matches formula
      MC5: SLH-DSA signature with NodeKey

BOOTSTRAP ECONOMICS (first 6 epochs):
  Available reward = (k+1)/6 × R_pou(i,k)
  Remainder locked in S_R until full vesting
```

---

## D.10 Node State Machine

```
        ┌─────────────────────────────────────────────────────┐
        │                  NODE STATES                        │
        └─────────────────────────────────────────────────────┘

  START
    │
    ▼
┌─────────────────┐
│  BOOTSTRAPPING  │ ◄── Loading peers from DHT / hardcoded bootstrap
│                 │     ~50 bootstrap nodes across 10 jurisdictions
└────────┬────────┘
         │  (peers found + transport established)
         ▼
┌─────────────────┐
│    SYNCING      │ ◄── Downloading NS_CHECKPOINT (~150 KB)
│                 │     Downloading NS_ACTIVE snapshot (~15 MB)
│                 │     Verifying utxo_set_root from network_health_digest
│                 │     (must match committed_manifest before DMM eligible)
└────────┬────────┘
         │  (state synchronized)
         ▼
┌─────────────────┐
│    ACTIVE       │ ◄── Sending heartbeats, verifying proofs,
│                 │     participating in manifest consensus,
│                 │     eligible for DMM (if committed_manifest verified)
└────────┬────────┘
         │  (network partition or peer loss)
         ▼
┌─────────────────┐
│   PARTITIONED   │ ◄── Local Time Guard active
│                 │     NMT peers < 9 → cannot compute median time
│                 │     Heartbeats continue but not propagated
└────────┬────────┘
         │  (connectivity restored)
         └──────────────────────► SYNCING (resync before ACTIVE)

NODE RECOVERY PROTOCOL:
  - Download NS_CHECKPOINT + NS_ACTIVE from peers
  - Verify manifest_hash against locally-computed value
  - Gap recovery allowed: 1 time per 6 epochs (1 epoch gap max)
  - Tier C nodes: same flow but Argon2id 16 MB / 100 iter for node_id
```

---

## D.11 Governance Protocol Flow

```
GOVERNANCE PROPOSAL
         │
         ├── Proposer: node_id_full with maturity ≥ 342 epochs (180 days)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  GOVERNANCE POWER COMPUTATION                           │
│                                                         │
│  conviction_factor(t_days):                             │
│    day 1   →  16,529 fp                                │
│    day 30  → 393,469 fp                                │
│    day 365 → 1,000,000 fp (maximum)                    │
│    (smooth curve, no cliff)                            │
│                                                         │
│  GP(i,t) = min(                                        │
│    conviction_factor(t) × min(maturity, W_MATURE)      │
│               / 1,000,000,                             │
│    GOV_MAX_FP_FOR_TIER(i)                              │
│  )                                                      │
│                                                         │
│  Tier A / B:  GOV_MAX_FP = 1,000,000                  │
│  Tier C:      GOV_MAX_FP = 200,000                    │
│  (Tier C cannot dominate even at large scale)          │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  VOTING PHASE        │
              │  Vote signed with    │
              │  NodeKey (SLH-DSA)   │
              └──────────┬───────────┘
                         │
              ┌──────────┴───────────┐
              │                      │
              ▼                      ▼
       ≥75% approval          ≥67% oppose
         → COMMIT               → ABORT
              │
              ▼
     Emergency override:
       ≥51% (critical only)
              │
              ▼
         HARD FORK
         (ossified parameters require fork;
          Layer 2 parameters via governance)
```

---

## D.12 Anti-Attack Summary

| Attack Vector | Mitigation | Specification |
|---|---|---|
| Double-spend | CC dual non-membership (NS_ACTIVE + NS_CHECKPOINT) | SCALAR-TECHNICAL §2.5 |
| Supply inflation | MC3 cap check + AccountingState invariant | SCALAR-TECHNICAL §3 |
| Aggregator manipulation | Deterministic seed from committed_manifest_hash | SCALAR-PROTOCOL §4.3 |
| DMM manipulation | DMM requires verified committed_manifest(k-1) | SCALAR-PROTOCOL §4.3 |
| UTXO ordering attack | tx_ordering_key fully deterministic from BLAKE3 | SCALAR-TECHNICAL §2 |
| Eclipse attack | NMT 23 deterministic + 1 random + DHT random probing | SCALAR-PROTOCOL §11.3 |
| Sybil (governance) | Tier C capped at 200,000 fp; maturity = 342 epochs | SCALAR-PROTOCOL §9 |
| Sybil (NMT) | NodeScore cap 600,000 < threshold 800,000 for Tier C | SCALAR-PROTOCOL §3.1 |
| Quantum adversary | No elliptic curves; all primitives hash-based | SCALAR-SECURITY §4 |
| STARK soundness | 2⁻¹²⁰·⁶⁸ (Scenario B, g=23); formal proof pending | SCALAR-SECURITY §1 |
| Consensus liveness | DMM always produces valid manifest if any synced node exists | SCALAR-PROTOCOL §4.3 |

---

*Aligned with SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY — 2026-07-15*
