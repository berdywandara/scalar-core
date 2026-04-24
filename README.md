# Scalar Network

> **"Truth by Mathematics, Not by Majority."**

Scalar Network is a post-quantum digital cash system that operates **without a blockchain**. Instead of a chain of blocks validated by majority consensus, every transaction is proven valid by a zero-knowledge STARK proof and recorded as a spent nullifier in a Sparse Merkle Tree — a system where mathematical certainty replaces social agreement.

**Conceived and designed by [Berdy Wandara](https://github.com/berdywandara).**

---

## The Core Idea

Traditional blockchains ask: *"Do enough nodes agree this transaction is valid?"*

Scalar asks: *"Can the sender prove — mathematically, beyond doubt — that this transaction is valid?"*

If the proof verifies, the transaction is accepted. No miners. No validators. No majority vote. The math is the consensus.

---

## Why Post-Quantum?

Bitcoin and Ethereum rely on elliptic curve cryptography (ECDSA/secp256k1). A sufficiently powerful quantum computer running Shor's algorithm can break these schemes — deriving private keys from public keys. This is not a distant theoretical threat; it is an engineering timeline question.

Scalar is built from the ground up with quantum-resistant primitives:

| Purpose | Algorithm | Standard |
|---|---|---|
| Signatures | SPHINCS+-SHAKE-256s | NIST FIPS 205 |
| Key Exchange | ML-KEM-768 (Kyber) | NIST FIPS 203 |
| ZK Proofs | zk-STARKs (Winterfell) | Hash-based, quantum-safe |
| In-circuit Hash | Poseidon2 (Goldilocks field) | ZK-optimized |
| Network Hash | BLAKE3 | Post-quantum safe |
| Channel Encryption | ChaCha20-Poly1305 | — |

There is no elliptic curve anywhere in this stack.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  SCALAR NETWORK NODE                    │
├─────────────────────────────────────────────────────────┤
│  scalar-node          — Boot, state machine, RPC (7777) │
├─────────────────────────────────────────────────────────┤
│  scalar-network       — P2P: gossipsub + Kademlia DHT   │
│    transport/internet — libp2p TCP + Noise + Yamux      │
│    transport/tor      — Tor SOCKS5 (tokio-socks)        │
│    transport/lora     — LoRa radio (200B MTU fragments) │
│    transport/mux      — Adaptive transport selection    │
│    onion              — 3-hop routing, 4 padding sizes  │
│    gossip             — Delta sync via gossipsub        │
├─────────────────────────────────────────────────────────┤
│  scalar-consensus     — Verify proofs, update SMT       │
├─────────────────────────────────────────────────────────┤
│  scalar-nullifier     — ScalarSMT (depth-32) + proofs  │
├─────────────────────────────────────────────────────────┤
│  scalar-stark         — AIR constraints + Winterfell    │
│    constraints/       — C1–C8: commitment, nullifier,   │
│                         merkle, value, auth             │
├─────────────────────────────────────────────────────────┤
│  scalar-crypto        — Poseidon2, SPHINCS+, ML-KEM,   │
│                         ChaCha20 channel, BLAKE3        │
├─────────────────────────────────────────────────────────┤
│  scalar-wallet-core   — Keys, coin selection, tx build  │
├─────────────────────────────────────────────────────────┤
│  scalar-governance    — Quadratic voting, tally circuit │
└─────────────────────────────────────────────────────────┘
```

---

## How a Transaction Works

```
1. PROVE
   Sender holds a coin (a commitment C = Poseidon2(value ‖ secret ‖ salt))
   Wallet generates:
     N_circuit = Poseidon2(secret ‖ spending_key)   ← nullifier, in-circuit
     N_network = BLAKE3(N_circuit)                   ← nullifier, broadcast
     STARK proof: C1–C8 constraints satisfied
       C1: input commitment valid
       C2: nullifier derived correctly (Poseidon2)
       C3: coin exists in genesis SMT
       C4: nullifier NOT yet in NullifierSet (anti-double-spend)
       C5: Σ inputs = Σ outputs + fee
       C6: all values ≥ 0 (range proof)
       C7: output commitment valid
       C8: spending_key → pubkey_commitment (SPHINCS+ verified publicly)

2. SIGN
   Sender signs the transaction with SPHINCS+-SHAKE-256s
   (verified at the node level, outside the circuit)

3. BROADCAST
   ScalarGossipMessage { nullifier, stark_proof, sphincs_sig, new_commitment }
   propagates via libp2p gossipsub → all nodes receive

4. VERIFY & RECORD
   Every node independently:
     a. Verifies SPHINCS+ signature
     b. Verifies STARK proof (5–20 ms)
     c. Checks nullifier ∉ local NullifierSet
     d. Inserts nullifier into NullifierSet → SMT root updates
   No vote. No coordination. Pure math.
```

---

## Supply

```
Total supply:    21,000,000 SCL  (fixed forever, like Bitcoin)
Smallest unit:   1 sSCL = 10⁻⁸ SCL
Total sSCL:      2,100,000,000,000,000

Fixed denominations (17):
1, 5, 10, 50, 100, 500, 1K, 5K, 10K, 50K,
100K, 500K, 1M, 5M, 10M, 50M, 100M sSCL
```

There is no inflation mechanism. The supply is a mathematical constant embedded in the genesis proof.

---

## Network Resilience

Scalar is designed to function across all communication conditions:

| Condition | Transport |
|---|---|
| Normal | Internet (libp2p TCP + Noise + Yamux) |
| Censored | Tor hidden services + obfs4/Snowflake pluggable transports |
| Internet down | LoRa mesh radio (40 km range, 200-byte MTU) |
| Emergency | HF Radio (continental range) |
| Face-to-face | QR code exchange (no connectivity required) |

Transport selection is automatic. Users see only "Connected" or a status indicator. The underlying routing is invisible.

All connections are end-to-end encrypted with ML-KEM key exchange + ChaCha20-Poly1305. All messages are padded to one of four standard sizes (1 KB / 16 KB / 64 KB / 256 KB) to prevent traffic analysis.

---

## Peer Discovery

50 hardcoded bootstrap nodes across 10 jurisdictions (US, EU, SG, JP, CH, IS, BR, ZA, AE, AU), with no single country exceeding 15% of bootstrap capacity. Discovery uses Kademlia DHT — no DNS dependency. Bootstrap addresses are `.onion` first, clearnet fallback.

---

## Governance

Scalar uses on-chain quadratic voting:

```
Voting power = √(SCL held)
Cap = √(0.001 × 21,000,000) = 144.9 votes maximum
```

Individual votes generate STARK proofs. A recursive tally circuit aggregates them into a single `governance_approval_proof`. An anti-flash-loan constraint requires SCL to be locked prior to the proposal timestamp.

---

## Repository Structure

```
scalar-core/
├── crates/
│   ├── scalar-crypto/        # Post-quantum cryptographic primitives
│   ├── scalar-nullifier/     # ScalarSMT + NullifierSet + delta sync
│   ├── scalar-stark/         # AIR definition + Winterfell prover/verifier
│   ├── scalar-network/       # P2P networking, transports, gossip
│   ├── scalar-node/          # Node binary, state machine, RPC
│   ├── scalar-wallet-core/   # Key derivation, coin selection, tx builder
│   ├── scalar-consensus/     # Consensus engine (math, not majority)
│   ├── scalar-governance/    # Quadratic voting + tally circuit
│   └── scalar-ffi/           # FFI bindings for mobile (UniFFI)
├── tools/
│   ├── genesis-tool/         # Generate the genesis proof object
│   └── circuit-bench/        # Benchmark proof generation
├── apps/
│   └── mobile/               # Flutter cross-platform wallet app
├── AUTHORS.md
├── .gitignore
└── Cargo.toml
```

---

## Running a Node

**Requirements:** Rust 1.82+, ~2 GB storage, ~500 MB/month bandwidth.

```bash
# Clone
git clone https://github.com/berdywandara/scalar-core
cd scalar-core

# Check everything compiles
cargo check

# Run a node
cargo run --bin scalar-node

# Query the node (in a second terminal)
curl http://localhost:7777              # node status
curl http://localhost:7777/get_smt_root # current NullifierSet root
curl http://localhost:7777/get_node_state
```

Node states: `BOOTSTRAPPING → SYNCING → ACTIVE → PARTITIONED`

The node transitions automatically based on network connectivity and SMT sync status.

---

## Development Status

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Core architecture, zk-STARK foundation | ✅ Complete |
| Phase 2 | Network layer, multi-transport, gossip | ✅ Complete |
| Phase 4 | Wallet architecture, key management, UX | ✅ Complete |
| Phase 5 | Integration review, gap resolution | ✅ Complete |
| Phase 6 | P2P swarm integration, mobile app, mainnet | 🔄 In Progress |

`cargo check` passes with warnings only (no errors). All 30 architectural components from the design documents are implemented.

---

## Design Principles

**No blockchain.** There are no blocks, no chain, no longest-chain rule. There is a NullifierSet (a Sparse Merkle Tree) and a set of Proof Objects. That is the entire state.

**No majority vote.** A transaction is valid because its STARK proof verifies — not because 51% of nodes agreed. A node running alone in an isolated network reaches the same conclusions as a node connected to 10,000 peers.

**No trusted setup.** zk-STARKs require no trusted ceremony. There is no "toxic waste" to compromise. The security assumptions are hash function collision resistance only.

**No elliptic curves.** Not for signatures, not for key exchange, not anywhere. The entire stack is quantum-resistant by construction.

**Privacy by default.** Transaction amounts, senders, and recipients are hidden from the network. Only the mathematical validity of the transaction is public.

---

## Concept Origin

Scalar Network was conceived and designed by **Berdy Wandara** as an exploration of what digital cash looks like when you start from first principles in the post-quantum era — discarding the assumptions of Bitcoin's 2009 design and rebuilding from the mathematics of zero-knowledge proofs and hash-based cryptography.

The design documents span five phases covering cryptographic architecture, network protocol, wallet UX, governance, and integration — totaling several hundred pages of specification written before a single line of code existed.

> *"The most dangerous assumption in cryptography is that the hard problem you rely on will stay hard."*
> — Berdy Wandara

---

## License

MIT OR Apache-2.0

---

## Authors

See [AUTHORS.md](AUTHORS.md).

Scalar Network protocol was initiated and fundamentally designed by **Berdy Wandara** (Original Architect & Founder). Per the leaderless principle of the protocol, this attribution is purely historical — it confers no special allocation or privilege within the running network.