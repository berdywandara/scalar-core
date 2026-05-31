# Contributing to Scalar Network

Thank you for your interest in contributing to Scalar Network.  
This guide explains how contributions are structured and what we expect.

**Specification authority:** `SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY` (2026-07-15).  
If there is any conflict between this guide and the specification, the specification takes precedence.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Before You Start](#before-you-start)
- [Development Environment](#development-environment)
- [Contribution Types](#contribution-types)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Cryptographic Implementation Rules](#cryptographic-implementation-rules)
- [Test Requirements](#test-requirements)
- [OSSIFIED Parameters — Do Not Change](#ossified-parameters--do-not-change)
- [Commit Message Format](#commit-message-format)
- [Review Process](#review-process)

---

## Code of Conduct

Be respectful. Focus on technical merit. Keep discussions on-topic.  
Security vulnerabilities must be reported privately — see [SECURITY.md](./SECURITY.md).

---

## Before You Start

1. **Read the specification.** The master technical specification is the single source of truth. All implementation decisions flow from it.
2. **Check existing issues and pull requests.** Your idea may already be in progress.
3. **Open an issue first** for non-trivial changes (new features, architectural modifications, changes to any crate in the protocol dependency chain). This avoids wasted effort.
4. **Never change OSSIFIED parameters** (see the section below) without a formal governance process.

---

## Development Environment

```bash
# Requirements
# - Rust 1.82+ (via rustup)
# - System: Linux or macOS recommended; Windows via WSL2

# Clone
git clone https://github.com/berdywandara/scalar-core
cd scalar-core

# Check compilation (no errors expected, warnings only)
cargo check

# Run tests
cargo test --workspace

# Run with production feature flag (required for mainnet binary)
cargo build --release --features production

# Format
cargo fmt --all

# Lint
cargo clippy --workspace -- -D warnings
```

---

## Contribution Types

### Protocol Crates (`scalar-crypto`, `scalar-nullifier`, `scalar-stark-p3`, `scalar-consensus`, `scalar-emission`)

Highest bar. Any change here must:
- Be fully traceable to a section of the specification
- Include test vectors from `docs/testing/TEST_VECTORS.md` or add new ones
- Be reviewed by at least two maintainers
- Not alter any OSSIFIED parameter

### Network Crate (`scalar-network`)

Changes to gossip, transport selection, Dandelion++ parameters, or NMT peer logic require specification references. Eclipse defense properties must not be weakened.

### Node Binary (`scalar-node`)

RPC endpoints and state machine transitions. Must not bypass any protocol invariant.

### SDK and Audit (`scalar-sdk`, `scalar-audit`)

Read-only and utility code. Must not import protocol crates directly (boundary enforced). Preferred contribution area for ecosystem developers.

### Documentation (`docs/`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`)

Very welcome. Accuracy over brevity. Specification section references (`§X.Y`) are mandatory for any technical claim.

### Tools (`tools/`)

Genesis tool and circuit benchmarks. Changes here do not affect live protocol.

---

## Pull Request Process

1. Fork the repository and create a branch: `git checkout -b feat/your-description`
2. Make your changes following the coding standards below
3. Add or update tests (see Test Requirements)
4. Run `cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace`
5. Open a pull request with:
   - **Title:** concise, imperative (`Add CC invariant test for NS_CHECKPOINT boundary`)
   - **Body:** problem, solution, specification reference (`§X.Y`), test coverage description
6. Link related issues
7. Do not merge your own PR; wait for reviewer approval

---

## Coding Standards

- **Language:** Rust (edition 2021). Stable toolchain only.
- **No `unsafe`** in protocol crates without explicit justification and reviewer sign-off.
- **No `unwrap()` or `expect()`** in library code; propagate errors with `Result`.
- **All public items** must have doc comments with specification references where applicable.
- **Constant-time operations:** Any code that branches on secret data must use constant-time primitives. This is mandatory for Argon2id, key derivation, and nullifier comparison. See §13.2.
- **Feature flags:** Production-specific code goes behind `#[cfg(feature = "production")]`. A compile-time error must fire if a mainnet binary is built without this flag (§10.2).

```rust
// Good — doc comment with spec reference
/// Derives the UTXO commitment per the unified schema.
/// Spec: §3.4, §4.3 (CA constraint)
pub fn compute_commitment(params: &CommitmentParams) -> FieldElement { ... }

// Bad — no spec reference, no error handling
pub fn commitment(v: u64, pk: &[u8]) -> [u8; 32] {
    poseidon2_hash(&[v, ...]).unwrap()
}
```

---

## Cryptographic Implementation Rules

These rules are non-negotiable:

1. **Poseidon2 is for in-circuit only.** BLAKE3 for all out-of-circuit operations. Never swap them.
2. **Domain separators are OSSIFIED.** Never modify, abbreviate, or reuse a domain separator for a different context. See [SCALAR-PROTOCOL §13.1](docs/spec/SCALAR-PROTOCOL.md).
3. **Argon2id implementations must be constant-time.** Execution time variance must be < ±1%. See §13.2.
4. **SLH-DSA signature verification** must use NIST FIPS 205 test vectors for regression.
5. **STARK parameters** (FRI blowup=8, queries=84, grinding=23, folding=4) must not be changed. Any change requires a governance fork (D-028: grinding changed 20→23).
6. **UTXO ordering** must use `tx_ordering_key = BLAKE3(DOMAIN_TX_ORDER ‖ tx_hash ‖ epoch_id)`. No alternative ordering is permitted. See §8.5.
7. **All integer serialization** is little-endian in wire format, big-endian in documentation. See §8.3 (S3).
8. **NullifierSet checkpoint** must use WAL with atomic commit. Zero-Gap Property must be maintained. See §6.3.

---

## Test Requirements

| Contribution Area | Minimum Test Requirement |
|---|---|
| Protocol crate (crypto, stark, nullifier) | Unit tests + test vectors from `docs/TEST_VECTORS.md` |
| Consensus / DMM | Unit test for BuildDMM with: normal case, partial anchor data, no quorum |
| NullifierSet | Checkpoint WAL crash-recovery test; CC dual non-membership boundary test |
| UTXO ordering | Determinism test: two nodes with same tx set must produce identical `utxo_set_root` |
| Network | Eclipse defense: NMT peer diversity constraints enforced |
| Wallet key derivation | SCL-SPEC-SEED-001 test vector (two independent implementations must match) |
| Governance | Tier C governance power cap (200,000 fp) enforced |

For new cryptographic test vectors, add entries to `docs/testing/TEST_VECTORS.md` following the existing format.

---

## OSSIFIED Parameters — Do Not Change

The following values are embedded in circuit constraints and cannot be changed without a hard fork governed by the formal governance process. PRs touching these values will be rejected:

```
S_MAX, S_E, S_R                  — supply caps
E₀, E_TAIL                       — emission constants
FRI blowup factor = 8
FRI queries = 84
Grinding bits = 23  (D-028)
Folding factor = 4
CRYPTO_VERSION_CURRENT = 0x01
SPEC_VERSION_MANIFEST = 0x01
All domain separator byte strings  — see SCALAR-PROTOCOL §13.1
UTXO denominations D1–D17
Argon2id wallet parameters (64 MB / 3 / 1)
```

---

## Commit Message Format

```
<type>(<scope>): <short summary>

[Optional body — explain WHY, reference spec section]

Spec: §X.Y
Fixes #<issue>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `security`  
Scopes: `crypto`, `nullifier`, `stark`, `network`, `consensus`, `emission`, `node`, `wallet`, `sdk`, `audit`, `governance`, `docs`

Examples:
```
feat(consensus): implement BuildDMM secure bootstrapping

Adds prasyarat verification: DMM is only built when the node holds a
locally-verified committed_manifest(k-1). Nodes without a valid prior
manifest cannot participate in DMM.

Spec: §8.2
Fixes #42

fix(nullifier): enforce Zero-Gap Property in WAL checkpoint

Ensures that NS_ACTIVE entries are only deleted after NS_CHECKPOINT
proof is verified and committed atomically.

Spec: §6.3
```

---

## Review Process

- All PRs require at least **one approval** from a maintainer.
- Protocol crate PRs require **two approvals**.
- Security-sensitive PRs (nullifier, STARK constraints, key derivation) require **two approvals plus explicit acknowledgement of the relevant spec invariant**.
- CI must pass: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --workspace`.
- Reviewers will check: spec alignment, constant-time safety, domain separator correctness, test coverage, OSSIFIED parameter preservation.

---

*Last updated: 2026-07-15 — aligned with SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY*
