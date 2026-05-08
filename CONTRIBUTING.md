# Contributing to Scalar Network

Scalar is leaderless by design. There is no company, no foundation, no benevolent dictator. The specification is the authority. Code is law. Contributions are welcome from anyone who understands and respects these principles.

---

## Before You Contribute

Read and internalize two documents:

1. **`Scalar_Master_Technical_Spec_v9.0`** — the single source of truth for all protocol decisions. If your contribution conflicts with the spec, the spec wins. No exceptions.
2. **`README.md`** — architecture overview and build instructions.

If the spec is unclear on something, that is a documentation issue worth raising. If you disagree with the spec, that is a governance matter — not a pull request.

---

## Four Principles That Cannot Be Compromised

Every contribution must preserve these without exception:

1. **No Blockchain** — no blocks, no chain, no leader election, no block producer
2. **Privacy by Default** — value, sender identity, and receiver identity are always private
3. **Mathematical Truth** — validity is determined by STARK proof verification, not by majority vote
4. **Leaderless Design** — no privileged actors, no founder allocation, no special cases

A pull request that violates any of these four principles will not be merged regardless of technical quality.

---

## What Contributions Are Welcome

### Always Welcome
- Bug fixes with reproduction steps and tests
- New tests that improve coverage of existing behavior
- Performance improvements that do not change protocol semantics
- Documentation improvements that increase clarity without changing meaning
- Tooling improvements (CI, build scripts, developer experience)

### Welcome With Discussion First
- New features that extend protocol capabilities
- Changes to existing behavior in any crate
- New crates or major restructuring
- Dependency additions or upgrades

Open an issue before starting significant work. This prevents wasted effort if the direction is wrong.

### Not Welcome
- Changes that introduce floating-point arithmetic anywhere (all calculations must be integer fixed-point)
- Changes that weaken privacy guarantees
- Changes that bypass the NullifierSet or STARK verification
- Changes that add trusted parties, oracles, or privileged roles
- Changes to ossified Layer 1 parameters without a formal spec change and governance process
- Code that is not covered by tests

---

## Definition of Done

Every pull request must satisfy all five conditions before merge:

```
1. cargo test --workspace        → 0 FAILED
2. cargo clippy --workspace      → 0 warnings (with -D warnings)
3. cargo fmt --all -- --check    → 0 diff
4. Spec compliance               → constants and behavior match spec v9.0
5. Tests added                   → new code has test coverage
```

No exceptions. CI enforces conditions 1–3 automatically.

---

## Development Setup

### Prerequisites

- Rust stable (currently 1.95.0)
- GCC (for `pqcrypto-sphincsplus` C compilation)

### Clone and Build

```bash
git clone https://github.com/berdywandara/scalar-core.git
cd scalar-core
cargo build --workspace
cargo test --workspace
# Expected: 965 passed, 0 failed
```

### Alpine Linux / musl Note

If you are on Alpine Linux or a musl-based system, `pqcrypto-sphincsplus` requires a GCC compatibility shim:

```bash
cat > /tmp/cc-wrapper.sh << 'EOF'
#!/bin/sh
exec gcc "-D__GNUC_PREREQ(x,y)=0" "$@"
EOF
chmod +x /tmp/cc-wrapper.sh
export CC=/tmp/cc-wrapper.sh
```

Add this export to your shell profile to make it persistent.

### Running Specific Tests

```bash
# Single crate
cargo test -p scalar-network

# Single test module
cargo test -p scalar-network -- eclipse

# With output
cargo test -p scalar-nullifier -- --nocapture
```

---

## Code Standards

### No Floating Point

All arithmetic must use integer fixed-point with basis `1_000_000`. This is a hard requirement for cross-platform determinism.

```rust
// WRONG
let ratio: f64 = minted as f64 / supply as f64;

// CORRECT
let ratio_fp: u64 = (minted * 1_000_000) / supply;
```

### Hash Usage

Follow the hash rules from spec §2.1.3 strictly:

| Context | Hash |
|---|---|
| In-circuit (commitments, nullifiers, Merkle paths) | Poseidon2 only |
| Out-circuit (NodeID, state hash, connectivity proof) | BLAKE3 only |

Mixing these is a protocol violation that breaks soundness.

### Constants Must Match Spec

Every ossified constant must reference its spec section in a comment:

```rust
/// Maximum gossip fanout. OSSIFIED. Spec §12.3.
pub const MAX_FANOUT: usize = 15;
```

If you add a new constant, include its spec reference and add a compliance test in `scalar-compliance/src/v9_parameters.rs`.

### Zeroize Sensitive Data

Any struct holding private key material must implement `Zeroize` and `ZeroizeOnDrop`:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveKey {
    pub bytes: [u8; 32],
}
```

### Error Handling

Use `Result` with descriptive error types. Do not use `unwrap()` or `expect()` in production code paths. `unwrap()` is acceptable in tests.

---

## Pull Request Process

1. **Fork** the repository and create a branch from `main`
2. **Name your branch** descriptively: `feat/pr-cs-16-genesis-cli`, `fix/bloom-false-positive-edge-case`
3. **Write tests** before or alongside your implementation
4. **Run the full check suite** locally before pushing:
   ```bash
   cargo test --workspace && \
   cargo clippy --workspace -- -D warnings && \
   cargo fmt --all -- --check
   ```
5. **Write a clear commit message** following the existing convention:
   ```
   feat(PR-CS-16): Genesis Ceremony CLI — BLAKE3 hash, verify, spec §12.8
   fix(scalar-nullifier): bloom filter edge case at exact capacity
   docs: update CONTRIBUTING.md
   ```
6. **Open the pull request** with a description that explains:
   - What the change does
   - Which spec section it implements or references
   - How to test it manually if relevant

### Commit Message Format

```
type(scope): short description — spec reference if applicable

type:  feat | fix | docs | test | refactor | chore
scope: crate name or PR ID (e.g., scalar-network, PR-CS-16)
```

---

## Spec Conflicts

If your implementation requires behavior that conflicts with the spec:

1. **Do not merge the conflicting code.** The spec wins.
2. **Open an issue** describing the conflict with a precise reference to the spec section.
3. **If the spec is wrong**, propose a spec amendment through the governance process described in spec §11.
4. **If the spec is ambiguous**, open an issue for clarification before proceeding.

The spec is the authority. Code that disagrees with the spec is a bug, even if the code is technically correct in isolation.

---

## Layer 1 Ossified Parameters

The following parameters are ossified and **cannot be changed by a pull request** under any circumstances. They require a formal governance fork process per spec §11.7:

- Goldilocks prime (2⁶⁴ - 2³² + 1)
- Poseidon2 parameters (t=4, d=7, RF=8, RP=22)
- Supply cap (21,000,000 SCL)
- PoU pool (18,900,000 SCL)
- E₀ (126,000 SCL/epoch)
- FLOOR_MIN_ABSOLUTE (40 sSCL)
- MAX_IO per transaction (10/10)
- MAX_FANOUT (15)
- STARK soundness target (ε ≈ 2⁻⁶¹⁴⁴)
- Multi-client STARK mandate (2 independent implementations)
- Fee burn (0%)
- Conflict resolution method (67% network consensus)

A pull request modifying any of these values will be rejected immediately.

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Follow the responsible disclosure process described in `SECURITY.md`.

---

## Recognition

Contributors are listed in `AUTHORS.md`. All contributions that are merged are credited. Security researchers who report valid vulnerabilities are listed under a dedicated section in `AUTHORS.md` with their permission.

---

## Questions

If you are unsure whether a contribution is appropriate, open an issue and ask before investing significant time. It is better to discuss direction early than to build something that cannot be merged.

> *Scalar is built on the principle that mathematical truth does not require consensus. The same applies to good code: it either satisfies the specification or it does not. There is no middle ground.*