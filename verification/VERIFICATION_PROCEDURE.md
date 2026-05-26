# Formal Verification and Fuzz Testing — Scalar Network

## Status

| File | Status | Notes |
|---|---|---|
| `invariant_cc.tla` | COMPLETE | Spec §15.4 — dual non-membership invariant |
| `deferred_pool.tla` | COMPLETE | Spec §15.5 — deferred emission pool invariants |
| `invariant_cc.cfg` | COMPLETE | TLC config: 5 nullifiers, MaxEpoch=6 |
| `deferred_pool.cfg` | COMPLETE | TLC config: S_E=100, E0=50, MaxEpoch=15 |

## Running TLC (TLA+ Model Checker)

TLC is not available in GitHub Codespace.
Formal verification **must be executed** by an external auditor before mainnet.

### Prerequisites

```bash
wget https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
java -version  # Java 11+ required
```

### Run invariant_cc.tla (Spec §15.4)

```bash
cd verification/
java -jar tla2tools.jar -config invariant_cc.cfg invariant_cc.tla
```

Expected: `Model checking completed. No error has been found.`

### Run deferred_pool.tla (Spec §15.5)

```bash
cd verification/
java -jar tla2tools.jar -config deferred_pool.cfg deferred_pool.tla
```

Expected: `Model checking completed. No error has been found.`

## Invariants Verified

### invariant_cc.tla (Spec §15.4)
InvariantCC:
FORALL n IN (ns_active UNION ns_checkpoint):
NonMembershipVerify(n, ns_active)     = FALSE
NonMembershipVerify(n, ns_checkpoint) = FALSE

State transitions: InsertNullifier, PromoteToCheckpoint, AdvanceEpoch.
Zero-Gap Property: nullifier cannot disappear between NS_ACTIVE and NS_CHECKPOINT.

### deferred_pool.tla (Spec §15.5)

Five invariants:
1. `D(k) >= 0` — pool is non-negative
2. `D(k) <= S_E` — pool never exceeds supply cap
3. `release(k) <= 10% x E0` — per-epoch release limit
4. `epochs_since_defer <= 12` — maximum defer window
5. `total_released <= total_residual` — conservation (nothing destroyed)

State transitions: AddResidul, ReleaseFromPool, AdvanceEpoch.

## Fuzz Testing — TV5.15 (Spec §5.15)

Fuzz targets are in `fuzz/fuzz_targets/`.

### Running (nightly Rust + cargo-fuzz required)

```bash
# Install cargo-fuzz once
cargo +nightly install cargo-fuzz

# STARKPack adversarial — minimum 10M iterations (TV5.15)
cd fuzz/
cargo +nightly fuzz run fuzz_starkpack_adversarial -- \
  -max_total_time=3600 \
  -runs=10000000

# Nullifier CC invariant fuzz
cargo +nightly fuzz run fuzz_nullifier_cc -- \
  -max_total_time=1800
```

### Attack Vectors Covered (TV5.15)

| Mode | Attack Vector | Expected Result |
|---|---|---|
| 0 | Valid batch | aggregate OK |
| 1 | Tampered proof (0x5c sentinel) | ProofVerificationFailed |
| 2 | Empty proof bytes | ProofVerificationFailed |
| 3 | Mismatched public inputs | ProofVerificationFailed |
| 4 | Order manipulation | transcript_hash differs |
| 5 | Element skipping | transcript_hash differs |
| 6 | Determinism check | hash identical for same input |
| 7 | Batch size overflow | InvalidBatchSize |

### CI Note

Fuzz testing is not run in CI (requires nightly toolchain and >1 hour runtime).
Must be executed manually before mainnet deployment.

## References

- Spec §15.4: Formal Invariant for Dual Non-Membership (CC)
- Spec §15.5: Formal Invariant for Deferred Emission Pool
- Spec §15.1: Six Core Invariants
- PraGenesis §5.15: STARKPack Adversarial Fuzz Test
