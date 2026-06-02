# Scalar Network — Poseidon2 impl#2

Independent Python re-implementation of the Poseidon2 permutation for
multi-client verification per MAD §15.3 / SCALAR-SECURITY §5.3.

## Status

**Phase 1 COMPLETE** — Poseidon2 primitive verified (7/7 test vectors PASS).

| Test | Input | Status |
|------|-------|--------|
| TV-1 OSSIFIED | [0]*8 | ✅ PASS |
| TV-2 p3-goldilocks | [0..7] | ✅ PASS |
| TV-3 dump_rc_canonical | [1,0,...,0] | ✅ PASS |
| TV-4 dump_rc_canonical | [0,1,...,0] | ✅ PASS |
| TV-5 dump_rc_canonical | [1,1,...,1] | ✅ PASS |
| TV-6 dump_rc_canonical | [100..800] | ✅ PASS |
| TV-7 ELL sub-test | [1..8] | ✅ PASS |

Phase 2 (full FRI proof verification) — PENDING pre-mainnet.

## Implementation

- `src/poseidon2.py` — Poseidon2 permutation, Goldilocks field, width=8
- `tests/test_poseidon2.py` — Test runner against OSSIFIED vectors

## Parameters (OSSIFIED — SCALAR-TECHNICAL §1.1)

- Field: Goldilocks p = 2^64 - 2^32 + 1
- Width: t = 8, Alpha: 7, R_F: 8, R_P: 22
- RC source: p3-goldilocks v0.5.3 GOLDILOCKS_POSEIDON2_RC_8_*

## Important: Spec Correction

SCALAR-TECHNICAL §1.1 describes MDSMat4 with rows [2,3,1,1], [3,2,1,1], [1,1,2,3], [1,1,3,2].

The **actual** Plonky3 `apply_mat4` uses a **circulant** matrix:
rows [2,3,1,1], [1,2,3,1], [1,1,2,3], [3,1,1,2] (each row is a right-cyclic shift).

The width-8 mixing formula is also different (sum-based via `mds_light_permutation`,
not 2*left+right). The authoritative source is `p3-poseidon2 v0.5.3 external.rs`.

This impl uses the correct Plonky3 implementation. The spec §1.1 MDSMat4 description
requires correction (documentation bug, not a protocol bug — the Rust code is correct).

## Run Tests

```bash
python3 tests/test_poseidon2.py
```

No external dependencies required (Python 3.6+, stdlib only).
