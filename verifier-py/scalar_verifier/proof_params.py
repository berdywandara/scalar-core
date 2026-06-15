"""
SCALAR proof system parameters — single source of truth.

All constants in this file derive from SCALAR-SECURITY §[PROOF-PARAMS].
DO NOT write literal values elsewhere in this codebase.

Ref: SCALAR-SECURITY §[PROOF-PARAMS] (§1.2), §1.4, K-2, K-3.
"""

# ── Field ────────────────────────────────────────────────────────────────────
# Goldilocks prime: p = 2^64 - 2^32 + 1. [SCALAR-SECURITY §[PROOF-PARAMS]]
GOLDILOCKS_P: int = (1 << 64) - (1 << 32) + 1

# Cubic extension GF(p^3) modulus: x^3 - x - 1. [SCALAR-SECURITY §[PROOF-PARAMS]]
# Extension field elements are polynomials a0 + a1*x + a2*x^2 mod (x^3 - x - 1).
CUBIC_EXT_MODULUS_COEFFS: tuple[int, int, int, int] = (
    GOLDILOCKS_P - 1,  # constant: -1 mod p
    GOLDILOCKS_P - 1,  # x coeff: -1 mod p
    0,                 # x^2 coeff: 0
    1,                 # x^3 coeff: 1  → x^3 = x + 1 (mod p)
)

# ── FRI parameters ───────────────────────────────────────────────────────────
# Number of FRI queries. OSSIFIED. [SCALAR-SECURITY §[PROOF-PARAMS]]
FRI_NUM_QUERIES: int = 108

# Proof-of-work grinding bits. g=0 (grinding amputated). [SCALAR-SECURITY §[PROOF-PARAMS]]
FRI_GRINDING_BITS: int = 0

# ── Soundness ────────────────────────────────────────────────────────────────
# Per-proof soundness (Johnson bound): 2^-162. [SCALAR-SECURITY §1.4]
SOUNDNESS_PER_PROOF_LOG2: int = -162

# Post-batch soundness N=256: 2^-154 = 2^8 * 2^-162. [SCALAR-SECURITY §1.4, K-3]
BATCH_SIZE_N: int = 256
SOUNDNESS_POST_BATCH_LOG2: int = -154  # union bound: N * epsilon_per_proof

# ── Poseidon2 parameters (t=8, Goldilocks) ───────────────────────────────────
# Must match scalar_crypto::poseidon2_t8. [SCALAR-TECHNICAL §2.1]
POSEIDON2_WIDTH: int = 8       # state size t=8
POSEIDON2_RATE: int = 4        # rate elements per absorb
POSEIDON2_CAPACITY: int = 4    # capacity elements
POSEIDON2_FULL_ROUNDS: int = 8
POSEIDON2_PARTIAL_ROUNDS: int = 22
POSEIDON2_SBOX_EXP: int = 7    # S-box exponent x^7
