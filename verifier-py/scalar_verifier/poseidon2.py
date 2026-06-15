"""
Poseidon2 permutation (t=8, Goldilocks) — Python impl#2.

Round constants: p3-goldilocks v0.5.3 src/poseidon2.rs (Grain LFSR, upstream canonical).
Algorithm: p3-poseidon2 v0.5.3 src/external.rs + src/generic.rs (MDSMat4).

Does NOT import from scalar-stark-p3 or scalar_crypto. [SCALAR-SECURITY §5.3, P4]
Ref: SCALAR-TECHNICAL §2.1, D-010, D-011.
"""

from .proof_params import GOLDILOCKS_P as P

# ── Round constants from p3-goldilocks v0.5.3 ────────────────────────────────
RC_EXTERNAL_INITIAL: list[list[int]] = [
    [0xdd5743e7f2a5a5d9, 0xcb3a864e58ada44b, 0xffa2449ed32f8cdc, 0x42025f65d6bd13ee,
     0x7889175e25506323, 0x34b98bb03d24b737, 0xbdcc535ecc4faa2a, 0x5b20ad869fc0d033],
    [0xf1dda5b9259dfcb4, 0x27515210be112d59, 0x4227d1718c766c3f, 0x26d333161a5bd794,
     0x49b938957bf4b026, 0x4a56b5938b213669, 0x1120426b48c8353d, 0x6b323c3f10a56cad],
    [0xce57d6245ddca6b2, 0xb1fc8d402bba1eb1, 0xb5c5096ca959bd04, 0x6db55cd306d31f7f,
     0xc49d293a81cb9641, 0x1ce55a4fe979719f, 0xa92e60a9d178a4d1, 0x002cc64973bcfd8c],
    [0xcea721cce82fb11b, 0xe5b55eb8098ece81, 0x4e30525c6f1ddd66, 0x43c6702827070987,
     0xaca68430a7b5762a, 0x3674238634df9c93, 0x88cee1c825e33433, 0xde99ae8d74b57176],
]
RC_EXTERNAL_FINAL: list[list[int]] = [
    [0x014ef1197d341346, 0x9725e20825d07394, 0xfdb25aef2c5bae3b, 0xbe5402dc598c971e,
     0x93a5711f04cdca3d, 0xc45a9a5b2f8fb97b, 0xfe8946a924933545, 0x2af997a27369091c],
    [0xaa62c88e0b294011, 0x058eb9d810ce9f74, 0xb3cb23eced349ae4, 0xa3648177a77b4a84,
     0x43153d905992d95d, 0xf4e2a97cda44aa4b, 0x5baa2702b908682f, 0x082923bdf4f750d1],
    [0x98ae09a325893803, 0xf8a6475077968838, 0xceb0735bf00b2c5f, 0x0a1a5d953888e072,
     0x2fcb190489f94475, 0xb5be06270dec69fc, 0x739cb934b09acf8b, 0x537750b75ec7f25b],
    [0xe9dd318bae1f3961, 0xf7462137299efe1a, 0xb1f6b8eee9adb940, 0xbdebcc8a809dfe6b,
     0x40fc1f791b178113, 0x3ac1c3362d014864, 0x9a016184bdb8aeba, 0x95f2394459fbc25e],
]
RC_INTERNAL: list[int] = [
    0x488897d85ff51f56, 0x1140737ccb162218, 0xa7eeb9215866ed35,
    0x9bd2976fee49fcc9, 0xc0c8f0de580a3fcc, 0x4fb2dae6ee8fc793,
    0x343a89f35f37395b, 0x223b525a77ca72c8, 0x56ccb62574aaa918,
    0xc4d507d8027af9ed, 0xa080673cf0b7e95c, 0xf0184884eb70dcf8,
    0x044f10b0cb3d5c69, 0xe9e3f7993938f186, 0x1b761c80e772f459,
    0x606cec607a1b5fac, 0x14a0c2e1d45f03cd, 0x4eace8855398574f,
    0xf905ca7103eff3e6, 0xf8c8f8d20862c059, 0xb524fe8bdd678e5a,
    0xfbb7865901a1ec41,
]
MATRIX_DIAG_8: list[int] = [
    0xfffffffeffffffff,  # -2 mod p
    0x0000000000000001,  # 1
    0x0000000000000002,  # 2
    0x7fffffff80000001,  # 1/2 mod p
    0x0000000000000003,  # 3
    0x7fffffff80000000,  # -1/2 mod p
    0xfffffffefffffffe,  # -3 mod p
    0xfffffffefffffffd,  # -4 mod p
]

# ── Field arithmetic ──────────────────────────────────────────────────────────
def fadd(a: int, b: int) -> int: return (a + b) % P
def fmul(a: int, b: int) -> int: return (a * b) % P
def sbox(x: int) -> int: return pow(x, 7, P)  # alpha=7

# ── MDSMat4: apply_mat4 from p3-poseidon2 external.rs ────────────────────────
# Matrix: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
def apply_mat4(x: list[int]) -> list[int]:
    t01   = fadd(x[0], x[1])
    t23   = fadd(x[2], x[3])
    t0123 = fadd(t01, t23)
    t01123 = fadd(t0123, x[1])   # x[0]+2x[1]+x[2]+x[3]
    t01233 = fadd(t0123, x[3])   # x[0]+x[1]+x[2]+2x[3]
    r3 = fadd(t01233, fadd(x[0], x[0]))   # 3x[0]+x[1]+x[2]+2x[3]
    r1 = fadd(t01123, fadd(x[2], x[2]))   # x[0]+2x[1]+3x[2]+x[3]
    r0 = fadd(t01123, t01)                 # 2x[0]+3x[1]+x[2]+x[3]
    r2 = fadd(t01233, t23)                 # x[0]+x[1]+2x[2]+3x[3]
    return [r0, r1, r2, r3]

# ── mds_light_permutation for WIDTH=8 (p3-poseidon2 external.rs) ─────────────
def mds_light_permutation_8(state: list[int]) -> list[int]:
    # Step 1: apply MDSMat4 to each 4-element chunk
    c0 = apply_mat4(state[0:4])
    c1 = apply_mat4(state[4:8])
    state = c0 + c1

    # Step 2: precompute 4 sums (one per position mod 4)
    # sums[k] = sum of state[k], state[k+4]  (for WIDTH=8, step=4)
    sums = [fadd(state[k], state[k + 4]) for k in range(4)]

    # Step 3: add sums[i % 4] to each element
    return [fadd(state[i], sums[i % 4]) for i in range(8)]

# ── Internal linear layer ─────────────────────────────────────────────────────
def internal_linear_layer_8(state: list[int]) -> list[int]:
    # sum = Σ state[i]
    s = 0
    for x in state:
        s = fadd(s, x)
    # state[i] = s + diag[i] * state[i]
    return [fadd(s, fmul(MATRIX_DIAG_8[i], state[i])) for i in range(8)]

# ── Poseidon2 permutation ─────────────────────────────────────────────────────
def poseidon2_permute_t8(state_in: list[int]) -> list[int]:
    """
    Poseidon2 permutation t=8, Goldilocks, R_F=8, R_P=22, alpha=7.
    Algorithm: external_initial_permute_state + internal + external_terminal_permute_state.
    [p3-poseidon2 v0.5.3 src/external.rs, SCALAR-TECHNICAL §2.1 D-010 D-011]
    """
    state = [x % P for x in state_in]

    # external_initial_permute_state:
    # 1. initial mds_light_permutation (before first round constants)
    state = mds_light_permutation_8(state)

    # 2. 4 initial full rounds: add_rc + sbox + mds
    for r in range(4):
        state = [fadd(state[i], RC_EXTERNAL_INITIAL[r][i]) for i in range(8)]
        state = [sbox(x) for x in state]
        state = mds_light_permutation_8(state)

    # 22 partial rounds: add_rc (first elem) + sbox (first elem) + internal linear
    for r in range(22):
        state[0] = fadd(state[0], RC_INTERNAL[r])
        state[0] = sbox(state[0])
        state = internal_linear_layer_8(state)

    # 4 final full rounds: add_rc + sbox + mds
    for r in range(4):
        state = [fadd(state[i], RC_EXTERNAL_FINAL[r][i]) for i in range(8)]
        state = [sbox(x) for x in state]
        state = mds_light_permutation_8(state)

    return state

# ── field_reduce (Goldilocks) ─────────────────────────────────────────────────
def field_reduce(x: int) -> int:
    """Reduce x into [0, p). Goldilocks: p = 2^64 - 2^32 + 1."""
    # Equivalent to scalar_crypto::poseidon2::field_reduce
    x = x & 0xFFFFFFFFFFFFFFFF  # truncate to u64
    return x % P

# ── poseidon2_hash_chained ────────────────────────────────────────────────────
def poseidon2_hash_chained(inputs: list[int]) -> list[int]:
    """
    Rate-4 chained sponge WITHOUT padding.
    Absorb input in chunks of RATE=4 via XOR + field_reduce, then permute.
    Must match scalar_crypto::poseidon2_t8::poseidon2_hash_chained.
    [SCALAR-TECHNICAL §2.1, D-010: NOT 10* padded sponge]
    """
    RATE = 4
    state = [0] * 8
    inputs_u64 = [x & 0xFFFFFFFFFFFFFFFF for x in inputs]

    # Absorb in chunks of RATE, XOR into rate portion, then permute
    for block_start in range(0, len(inputs_u64), RATE):
        chunk = inputs_u64[block_start:block_start + RATE]
        for i, v in enumerate(chunk):
            state[i] = field_reduce(state[i] ^ field_reduce(v))
        state = poseidon2_permute_t8(state)

    return state[:4]

# ── poseidon2_hash_to_4 ───────────────────────────────────────────────────────
def poseidon2_hash_to_4(inputs: list[int]) -> list[int]:
    """
    Single permutation hash (D-010): zero-pad to width=8, field_reduce, permute once.
    Used by Poseidon2T8Hasher::hash_to_4. Input must be <= 8 elements.
    Must match scalar_crypto::poseidon2_t8::Poseidon2T8Hasher::hash_to_4.
    [SCALAR-TECHNICAL §2.1, D-010]
    """
    assert len(inputs) <= 8, f"D-010: max 8 inputs, got {len(inputs)}"
    state = [0] * 8
    for i, v in enumerate(inputs):
        state[i] = field_reduce(v)
    state = poseidon2_permute_t8(state)
    return state[:4]
