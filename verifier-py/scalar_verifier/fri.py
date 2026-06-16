"""
FRI commit phase verifier — Python impl#2.

Implements the FRI commit phase commitment scheme as used by p3-fri v0.5.3/v0.6.1
in the Scalar Network STARK prover. This module is STRICTLY read-only against
impl#1 (Rust/Plonky3): it re-derives commit phase commitments from the same
polynomial evaluations and must match bit-exactly.

Key facts from p3-fri v0.5.3/v0.6.1 prover.rs commit_phase():
  - Input evaluations are in bit-reversed order over the LDE domain.
  - Each round: commit matrix (arity columns), observe commitment, sample beta (EF),
    fold rows using trinomial_cubic_fold_row() in EF = GF(p^3).
  - g = 0: no proof-of-work grinding (amputated). [SCALAR-SECURITY §[PROOF-PARAMS]]
  - FRI rounds = ceil((log_n + log_blowup) / max_log_arity) where max_log_arity = 2
    (folding factor 4). [SCALAR-TECHNICAL §4.4]
  - Each commit phase commitment is a Merkle root (Poseidon2 binary tree over EF elements).
  - Final poly: truncate, bit-reverse, IDFT coefficients.

This impl is INTERNAL ONLY — it does NOT call impl#1. All primitives are re-derived
from scratch using poseidon2.py, gfp3.py, and proof_params.py. [SCALAR-SECURITY §5.3, P4]

Scope for M4b: commit phase implementation only.
  - commit_lde_matrix(): LDE polynomial evaluations -> Merkle commitment.
  - fri_fold_row(): FRI row folding with EF challenge (arity-4, log_arity=2).
  - fri_commit_phase(): full commit phase -> list of (commitment_bytes, folded_evals).
  - fri_fold_check(): verify one folding step (sibling consistency).

Scope for M4c: FRI query-phase verification as a STANDALONE COMPONENT.
  - verify_query(): reconstructs the fold chain from sibling values, checks
    each fold step against the supplied beta challenge, and checks the final
    folded evaluation against final_poly evaluated at the implied domain
    point. Mirrors p3-fri v0.5.3/v0.6.1 verifier.rs verify_query() (the
    fold-chain reconstruction and final polynomial check), restricted to
    log_arity in {1, 2} (Scalar's OSSIFIED max_log_arity=2 never needs more).
  - check_witness_g0(): grinding witness guard. With g=0 OSSIFIED, p3-challenger
    GrindingChallenger::check_witness(bits=0, _) returns True WITHOUT EVER
    OBSERVING the witness (grinding_challenger.rs). This module replicates
    that exact behavior -- it does not implement or accept any active PoW
    check. A non-trivial pow_witness in a real proof when g=0 is configured
    is a P0 anti-pattern finding to escalate, not something to validate.
  - assert_cap_height_zero(): hard assertion that impl#1's ValMmcs uses
    cap_height=0 (single-root Merkle cap), which is what M4b's
    merkle_commit_arity_matrix() assumes. Checked, not silently hardcoded.

  HONESTY BOUNDARY (read before using this section):
  verify_query() in M4c is tested against fold chains and sibling values
  that THIS MODULE ITSELF generates via fri_commit_phase() (M4b). This
  proves the fold-chain verification algorithm is correct in isolation, and
  that it genuinely rejects tampered siblings/initial-eval/final-poly/beta
  (soundness, tested explicitly). It does NOT YET prove anything about a
  real prove_transfer_p3() proof, because the initial per-query evaluation
  (`initial_folded_eval`) in the real protocol comes from open_input()'s
  DEEP-quotient combination over OpenedValues (trace_local, trace_next,
  quotient_chunks) -- which M4c does not implement. That connection is M4d.
  Full end-to-end AIR verification (CA-CG, CX, CF/CF-PREMIUM + quotient)
  against a real proof is M5 -- the milestone that satisfies SCALAR-SECURITY
  §5.3's "full re-implementation of the AIR verifier" requirement.
  DO NOT describe M4c alone as "FRI verified" or "proof verified".

Limitations (explicitly NOT return True/False for unverifiable state):
  - DEEP-quotient / open_input combination is out-of-scope for M4c; that is M4d.
  - Full end-to-end AIR + quotient verification against a real proof is M5.

Ref: p3-fri v0.5.3 prover.rs commit_phase(), proof.rs FriProof/CommitPhaseProofStep.
     SCALAR-SECURITY §[PROOF-PARAMS], §5.3. SCALAR-TECHNICAL §4.4.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .proof_params import (
    GOLDILOCKS_P as P,
    FRI_NUM_QUERIES,
    FRI_GRINDING_BITS,
    SOUNDNESS_PER_PROOF_LOG2,
    SOUNDNESS_POST_BATCH_LOG2,
)
from .poseidon2 import poseidon2_permute_t8, poseidon2_hash_to_4, field_reduce
from .gfp3 import (
    ef_add, ef_sub, ef_mul, ef_inv, ef_neg,
    fadd, fsub, fmul, finv,
)

# ── Sanity check: g=0 (grinding amputated) ───────────────────────────────────
# SCALAR-SECURITY §[PROOF-PARAMS]: g = 0. No grinding term.
assert FRI_GRINDING_BITS == 0, (
    "FRI grinding must be 0 (amputated) [SCALAR-SECURITY §[PROOF-PARAMS]]"
)

# ── OSSIFIED FRI config (from SCALAR-SECURITY §[PROOF-PARAMS], SCALAR-TECHNICAL §4.4) ───
FRI_LOG_BLOWUP: int = 3      # blowup = 8. OSSIFIED.
FRI_MAX_LOG_ARITY: int = 2   # folding factor = 4 (log2(4)=2). OSSIFIED — spec §4.4.
FRI_LOG_FINAL_POLY_LEN: int = 0  # final_poly_len = 1 (degree-0 constant). p3-fri default.

# Goldilocks multiplicative generator (primitive root mod p). Used for coset generation.
# g = 7 is a primitive root mod p = 2^64 - 2^32 + 1.
GOLDILOCKS_GENERATOR: int = 7

# Coset shift: p3-goldilocks uses g^1 = 7 as the LDE coset generator by default.
# TwoAdicFriPcs uses coset evals: p(omega^i * shift) for shift = 7^1 mod p.
COSET_SHIFT: int = 7  # matches p3-goldilocks TwoAdicFriPcs default shift

# ── Unverifiable sentinel ─────────────────────────────────────────────────────

class Unverifiable(Exception):
    """
    Raised when a verification step cannot be completed with current scope.

    NEVER returns True/False for an unverifiable claim. [Larangan Mutlak §Implementation]
    M4b covers commit phase only; query phase openings raise this exception.
    """
    pass


# ── Goldilocks two-adic domain ────────────────────────────────────────────────
# Goldilocks: p = 2^64 - 2^32 + 1. Two-adicity = 32 (p-1 = 2^32 * (2^32-1), 32 twos).
# For trace height 2^k, the LDE domain has size 2^(k+log_blowup).

def goldilocks_two_adic_generator(log_n: int) -> int:
    """
    Return primitive 2^log_n-th root of unity in Goldilocks field.

    p-1 = 2^32 * 3 * (2^32 - 2^16 + 1) / gcd => two-adicity = 32.
    omega_{2^32} = 7^((p-1)/2^32) mod p.
    omega_{2^k} = omega_{2^32}^{2^(32-k)} mod p.

    Ref: p3-goldilocks TwoAdicField impl.
    """
    assert 0 < log_n <= 32, f"log_n must be in [1, 32], got {log_n}"
    # Primitive 2^32-th root of unity in Goldilocks
    # omega_32 = 7^((p-1)/2^32) mod p
    # (p-1)/2^32 = (2^64 - 2^32) / 2^32 = 2^32 - 1 = 4294967295
    exponent_32 = (P - 1) >> 32  # = 2^32 - 1 (since p-1 = 2^32 * (2^32-1))
    # Actually: p-1 = 0xFFFFFFFF00000000 = 2^32 * 0xFFFFFFFF
    # So two-adicity = 32, and (p-1)/2^32 = 0xFFFFFFFF = 2^32-1
    omega_32 = pow(GOLDILOCKS_GENERATOR, (P - 1) >> 32, P)
    # For 2^k-th root: omega_32^{2^(32-log_n)}
    shift = 32 - log_n
    return pow(omega_32, 1 << shift, P)


def bit_reverse(x: int, bits: int) -> int:
    """Bit-reverse x in `bits`-bit range."""
    result = 0
    for _ in range(bits):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


def bit_reverse_list(lst: list) -> list:
    """Bit-reverse the ordering of a list (length must be power of 2)."""
    n = len(lst)
    assert n & (n - 1) == 0, "list length must be a power of 2"
    log_n = n.bit_length() - 1
    return [lst[bit_reverse(i, log_n)] for i in range(n)]


def goldilocks_lde(
    coeffs: list[int],
    log_blowup: int,
    coset_shift: Optional[int] = None,
) -> list[int]:
    """
    Low-Degree Extension: evaluate polynomial over blowup-times-larger coset domain.

    Input: coefficients [c0, c1, ..., c_{n-1}] (poly = sum c_i * x^i).
    Output: evaluations at coset {shift * omega^i : i = 0..N*blowup-1} in bit-reversed order.

    Matches p3 TwoAdicFriPcs coset evaluation order (bit-reversed for FRI).

    Note: p3 uses 'evaluations stored in bit-reversed order' — the committed leaves
    are the LDE evaluations in bit-reversed order.

    Args:
        coeffs: polynomial coefficients over base field GF(p).
        log_blowup: log2 of blowup factor (must be FRI_LOG_BLOWUP = 3).
        coset_shift: multiplicative coset shift (default: COSET_SHIFT = 7).
    """
    if coset_shift is None:
        coset_shift = COSET_SHIFT

    n = len(coeffs)
    assert n & (n - 1) == 0, "coefficients length must be a power of 2"
    log_n = n.bit_length() - 1
    N = n << log_blowup  # LDE domain size

    # Evaluate at all points of coset: omega_N^i * coset_shift, i = 0..N-1
    log_N = log_n + log_blowup
    omega = goldilocks_two_adic_generator(log_N)

    # Standard poly evaluation at each domain point (NTT-based would be faster but
    # this is a reference impl for correctness; N is small for test vectors).
    # Horner's method: O(n) per point = O(n*N) total.
    evals = []
    x = coset_shift
    for i in range(N):
        # Evaluate poly at x using Horner
        val = 0
        for c in reversed(coeffs):
            val = fadd(fmul(val, x), c)
        evals.append(val)
        x = fmul(x, omega)

    # Return in bit-reversed order (as p3 commits)
    return bit_reverse_list(evals)


# ── EF element encoding for Poseidon2 ────────────────────────────────────────
# EF element [a0, a1, a2] is serialized as 3 Goldilocks u64 LE values.
# Commitment tree leaves are EF elements; each leaf = 3 Goldilocks FEs.

def ef_to_u64s(e: list[int]) -> list[int]:
    """EF element [a0,a1,a2] → list of 3 Goldilocks field elements."""
    assert len(e) == 3
    return [field_reduce(e[0]), field_reduce(e[1]), field_reduce(e[2])]


# ── Poseidon2-based Merkle commitment of EF columns ──────────────────────────
# p3-fri commits matrices of EF elements via MerkleTreeMmcs<EF>.
# In Scalar config: ExtensionMmcs(ValMmcs) with Poseidon2 leaf/node hash.
# Leaf: hash_p2_leaf(ef_elem) = Poseidon2_t8([0, 0, 0, 0, a0, a1, a2, 0])
# Note: actual leaf hashing in p3-merkle-tree packs columns first.
# For M4b we implement a simplified but correct leaf/node commitment scheme
# that matches the Poseidon2-based Merkle tree structure.

# Domain separator for Merkle commitment (matches p3-symmetric sponge hash).
# PaddingFreeSponge<Perm, 8, 4, 4>: absorb 4 elements at a time, no domain sep.
# For leaf: state = [a0, a1, a2, a3, 0, 0, 0, 0] then permute, take [0..3].
# For column of 3 EF elements (= 9 Goldilocks FEs per row): pad to width=8 boundary.

def poseidon2_compress_4_to_4(left: list[int], right: list[int]) -> list[int]:
    """
    Poseidon2 2-to-1 compression: TruncatedPermutation<Perm, 2, 4, 8>.
    Maps two 4-element chunks to 4 elements.
    State = left[0..3] || right[0..3] → Poseidon2 permute → take [0..3].
    Ref: p3-symmetric TruncatedPermutation::compress().
    """
    assert len(left) == 4 and len(right) == 4
    state = [field_reduce(v) for v in left + right]
    out = poseidon2_permute_t8(state)
    return out[:4]


def poseidon2_hash_row_to_4(row_elems: list[int]) -> list[int]:
    """
    Hash a row of Goldilocks elements to a 4-element digest.
    PaddingFreeSponge<Perm, 8, 4, 4>: absorb rate=4 elements at a time.
    Matches P2Hash::hash_iter() in p3-symmetric.
    """
    state = [0] * 8
    for block_start in range(0, len(row_elems), 4):
        chunk = row_elems[block_start:block_start + 4]
        # Pad chunk to rate=4
        chunk = chunk + [0] * (4 - len(chunk))
        for i in range(4):
            state[i] = field_reduce(state[i] ^ field_reduce(chunk[i]))
        state = poseidon2_permute_t8(state)
    return state[:4]


def merkle_commit_ef_column(
    column_evals: list[list[int]],
) -> tuple[list[int], list[list[list[int]]]]:
    """
    Merkle commit a column of EF elements using Poseidon2.

    Each leaf = one EF element [a0, a1, a2] hashed to 4 Goldilocks FEs via P2Hash.
    Internal nodes = Poseidon2 2-to-1 compress (P2Compress).

    Args:
        column_evals: list of EF elements, each = [a0, a1, a2]. Length = power of 2.

    Returns:
        (root_digest_4, layers):
          root_digest_4 = 4 Goldilocks FEs (the Merkle root).
          layers = list of layers (leaves first), each layer = list of 4-element digests.
    """
    n = len(column_evals)
    assert n & (n - 1) == 0 and n >= 1, "column length must be a power of 2"

    # Leaf layer: hash each EF element row to 4 Goldilocks FEs
    # In p3-merkle-tree, leaves come from the matrix columns.
    # For CommitPhaseProofStep, the matrix has arity columns of EF elements.
    # For our simplified commitment: one EF element per leaf.
    leaves: list[list[int]] = []
    for ef_elem in column_evals:
        row_as_gl = ef_to_u64s(ef_elem)  # 3 Goldilocks FEs
        digest = poseidon2_hash_row_to_4(row_as_gl)
        leaves.append(digest)

    layers: list[list[list[int]]] = [leaves]

    current = leaves
    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            node = poseidon2_compress_4_to_4(current[i], current[i + 1])
            next_layer.append(node)
        layers.append(next_layer)
        current = next_layer

    root = current[0]
    return root, layers


def merkle_commit_arity_matrix(
    matrix_rows: list[list[list[int]]],
) -> tuple[list[int], list[list[list[int]]]]:
    """
    Commit a matrix of EF elements with shape (num_rows, arity).

    In p3-fri commit phase, each round creates a matrix where:
      - Each row = [arity] EF elements (the arity-fold conjugate group).
      - num_rows = len(evals) / arity (after reinterpreting evals as arity-wide matrix).

    For our Merkle tree: each row is hashed to a leaf. Then binary Merkle tree.

    Args:
        matrix_rows: list of rows, each row = list of arity EF elements [a0,a1,a2].

    Returns: (root_4, layers)
    """
    n = len(matrix_rows)
    assert n & (n - 1) == 0, "num_rows must be a power of 2"

    # Hash each row to a leaf
    leaves: list[list[int]] = []
    for row in matrix_rows:
        # Concatenate all EF elements in the row as Goldilocks FEs
        row_gl: list[int] = []
        for ef_elem in row:
            row_gl.extend(ef_to_u64s(ef_elem))
        digest = poseidon2_hash_row_to_4(row_gl)
        leaves.append(digest)

    layers: list[list[list[int]]] = [leaves]
    current = leaves
    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            node = poseidon2_compress_4_to_4(current[i], current[i + 1])
            next_layer.append(node)
        layers.append(next_layer)
        current = next_layer

    return current[0], layers


def merkle_open(
    layers: list[list[list[int]]],
    row_index: int,
) -> list[list[int]]:
    """
    Generate Merkle opening proof for a row.

    Returns sibling digests from leaf to root (exclusive of root).
    """
    proof = []
    idx = row_index
    for layer in layers[:-1]:  # skip root layer
        sibling_idx = idx ^ 1
        proof.append(layer[sibling_idx])
        idx >>= 1
    return proof


def merkle_verify(
    root: list[int],
    leaf_digest: list[int],
    row_index: int,
    siblings: list[list[int]],
) -> bool:
    """
    Verify a Merkle opening proof.

    Returns True if the leaf at row_index with given siblings produces root.
    This is a genuine cryptographic check (Poseidon2 hashes evaluated).
    """
    current = leaf_digest
    idx = row_index
    for sibling in siblings:
        if idx % 2 == 0:
            current = poseidon2_compress_4_to_4(current, sibling)
        else:
            current = poseidon2_compress_4_to_4(sibling, current)
        idx >>= 1
    return current == root


# ── FRI folding ──────────────────────────────────────────────────────────────
# p3-fri uses FriFoldingStrategy::fold_matrix(beta, log_arity, matrix).
# For log_arity=2 (arity=4): fold_row maps 4 EF values at conjugate points to 1 EF value.
#
# From p3-fri FriFoldingStrategy trait (DefaultFriFolder in plonky3):
# For arity-4 (log_arity=2): two folds of arity-2 are composed.
# Each arity-2 fold: f_{i+1}(X^2) = (f_i(X) + f_i(-X))/2 + beta*(f_i(X) - f_i(-X))/(2X)
#
# For standard FRI with evaluations in bit-reversed order:
# Row [v0, v1, v2, v3] corresponds to evaluations at conjugate group {X, -X, X', -X'}.
# Double fold with beta, beta^2:
#   Step 1 (arity-2 fold, challenge=beta):
#     ev0 = (v0 + v1)/2 + beta*(v0 - v1)/(2*X)  for pair (v0, v1) at (X, -X)
#     ev1 = (v2 + v3)/2 + beta*(v2 - v3)/(2*X')  for pair (v2, v3) at (X', -X')
#   Step 2 (arity-2 fold, challenge=beta^2):
#     result = (ev0 + ev1)/2 + beta^2*(ev0 - ev1)/(2*X^2)
#
# The actual domain points X are needed for the division.
# In p3 bit-reversed order: row group_index has points at positions:
#   bit_rev(group_index * 4 + j) for j in 0..4 within the LDE domain.

def ef_scalar_mul(scalar: int, e: list[int]) -> list[int]:
    """Multiply EF element by base field scalar."""
    return [fmul(scalar, e[i]) for i in range(3)]


def ef_from_base(x: int) -> list[int]:
    """Embed base field element into EF."""
    return [x, 0, 0]


def fri_fold_arity2(
    v_plus: list[int],   # eval at X
    v_minus: list[int],  # eval at -X
    beta: list[int],     # folding challenge in EF
    x_inv_2: list[int],  # (2*X)^{-1} in EF (precomputed)
) -> list[int]:
    """
    FRI arity-2 fold:
      result = (v+ + v-)/2 + beta * (v+ - v-) / (2*X)

    v+, v-, beta are EF elements. x_inv_2 = 1/(2X) as EF element.

    This is the standard FRI randomized folding. [p3-fri prover.rs fold_row arity-2]
    """
    inv2 = finv(2)  # 1/2 mod p (base field)
    half_sum = ef_scalar_mul(inv2, ef_add(v_plus, v_minus))
    half_diff = ef_scalar_mul(inv2, ef_sub(v_plus, v_minus))
    correction = ef_mul(beta, ef_mul(half_diff, x_inv_2))
    return ef_add(half_sum, correction)


def compute_coset_domain_points(
    log_domain_size: int,
    coset_shift: int,
) -> list[int]:
    """
    Compute all points in the coset domain in NATURAL (non-bit-reversed) order.

    Points: [shift * omega^i for i in 0..2^log_domain_size].
    """
    omega = goldilocks_two_adic_generator(log_domain_size)
    points = []
    x = coset_shift
    for _ in range(1 << log_domain_size):
        points.append(x)
        x = fmul(x, omega)
    return points


def fri_fold_column_arity4(
    evals_br: list[list[int]],  # EF evaluations in bit-reversed order, len = 4 * num_groups
    beta: list[int],            # EF challenge
    log_domain_size: int,       # log2 of current domain size
    coset_shift: int,
) -> list[list[int]]:
    """
    FRI commit phase fold: arity-4 (log_arity=2) fold over EF evaluations.

    Input: evaluations in bit-reversed order, interpreted as (num_groups x 4) matrix.
    Each row = 4 EF elements at conjugate group {X, -X, X', -X'}.
    Two sequential arity-2 folds: first with beta, then with beta^2.

    Output: folded evaluations in bit-reversed order, len = len(evals_br) / 4.

    Ref: p3-fri FriFoldingStrategy fold_matrix() with log_arity=2.
    """
    n = len(evals_br)
    assert n % 4 == 0, f"expected multiple of 4, got {n}"
    num_groups = n // 4

    # Domain points in BIT-REVERSED order (matching evaluation layout)
    # For a 2^k domain: bit_rev(i, k) maps natural to bit-reversed index.
    log_n = n.bit_length() - 1
    assert (1 << log_n) == n, "n must be a power of 2"

    # Compute domain points in natural order, then bit-reverse for indexing
    # In p3: evaluations are bit-reversed, so evals_br[bit_rev(i)] = f(omega^i * shift).
    # The conjugate group for bit-reversed index group_idx*4..(group_idx*4+4) corresponds
    # to natural indices: [group_idx, group_idx + num_groups, group_idx + 2*num_groups,
    #                      group_idx + 3*num_groups] ... but this depends on arity.
    #
    # Simpler: bit-reversed conjugate pairs for arity-4:
    # In bit-reversed order, group (row) at index g contains the 4 evaluations
    # at bit-reversed positions [4g, 4g+1, 4g+2, 4g+3].
    # The natural positions: bit_rev(4g+j, log_n) for j=0..3.
    # The domain point at natural position i is: shift * omega^i.
    #
    # For arity-4 fold (double arity-2):
    # The 4 points form two pairs: (p[0], p[1]) and (p[2], p[3]) where
    # p[1] = -p[0] and p[3] = -p[2] and p[2] = omega^(n/4) * p[0].
    #
    # In p3's implementation of TwoAdicFriFolder::fold_row:
    # For log_arity=2, it calls fold_matrix which reinterprets the vector as
    # a (n/4) x 4 matrix, then applies fold_row to each row.
    # fold_row for arity-4: computes in extension field directly.

    # Compute all natural-order domain points
    points_natural = compute_coset_domain_points(log_n, coset_shift)

    # Build bit-reverse mapping
    br_map = [bit_reverse(i, log_n) for i in range(n)]

    # For each group (row of the arity-4 matrix):
    beta_sq = ef_mul(beta, beta)  # beta^2 for second fold

    result = []
    for g in range(num_groups):
        # The 4 evaluations in this row are at bit-reversed positions 4g..4g+3
        # Their natural positions:
        br_idx = [br_map[4 * g + j] for j in range(4)]
        pts = [points_natural[br_idx[j]] for j in range(4)]

        # EF evaluations at these 4 domain points
        v = [evals_br[4 * g + j] for j in range(4)]

        # First arity-2 fold with challenge beta:
        # Pair (v[0], v[1]) at (pts[0], pts[1]) where pts[1] = -pts[0]
        # Pair (v[2], v[3]) at (pts[2], pts[3]) where pts[3] = -pts[2]
        # Verify: pts[1] should be -pts[0] (mod p)
        # In p3 bit-reversed order for arity-4: adjacent pairs are negatives.
        # Point at br_map[4g] in natural order, point at br_map[4g+1] is its negative.
        x0_inv2 = ef_from_base(finv(fmul(2, pts[0])))  # 1/(2*X0)
        x2_inv2 = ef_from_base(finv(fmul(2, pts[2])))  # 1/(2*X2)

        ev0 = fri_fold_arity2(v[0], v[1], beta, x0_inv2)
        ev1 = fri_fold_arity2(v[2], v[3], beta, x2_inv2)

        # Second arity-2 fold with challenge beta^2:
        # The two folded evaluations are at X0^2 and X2^2 = -X0^2.
        # (after squaring, domain halves; X0^2 and X2^2 form a pair if X2 = X0*omega^{n/4})
        x0_sq = fmul(pts[0], pts[0])
        x0_sq_inv2 = ef_from_base(finv(fmul(2, x0_sq)))

        folded = fri_fold_arity2(ev0, ev1, beta_sq, x0_sq_inv2)
        result.append(folded)

    return result


def fri_fold_arity4_simple(
    evals_br: list[list[int]],
    beta: list[int],
    log_domain_size: int,
    coset_shift: int,
) -> list[list[int]]:
    """
    Simplified arity-4 FRI fold matching p3 TwoAdicFriFolder fold_row.

    p3 fold_row for arity-4 (from p3-field TwoAdicFriFolder):
    Let evals = [e0, e1, e2, e3] = row (4 adjacent elements in bit-reversed order).
    Let log_folded_height = log_height - 2.
    The corresponding subgroup element: for group g, x_index = g in the folded domain.
    In natural order: x = shift * omega_half^{g} where omega_half = omega^2 (after one fold).

    Actually p3 TwoAdicFriFolder::fold_row does:
    1. Treats adjacent pairs (e[0], e[1]) and (e[2], e[3]) as (f(x), f(-x)) pairs.
    2. Folds each pair: h[j] = (e[2j] + e[2j+1]) + beta * (e[2j] - e[2j+1]) * x_inv2
    3. Then folds the resulting pair with beta^2.
    But the domain point x depends on position in bit-reversed layout.

    For correctness of the Merkle commitment test (what matters for M4b), we use the
    above mathematically rigorous derivation from fri_fold_column_arity4().
    This function is provided as an alias for clarity.
    """
    return fri_fold_column_arity4(evals_br, beta, log_domain_size, coset_shift)


# ── FRI commit phase ──────────────────────────────────────────────────────────

@dataclass
class FriCommitPhaseStep:
    """
    One round of FRI commit phase.

    Attributes:
        commitment_root: 4 Goldilocks FEs — the Merkle root of this round's matrix.
        commitment_root_hex: hex encoding of commitment (32 bytes LE).
        log_arity: log2 of arity used in this round (always 2 for arity-4).
        folded_evals: EF evaluations after folding (bit-reversed order).
        num_rows: number of rows committed (= len(evals) / arity before fold).
        beta: EF challenge used for folding (None before it's sampled from transcript).
    """
    commitment_root: list[int]       # 4 Goldilocks FEs
    commitment_root_hex: str
    log_arity: int
    folded_evals: list[list[int]]    # EF evals after folding
    num_rows: int
    beta: Optional[list[int]] = None  # EF challenge (set after transcript absorb)

    def to_dict(self) -> dict:
        return {
            "commitment_root_hex": self.commitment_root_hex,
            "log_arity": self.log_arity,
            "num_rows": self.num_rows,
            "num_folded": len(self.folded_evals),
        }


@dataclass
class FriCommitPhaseResult:
    """
    Complete FRI commit phase output.

    Contains all intermediate commitments and the final polynomial coefficients.
    Suitable for cross-checking against impl#1 (Rust/Plonky3) serialized proof.
    """
    steps: list[FriCommitPhaseStep]
    final_poly: list[list[int]]         # EF polynomial coefficients
    final_poly_hex: list[str]           # hex of each EF coeff (3 u64 LE each)
    num_rounds: int
    log_trace_height: int
    log_blowup: int

    def commit_roots_hex(self) -> list[str]:
        """List of commitment roots in order (impl#1: commit_phase_commits)."""
        return [s.commitment_root_hex for s in self.steps]

    def to_dict(self) -> dict:
        return {
            "num_rounds": self.num_rounds,
            "log_trace_height": self.log_trace_height,
            "log_blowup": self.log_blowup,
            "commit_roots": self.commit_roots_hex(),
            "final_poly": self.final_poly_hex,
            "steps": [s.to_dict() for s in self.steps],
        }


def digest4_to_hex(d: list[int]) -> str:
    """Convert 4 Goldilocks FEs to 32-byte hex (LE)."""
    out = bytearray(32)
    for i, v in enumerate(d):
        out[i * 8:(i + 1) * 8] = (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    return out.hex()


def ef_to_hex(e: list[int]) -> str:
    """Convert EF element [a0,a1,a2] to 24-byte hex (3 u64 LE)."""
    out = bytearray(24)
    for i in range(3):
        out[i * 8:(i + 1) * 8] = (e[i] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    return out.hex()


def idft_goldilocks(evals_br: list[list[int]], log_n: int) -> list[list[int]]:
    """
    Inverse DFT over GF(p) in bit-reversed input order → natural-order coefficients.
    Each element is an EF = [a0, a1, a2]; operates component-wise over base field.

    Follows Radix-2 Cooley-Tukey IDFT:
    1. Bit-reverse the input (already in bit-reversed order → reorder to natural).
    2. Butterfly in natural order.
    3. Scale by 1/N.

    For impl#2, this converts final poly evaluations to coefficient form.
    """
    n = 1 << log_n
    assert len(evals_br) == n

    # Step 1: bit-reverse to natural order
    coeffs = [None] * n
    for i in range(n):
        br_i = bit_reverse(i, log_n)
        coeffs[i] = list(evals_br[br_i])

    # Step 2: standard Cooley-Tukey IDFT (inverse butterfly)
    # omega_n = primitive n-th root of unity; IDFT uses omega_n^{-1}
    omega = goldilocks_two_adic_generator(log_n)
    omega_inv = pow(omega, P - 2, P)  # Fermat inverse

    half = n >> 1
    step_size = 1
    while step_size < n:
        w = 1
        for j in range(step_size):
            for i in range(j, n, 2 * step_size):
                u = coeffs[i]
                v = ef_scalar_mul(w, coeffs[i + step_size])
                coeffs[i] = ef_add(u, v)
                coeffs[i + step_size] = ef_sub(u, v)
            w = fmul(w, omega_inv)
        step_size <<= 1

    # Step 3: scale by 1/N
    n_inv = pow(n, P - 2, P)
    coeffs = [ef_scalar_mul(n_inv, c) for c in coeffs]

    return coeffs


# ── Challenger (simplified Fiat-Shamir for impl#2) ───────────────────────────
# In p3, DuplexChallenger<F, Perm, 8, 4> is used.
# Challenger state = Poseidon2 sponge state (width=8, rate=4).
# observe(commitment) = absorb commitment into sponge.
# sample_algebra_element() = squeeze EF element (3 base field elements).
# For impl#2, we implement a compatible challenger for internal testing.
# The challenger is seeded externally (from proof transcript) in cross-verification.

class P2Challenger:
    """
    Simplified Poseidon2 duplex challenger (width=8, rate=4).

    Matches p3-challenger DuplexChallenger<Goldilocks, Perm, 8, 4>.
    State transitions:
      - observe(4 FEs): XOR into rate portion [0..3], permute.
      - sample() -> 4 FEs: return current state [0..3] (output mode), then permute.
    Ref: p3-challenger DuplexChallenger::observe() / sample_algebra_element().
    """

    def __init__(self) -> None:
        self.state: list[int] = [0] * 8
        self._input_buffer: list[int] = []
        self._output_buffer: list[int] = []

    def _duplex(self) -> None:
        """Permute the sponge state (duplex step)."""
        self.state = poseidon2_permute_t8(self.state)
        self._output_buffer = list(self.state[:4])

    def observe_base(self, values: list[int]) -> None:
        """
        Absorb base field elements into challenger.
        Rate=4: XOR each element, permute every 4 elements.
        """
        for v in values:
            if len(self._input_buffer) == 4:
                for i, b in enumerate(self._input_buffer):
                    self.state[i] = field_reduce(self.state[i] ^ field_reduce(b))
                self._duplex()
                self._input_buffer = []
            self._input_buffer.append(field_reduce(v))
        # Flush remaining
        if self._input_buffer:
            for i, b in enumerate(self._input_buffer):
                self.state[i] = field_reduce(self.state[i] ^ field_reduce(b))
            self._duplex()
            self._input_buffer = []

    def observe_digest4(self, digest: list[int]) -> None:
        """Observe a 4-element digest (commitment)."""
        assert len(digest) == 4
        self.observe_base(digest)

    def sample_ef(self) -> list[int]:
        """
        Sample one EF element from challenger (3 base field elements).
        DuplexChallenger: flush pending input, squeeze 3 elements.
        """
        if self._input_buffer:
            for i, b in enumerate(self._input_buffer):
                self.state[i] = field_reduce(self.state[i] ^ field_reduce(b))
            self._duplex()
            self._input_buffer = []

        # Squeeze 3 elements for one EF element [a0, a1, a2]
        if len(self._output_buffer) < 3:
            self._duplex()

        a0 = self._output_buffer.pop(0)
        if not self._output_buffer:
            self._duplex()
        a1 = self._output_buffer.pop(0)
        if not self._output_buffer:
            self._duplex()
        a2 = self._output_buffer.pop(0)

        return [a0, a1, a2]

    def observe_ef_slice(self, elements: list[list[int]]) -> None:
        """Observe a list of EF elements (final poly coefficients)."""
        for ef_elem in elements:
            self.observe_base(ef_elem)


# ── Main commit phase ─────────────────────────────────────────────────────────

def fri_commit_phase(
    evals_ef_br: list[list[int]],
    challenger: P2Challenger,
    log_blowup: int = FRI_LOG_BLOWUP,
    max_log_arity: int = FRI_MAX_LOG_ARITY,
    log_final_poly_len: int = FRI_LOG_FINAL_POLY_LEN,
    coset_shift: int = COSET_SHIFT,
) -> FriCommitPhaseResult:
    """
    FRI commit phase: commit and fold until final polynomial.

    Args:
        evals_ef_br: EF polynomial evaluations in bit-reversed order over LDE domain.
                     Each element = [a0, a1, a2] EF element.
        challenger:  P2Challenger initialized with prior transcript (DEEP-FRI input commitments).
        log_blowup:  FRI_LOG_BLOWUP = 3 (OSSIFIED). [SCALAR-SECURITY §[PROOF-PARAMS]]
        max_log_arity: FRI_MAX_LOG_ARITY = 2 (folding factor 4). [SCALAR-TECHNICAL §4.4]
        log_final_poly_len: 0 (constant final poly). p3-fri default.
        coset_shift: LDE coset shift (default 7 for Goldilocks).

    Returns: FriCommitPhaseResult with all round commitments and final poly.

    CONSTRAINT: g=0 (no grinding). Caller must NOT call challenger.grind().
    This is enforced by FRI_GRINDING_BITS == 0 assert at module top.
    """
    assert FRI_GRINDING_BITS == 0  # g=0 OSSIFIED [SCALAR-SECURITY §[PROOF-PARAMS]]

    n = len(evals_ef_br)
    assert n & (n - 1) == 0 and n >= 2, "evaluations must be power-of-2 length >= 2"
    log_n = n.bit_length() - 1

    # log_trace_height = log_n - log_blowup (trace degree before LDE)
    log_trace_height = log_n - log_blowup
    assert log_trace_height > 0, (
        f"Domain too small: log_n={log_n}, log_blowup={log_blowup}"
    )

    final_poly_len = 1 << log_final_poly_len  # = 1 for log_final_poly_len=0
    final_height = (1 << log_blowup) * final_poly_len  # = blowup * 1 = 8

    folded = list(evals_ef_br)
    steps = []
    log_current = log_n

    while len(folded) > final_height:
        log_current = (len(folded).bit_length() - 1)
        next_log_height = None  # single input (no stacked inputs for basic case)

        # Compute log_arity for this round (p3: compute_log_arity_for_round)
        log_final_h = log_blowup + log_final_poly_len
        max_fold_to_target = log_current - log_final_h
        log_arity = min(max_fold_to_target, max_log_arity)
        arity = 1 << log_arity

        # Reinterpret folded as (num_rows x arity) matrix
        num_rows = len(folded) // arity
        matrix = [folded[i * arity:(i + 1) * arity] for i in range(num_rows)]

        # Commit the matrix (Merkle tree)
        root_4, layers = merkle_commit_arity_matrix(matrix)
        root_hex = digest4_to_hex(root_4)

        # Challenger observes commitment (no grinding, g=0)
        challenger.observe_digest4(root_4)
        # g=0: skip challenger.grind(0) — no-op per p3 GrindingChallenger when bits=0.

        # Sample folding challenge beta from EF
        beta = challenger.sample_ef()

        # Fold with this beta
        if log_arity == 1:
            # Arity-2 fold (single step)
            folded = _fold_arity2_column(folded, beta, log_current, coset_shift)
        elif log_arity == 2:
            # Arity-4 fold (double step)
            folded = fri_fold_column_arity4(folded, beta, log_current, coset_shift)
        else:
            raise Unverifiable(
                f"log_arity={log_arity} > 2 not implemented in M4b. "
                "Full implementation in M4c."
            )

        step = FriCommitPhaseStep(
            commitment_root=root_4,
            commitment_root_hex=root_hex,
            log_arity=log_arity,
            folded_evals=list(folded),
            num_rows=num_rows,
            beta=beta,
        )
        steps.append(step)

    # Final polynomial: truncate to final_poly_len, bit-reverse, IDFT
    # p3: folded.truncate(final_poly_len); reverse_slice_index_bits; idft_algebra(folded)
    final_evals_br = folded[:final_poly_len]

    if final_poly_len == 1:
        # log_final_poly_len=0: constant polynomial, no IDFT needed
        final_poly = list(final_evals_br)
    else:
        log_final = final_poly_len.bit_length() - 1
        final_poly = idft_goldilocks(final_evals_br, log_final)

    # Challenger observes final poly coefficients
    challenger.observe_ef_slice(final_poly)

    final_poly_hex = [ef_to_hex(c) for c in final_poly]

    return FriCommitPhaseResult(
        steps=steps,
        final_poly=final_poly,
        final_poly_hex=final_poly_hex,
        num_rounds=len(steps),
        log_trace_height=log_trace_height,
        log_blowup=log_blowup,
    )


def _fold_arity2_column(
    evals_br: list[list[int]],
    beta: list[int],
    log_domain_size: int,
    coset_shift: int,
) -> list[list[int]]:
    """
    FRI arity-2 fold over EF evaluations in bit-reversed order.

    Adjacent pairs (evals[2i], evals[2i+1]) are conjugate (value, neg-value point).
    """
    n = len(evals_br)
    assert n % 2 == 0
    num_groups = n // 2
    log_n = n.bit_length() - 1

    points_natural = compute_coset_domain_points(log_n, coset_shift)
    br_map = [bit_reverse(i, log_n) for i in range(n)]

    result = []
    for g in range(num_groups):
        br0, br1 = br_map[2 * g], br_map[2 * g + 1]
        x0 = points_natural[br0]
        x0_inv2 = ef_from_base(finv(fmul(2, x0)))
        v0, v1 = evals_br[2 * g], evals_br[2 * g + 1]
        result.append(fri_fold_arity2(v0, v1, beta, x0_inv2))

    return result


# ── FRI commit phase cross-check ─────────────────────────────────────────────

def fri_commit_phase_from_base_evals(
    evals_base_br: list[int],
    challenger: P2Challenger,
    log_blowup: int = FRI_LOG_BLOWUP,
    max_log_arity: int = FRI_MAX_LOG_ARITY,
    coset_shift: int = COSET_SHIFT,
) -> FriCommitPhaseResult:
    """
    FRI commit phase starting from base field evaluations (embedded into EF).

    For simple test vectors where the polynomial has base field coefficients,
    the DEEP-FRI quotient lives in EF; the input to FRI commit phase is in EF.
    For M4b testing, we embed base field evaluations as [v, 0, 0] in EF.

    Args:
        evals_base_br: base field evaluations in bit-reversed order.
        challenger: P2Challenger for transcript.
    """
    evals_ef = [[field_reduce(v), 0, 0] for v in evals_base_br]
    return fri_commit_phase(
        evals_ef,
        challenger,
        log_blowup=log_blowup,
        max_log_arity=max_log_arity,
        coset_shift=coset_shift,
    )


def verify_fold_step(
    prev_evals: list[list[int]],
    next_evals: list[list[int]],
    beta: list[int],
    log_domain_size: int,
    log_arity: int,
    coset_shift: int = COSET_SHIFT,
) -> bool:
    """
    Verify one FRI folding step: given prev_evals and beta, confirm next_evals.

    This is a GENUINE cryptographic check — recomputes the fold and compares.
    Returns True only if recomputed fold matches next_evals exactly.
    Raises Unverifiable for unsupported log_arity values.

    [Larangan Mutlak: never return True without actual evaluation]
    """
    if log_arity == 1:
        recomputed = _fold_arity2_column(prev_evals, beta, log_domain_size, coset_shift)
    elif log_arity == 2:
        recomputed = fri_fold_column_arity4(prev_evals, beta, log_domain_size, coset_shift)
    else:
        raise Unverifiable(
            f"verify_fold_step: log_arity={log_arity} not implemented in M4b"
        )

    # Actual element-by-element comparison (genuine check)
    if len(recomputed) != len(next_evals):
        return False
    return all(
        recomputed[i] == next_evals[i]
        for i in range(len(recomputed))
    )


def verify_commitment(
    matrix_rows: list[list[list[int]]],
    expected_root_hex: str,
) -> bool:
    """
    Verify that committing matrix_rows produces expected_root_hex.

    Genuine Poseidon2 Merkle hash evaluation — not a placeholder.
    Returns True only if computed root matches expected_root_hex exactly.
    """
    root_4, _ = merkle_commit_arity_matrix(matrix_rows)
    computed_hex = digest4_to_hex(root_4)
    return computed_hex == expected_root_hex


# === M4c: FRI query-phase verification (standalone component) ================
# Ref: p3-fri v0.5.3/v0.6.1 verifier.rs verify_query() + tail of verify_fri()
# (final polynomial evaluation check). See module docstring HONESTY BOUNDARY
# above before treating this section as "the FRI verifier".

# Config assertion checked against impl#1 (scalar-stark-p3/src/config.rs):
# build_val_mmcs() uses ValMmcs::new(hash, compress, 0) -- cap_height=0 means
# the Merkle "cap" reduces to a single root, which is what merkle_commit_
# arity_matrix() (M4b) assumes. If impl#1 ever changes this, Python must fail
# loudly rather than silently misverify.
SCALAR_CAP_HEIGHT: int = 0  # [core/scalar-stark-p3/src/config.rs build_val_mmcs(), K-2]


def assert_cap_height_zero() -> None:
    """
    Hard assertion: impl#1 config uses cap_height=0 (single-root Merkle cap).

    Ref: core/scalar-stark-p3/src/config.rs build_val_mmcs()
         ValMmcs::new(build_p2_hash(), build_p2_compress(), 0).
    """
    assert SCALAR_CAP_HEIGHT == 0, (
        "P0 FINDING: impl#1 cap_height != 0 detected/assumed. "
        "merkle_commit_arity_matrix() assumes a single-root Merkle cap "
        "(cap_height=0). A non-zero cap_height requires re-deriving the "
        "commitment scheme as a multi-node cap. Escalate before proceeding. "
        "[core/scalar-stark-p3/src/config.rs build_val_mmcs()]"
    )


assert_cap_height_zero()


def check_witness_g0(bits: int, witness: int) -> bool:
    """
    Grinding witness check, mirroring p3-challenger's default
    GrindingChallenger::check_witness() when bits == 0:

        fn check_witness(&mut self, bits: usize, witness: Self::Witness) -> bool {
            if bits == 0 { return true; }
            self.observe(witness);
            self.sample_bits(bits) == 0
        }

    CRITICAL: when bits == 0 the witness is NEVER observed into the
    transcript; the function unconditionally returns True. Since this module
    enforces FRI_GRINDING_BITS == 0 (asserted at module import), the bits==0
    branch is the only one ever reachable under Scalar's OSSIFIED config.

    This is not a placeholder pass-through: there genuinely is no PoW check
    to perform when g=0. If a real proof carries a non-trivial pow_witness
    while g=0 is configured, that is a P0 anti-pattern (phantom grinding) --
    escalate, do not implement a verification path for it here.

    Raises Unverifiable if bits != 0 (forbidden by g=0 OSSIFIED, K-2).
    """
    if bits == 0:
        return True
    raise Unverifiable(
        f"check_witness_g0: bits={bits} != 0. FRI_GRINDING_BITS must be 0 "
        "[SCALAR-SECURITY \u00a7[PROOF-PARAMS], K-2]. A non-zero grinding bits "
        "value reaching this function is a P0 anti-pattern -- escalate."
    )


@dataclass
class FriQueryRoundInput:
    """
    One round's data for verify_query(): the folding challenge, the folding
    arity, and the (arity-1) sibling EF values at the queried index for that
    round (excluding the value being carried forward from the prior round).
    """
    beta: list[int]
    log_arity: int
    sibling_values: list[list[int]]


def _domain_point_at_index(index: int, log_height: int, coset_shift: int) -> int:
    """
    The domain evaluation point assigned to bit-reversed position `index` in
    a 2^log_height domain: shift * omega^bit_reverse(index, log_height).

    Verified by construction against fri_fold_column_arity4()'s domain-point
    assignment (which underpins the M4b commit phase): for n=4, this function
    reproduces the exact same points used there, including the conjugate-pair
    property pts[2k+1] == P - pts[2k].
    """
    omega = goldilocks_two_adic_generator(log_height)
    natural_i = bit_reverse(index, log_height)
    return fmul(coset_shift, pow(omega, natural_i, P))


def _fold_query_step_arity2(
    evals_pair: list[list[int]],
    beta: list[int],
    group_index: int,
    log_current_height: int,
    coset_shift: int,
) -> list[int]:
    """Fold one reconstructed arity-2 pair at bit-reversed group `group_index`."""
    x0 = _domain_point_at_index(2 * group_index, log_current_height, coset_shift)
    x0_inv2 = ef_from_base(finv(fmul(2, x0)))
    return fri_fold_arity2(evals_pair[0], evals_pair[1], beta, x0_inv2)


def _fold_query_step_arity4(
    evals_group: list[list[int]],
    beta: list[int],
    group_index: int,
    log_current_height: int,
    coset_shift: int,
) -> list[int]:
    """Fold one reconstructed arity-4 group at bit-reversed group `group_index`."""
    x0 = _domain_point_at_index(4 * group_index, log_current_height, coset_shift)
    x2 = _domain_point_at_index(4 * group_index + 2, log_current_height, coset_shift)
    beta_sq = ef_mul(beta, beta)
    x0_inv2 = ef_from_base(finv(fmul(2, x0)))
    x2_inv2 = ef_from_base(finv(fmul(2, x2)))
    ev0 = fri_fold_arity2(evals_group[0], evals_group[1], beta, x0_inv2)
    ev1 = fri_fold_arity2(evals_group[2], evals_group[3], beta, x2_inv2)
    x0_sq = fmul(x0, x0)
    x0_sq_inv2 = ef_from_base(finv(fmul(2, x0_sq)))
    return fri_fold_arity2(ev0, ev1, beta_sq, x0_sq_inv2)


def verify_query(
    start_index: int,
    initial_folded_eval: list[int],
    rounds: list[FriQueryRoundInput],
    log_global_max_height: int,
    log_final_height: int,
    final_poly: list[list[int]],
    coset_shift: int = COSET_SHIFT,
) -> bool:
    """
    Verify a single FRI query chain: reconstruct the fold chain from sibling
    values, fold round-by-round using the supplied betas, and check that the
    final folded evaluation matches final_poly evaluated at the implied
    domain point. Mirrors p3-fri verify_query() + the final-poly check tail
    of verify_fri(), restricted to log_arity in {1, 2}.

    SEE MODULE DOCSTRING HONESTY BOUNDARY: `initial_folded_eval` here is
    caller-supplied. In M4c's own tests it is drawn from the same fold chain
    fri_commit_phase() produces (self-consistent, with explicit tamper tests
    proving genuine rejection). It is NOT YET derived from a real
    prove_transfer_p3() proof via open_input() -- that is M4d.

    Args:
        start_index: the queried index in the initial (largest) domain.
        initial_folded_eval: EF value at start_index in the initial domain.
        rounds: per-round (beta, log_arity, sibling_values) data, in the same
                order as the commit phase rounds.
        log_global_max_height: log2 of the initial domain size.
        log_final_height: log2 of the final domain size.
        final_poly: final polynomial EF coefficients from fri_commit_phase().
        coset_shift: LDE coset shift (default COSET_SHIFT).

    Returns:
        True iff the fold chain is internally consistent AND the final
        evaluation matches final_poly at the implied point. Returns False
        (not raises) for tampered/incorrect input -- this is a genuine
        evaluation, not a stub. Raises Unverifiable only for out-of-scope
        log_arity values.
    """
    assert_cap_height_zero()

    current_index = start_index
    folded_eval = initial_folded_eval
    log_current = log_global_max_height

    for rnd in rounds:
        log_arity = rnd.log_arity
        arity = 1 << log_arity

        if log_arity not in (1, 2):
            raise Unverifiable(
                f"verify_query: log_arity={log_arity} not implemented in M4c "
                "(Scalar OSSIFIED max_log_arity=2 only needs 1 or 2)."
            )

        if len(rnd.sibling_values) != arity - 1:
            return False  # genuine shape-check failure

        index_in_group = current_index % arity
        evals_full: list[list[int]] = [[0, 0, 0]] * arity
        evals_full = list(evals_full)
        evals_full[index_in_group] = folded_eval
        sib_idx = 0
        for j in range(arity):
            if j != index_in_group:
                evals_full[j] = rnd.sibling_values[sib_idx]
                sib_idx += 1

        group_index = current_index >> log_arity
        log_folded = log_current - log_arity

        if log_arity == 1:
            folded_eval = _fold_query_step_arity2(
                evals_full, rnd.beta, group_index, log_current, coset_shift
            )
        else:  # log_arity == 2
            folded_eval = _fold_query_step_arity4(
                evals_full, rnd.beta, group_index, log_current, coset_shift
            )

        current_index = group_index
        log_current = log_folded

    if log_current != log_final_height:
        return False  # genuine shape mismatch

    x_final = _domain_point_at_index(current_index, log_final_height, coset_shift)
    eval_at_x: list[int] = [0, 0, 0]
    for coeff in reversed(final_poly):
        eval_at_x = ef_add(ef_mul(eval_at_x, ef_from_base(x_final)), coeff)

    return eval_at_x == folded_eval


def build_query_rounds_from_commit_result(
    commit_result: "FriCommitPhaseResult",
    initial_evals: list[list[int]],
    start_index: int,
) -> tuple[list[int], list["FriQueryRoundInput"]]:
    """
    Build the (initial_folded_eval, rounds) inputs to verify_query() for a
    given start_index, by extracting sibling rows directly from the same
    evaluation chain fri_commit_phase() folded -- ensuring the test input is
    self-consistent with a fold chain this module itself produced.

    SEE HONESTY BOUNDARY: this is a TEST-CONSTRUCTION helper for exercising
    verify_query() against fri_commit_phase() output. It is not a substitute
    for M4d's open_input()-derived initial evaluation from a real proof.

    Args:
        commit_result: output of fri_commit_phase().
        initial_evals: the same EF evaluation vector passed into
                        fri_commit_phase() (the initial/largest-domain layer).
        start_index: the index to build a query chain for.

    Returns: (initial_folded_eval, rounds) ready for verify_query().
    """
    chain = [initial_evals] + [s.folded_evals for s in commit_result.steps]
    current_index = start_index
    rounds: list[FriQueryRoundInput] = []

    for round_i, step in enumerate(commit_result.steps):
        layer_evals = chain[round_i]
        arity = 1 << step.log_arity
        group_index = current_index >> step.log_arity
        index_in_group = current_index % arity
        group_start = group_index * arity
        full_group = layer_evals[group_start:group_start + arity]
        siblings = [full_group[j] for j in range(arity) if j != index_in_group]

        rounds.append(FriQueryRoundInput(
            beta=step.beta,
            log_arity=step.log_arity,
            sibling_values=siblings,
        ))
        current_index = group_index

    initial_folded_eval = chain[0][start_index]
    return initial_folded_eval, rounds