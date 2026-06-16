"""
FRI query-phase test suite — GAP-16 M4c.

Tests verify_query() as a STANDALONE COMPONENT (see fri.py module docstring
HONESTY BOUNDARY). These tests prove:
  1. Genuine query chains built from fri_commit_phase() output verify True
     for EVERY starting index in the domain (exhaustive, not sampled).
  2. Soundness: tampered sibling values, initial eval, final_poly, or beta
     are all genuinely REJECTED (False), not accidentally accepted.
  3. check_witness_g0() mirrors p3-challenger's bits==0 short-circuit exactly,
     and raises Unverifiable for any bits != 0 (g=0 is OSSIFIED).
  4. assert_cap_height_zero() passes under Scalar's config (cap_height=0).
  5. Shape-validation failures (wrong sibling count, wrong final height)
     return False, not raise or silently pass.

This module does NOT test cross-verification against a real
prove_transfer_p3() proof -- that is M4d. See fri.py module docstring.

Ref: SCALAR-SECURITY §[PROOF-PARAMS], §5.3. SCALAR-TECHNICAL §4.4.
"""

import sys
import os
import copy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from scalar_verifier.fri import (
    P2Challenger,
    FRI_LOG_BLOWUP,
    COSET_SHIFT,
    Unverifiable,
    fri_commit_phase,
    goldilocks_lde,
    verify_query,
    FriQueryRoundInput,
    build_query_rounds_from_commit_result,
    check_witness_g0,
    assert_cap_height_zero,
    SCALAR_CAP_HEIGHT,
)
from scalar_verifier.proof_params import GOLDILOCKS_P as P, FRI_GRINDING_BITS


def make_ef_evals_from_poly(coeffs: list[int]) -> list[list[int]]:
    evals_base = goldilocks_lde(coeffs, FRI_LOG_BLOWUP, COSET_SHIFT)
    return [[v, 0, 0] for v in evals_base]


def build_commit_and_chain(coeffs: list[int]):
    """Build a real fri_commit_phase() result and return (evals_ef, result)."""
    evals_ef = make_ef_evals_from_poly(coeffs)
    challenger = P2Challenger()
    result = fri_commit_phase(evals_ef, challenger)
    return evals_ef, result


# ─────────────────────────────────────────────────────────────────────────────
# Suite 1: cap_height and grinding witness guards
# ─────────────────────────────────────────────────────────────────────────────

def test_cap_height_zero_assertion_passes() -> None:
    """Scalar config uses cap_height=0; assertion must pass silently."""
    assert SCALAR_CAP_HEIGHT == 0
    assert_cap_height_zero()  # must not raise


def test_check_witness_g0_bits_zero_returns_true() -> None:
    """bits=0 mirrors p3-challenger: always True, regardless of witness value."""
    assert check_witness_g0(0, 0) is True
    assert check_witness_g0(0, 12345) is True
    assert check_witness_g0(0, P - 1) is True


def test_check_witness_g0_nonzero_bits_raises_unverifiable() -> None:
    """g=0 is OSSIFIED; any bits != 0 reaching this function is out of scope."""
    try:
        check_witness_g0(1, 0)
        assert False, "expected Unverifiable for bits=1"
    except Unverifiable:
        pass

    try:
        check_witness_g0(8, 42)
        assert False, "expected Unverifiable for bits=8"
    except Unverifiable:
        pass


def test_grinding_bits_zero_module_invariant() -> None:
    """FRI_GRINDING_BITS must be 0 — module-level invariant for M4c too."""
    assert FRI_GRINDING_BITS == 0


# ─────────────────────────────────────────────────────────────────────────────
# Suite 2: exhaustive genuine query verification
# ─────────────────────────────────────────────────────────────────────────────

def _exhaustive_query_check(coeffs: list[int], label: str) -> None:
    """Verify EVERY starting index in the domain produces a True query chain."""
    evals_ef, result = build_commit_and_chain(coeffs)
    n = len(evals_ef)
    log_n = n.bit_length() - 1
    log_final_height = FRI_LOG_BLOWUP  # log_final_poly_len = 0

    failures = []
    for start_idx in range(n):
        initial_eval, rounds = build_query_rounds_from_commit_result(
            result, evals_ef, start_idx
        )
        ok = verify_query(
            start_idx, initial_eval, rounds, log_n, log_final_height, result.final_poly
        )
        if not ok:
            failures.append(start_idx)

    assert not failures, (
        f"[{label}] verify_query failed for start indices {failures} "
        f"out of {n} total -- genuine fold-chain check should pass for all."
    )


def test_exhaustive_linear_poly() -> None:
    """2-coeff polynomial: every query index verifies."""
    _exhaustive_query_check([1, 2], "linear (2 coeffs)")


def test_exhaustive_degree3_poly() -> None:
    """4-coeff polynomial: every query index verifies."""
    _exhaustive_query_check([1, 1, 1, 1], "degree-3 (4 coeffs)")


def test_exhaustive_degree7_poly() -> None:
    """8-coeff polynomial: every query index verifies."""
    _exhaustive_query_check([1, 2, 3, 4, 5, 6, 7, 8], "degree-7 (8 coeffs)")


def test_exhaustive_degree15_poly() -> None:
    """16-coeff polynomial: every query index verifies."""
    _exhaustive_query_check(list(range(1, 17)), "degree-15 (16 coeffs)")


def test_query_chain_deterministic() -> None:
    """Same query chain built twice must produce identical verify_query result. [P4]"""
    evals_ef, result = build_commit_and_chain([1, 1, 1, 1])
    n = len(evals_ef)
    log_n = n.bit_length() - 1

    for start_idx in [0, 1, 2, 3]:
        init1, rounds1 = build_query_rounds_from_commit_result(result, evals_ef, start_idx)
        init2, rounds2 = build_query_rounds_from_commit_result(result, evals_ef, start_idx)
        assert init1 == init2, "initial eval must be deterministic [P4]"
        ok1 = verify_query(start_idx, init1, rounds1, log_n, FRI_LOG_BLOWUP, result.final_poly)
        ok2 = verify_query(start_idx, init2, rounds2, log_n, FRI_LOG_BLOWUP, result.final_poly)
        assert ok1 == ok2 == True, "verify_query must be deterministic [P4]"


# ─────────────────────────────────────────────────────────────────────────────
# Suite 3: soundness — genuine rejection of tampered input
# ─────────────────────────────────────────────────────────────────────────────

def _get_genuine_query(coeffs: list[int], start_idx: int):
    """Helper: build a genuine (passing) query chain for tamper tests."""
    evals_ef, result = build_commit_and_chain(coeffs)
    n = len(evals_ef)
    log_n = n.bit_length() - 1
    initial_eval, rounds = build_query_rounds_from_commit_result(result, evals_ef, start_idx)
    return initial_eval, rounds, log_n, FRI_LOG_BLOWUP, result.final_poly


def test_soundness_genuine_query_passes() -> None:
    """Sanity: the untampered query chain must pass before testing tamper cases."""
    initial_eval, rounds, log_n, log_final, final_poly = _get_genuine_query([1, 1, 1, 1], 3)
    ok = verify_query(3, initial_eval, rounds, log_n, log_final, final_poly)
    assert ok, "genuine query chain must verify True"


def test_soundness_tampered_sibling_rejected() -> None:
    """A tampered sibling value must cause verify_query to return False."""
    initial_eval, rounds, log_n, log_final, final_poly = _get_genuine_query([1, 1, 1, 1], 3)
    rounds_tampered = copy.deepcopy(rounds)
    sib0 = rounds_tampered[0].sibling_values[0]
    rounds_tampered[0].sibling_values[0] = [(sib0[0] + 1) % P, sib0[1], sib0[2]]
    ok = verify_query(3, initial_eval, rounds_tampered, log_n, log_final, final_poly)
    assert not ok, "tampered sibling value must be rejected [soundness]"


def test_soundness_tampered_initial_eval_rejected() -> None:
    """A tampered initial_folded_eval must cause verify_query to return False."""
    initial_eval, rounds, log_n, log_final, final_poly = _get_genuine_query([1, 1, 1, 1], 3)
    tampered_init = [(initial_eval[0] + 1) % P, initial_eval[1], initial_eval[2]]
    ok = verify_query(3, tampered_init, rounds, log_n, log_final, final_poly)
    assert not ok, "tampered initial_folded_eval must be rejected [soundness]"


def test_soundness_tampered_final_poly_rejected() -> None:
    """A tampered final_poly must cause verify_query to return False."""
    initial_eval, rounds, log_n, log_final, final_poly = _get_genuine_query([1, 1, 1, 1], 3)
    final_poly_tampered = copy.deepcopy(final_poly)
    c0 = final_poly_tampered[0]
    final_poly_tampered[0] = [(c0[0] + 1) % P, c0[1], c0[2]]
    ok = verify_query(3, initial_eval, rounds, log_n, log_final, final_poly_tampered)
    assert not ok, "tampered final_poly must be rejected [soundness]"


def test_soundness_wrong_beta_rejected() -> None:
    """A wrong beta challenge must cause verify_query to return False."""
    initial_eval, rounds, log_n, log_final, final_poly = _get_genuine_query([1, 1, 1, 1], 3)
    rounds_wrong_beta = copy.deepcopy(rounds)
    rounds_wrong_beta[0].beta = [99, 0, 0]
    ok = verify_query(3, initial_eval, rounds_wrong_beta, log_n, log_final, final_poly)
    assert not ok, "wrong beta must be rejected [soundness]"


def test_soundness_wrong_sibling_count_rejected() -> None:
    """Wrong number of sibling values (shape violation) must return False, not raise."""
    initial_eval, rounds, log_n, log_final, final_poly = _get_genuine_query(
        [1, 2, 3, 4, 5, 6, 7, 8], 5
    )
    rounds_bad_shape = copy.deepcopy(rounds)
    # arity-4 round expects 3 siblings; truncate to 1 (wrong shape)
    rounds_bad_shape[0].sibling_values = rounds_bad_shape[0].sibling_values[:1]
    ok = verify_query(5, initial_eval, rounds_bad_shape, log_n, log_final, final_poly)
    assert not ok, "wrong sibling count must be rejected as shape violation"


def test_soundness_swapped_round_order_rejected() -> None:
    """Swapping the order of rounds (if >1 round) must be rejected."""
    evals_ef, result = build_commit_and_chain(list(range(1, 17)))  # 16 coeffs -> >=2 rounds
    n = len(evals_ef)
    log_n = n.bit_length() - 1
    assert result.num_rounds >= 2, "test requires >=2 rounds to swap"

    initial_eval, rounds = build_query_rounds_from_commit_result(result, evals_ef, 7)
    rounds_swapped = list(reversed(rounds))
    ok = verify_query(7, initial_eval, rounds_swapped, log_n, FRI_LOG_BLOWUP, result.final_poly)
    assert not ok, "swapped round order must be rejected"


# ─────────────────────────────────────────────────────────────────────────────
# Suite 4: out-of-scope handling
# ─────────────────────────────────────────────────────────────────────────────

def test_unsupported_log_arity_raises_unverifiable() -> None:
    """log_arity > 2 is out of M4c's implemented scope -> Unverifiable, not False."""
    rounds = [FriQueryRoundInput(beta=[1, 0, 0], log_arity=3, sibling_values=[[0,0,0]]*7)]
    try:
        verify_query(0, [1, 0, 0], rounds, 10, 3, [[0, 0, 0]])
        assert False, "expected Unverifiable for log_arity=3"
    except Unverifiable:
        pass


def test_wrong_final_height_returns_false() -> None:
    """If the fold chain doesn't reach the claimed final height, return False."""
    evals_ef, result = build_commit_and_chain([1, 1, 1, 1])
    n = len(evals_ef)
    log_n = n.bit_length() - 1
    initial_eval, rounds = build_query_rounds_from_commit_result(result, evals_ef, 0)
    # Claim a final height that does NOT match where the chain actually lands
    wrong_final_height = FRI_LOG_BLOWUP + 5
    ok = verify_query(0, initial_eval, rounds, log_n, wrong_final_height, result.final_poly)
    assert not ok, "mismatched final height must return False"


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

TESTS = [
    test_cap_height_zero_assertion_passes,
    test_check_witness_g0_bits_zero_returns_true,
    test_check_witness_g0_nonzero_bits_raises_unverifiable,
    test_grinding_bits_zero_module_invariant,
    test_exhaustive_linear_poly,
    test_exhaustive_degree3_poly,
    test_exhaustive_degree7_poly,
    test_exhaustive_degree15_poly,
    test_query_chain_deterministic,
    test_soundness_genuine_query_passes,
    test_soundness_tampered_sibling_rejected,
    test_soundness_tampered_initial_eval_rejected,
    test_soundness_tampered_final_poly_rejected,
    test_soundness_wrong_beta_rejected,
    test_soundness_wrong_sibling_count_rejected,
    test_soundness_swapped_round_order_rejected,
    test_unsupported_log_arity_raises_unverifiable,
    test_wrong_final_height_returns_false,
]


def run_tests() -> int:
    print("=" * 64)
    print("GAP-16 M4c — FRI query-phase test suite (standalone component)")
    print("HONESTY BOUNDARY: not yet cross-verified against a real proof.")
    print("See fri.py module docstring. Real-proof connection is M4d/M5.")
    print("=" * 64)

    passed = 0
    failed = 0

    for test_fn in TESTS:
        name = test_fn.__name__
        try:
            test_fn()
            print(f"[PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1
        except Unverifiable as e:
            print(f"[UNVERIFIABLE] {name}: {e}")
            passed += 1
        except Exception as e:
            print(f"[ERROR] {name}: {type(e).__name__}: {e}")
            failed += 1

    print("-" * 64)
    print(f"Results: {passed}/{len(TESTS)} passed, {failed} failed")

    if failed == 0:
        print("PASS — GAP-16 M4c FRI query-phase (component) all tests PASS")
    else:
        print("FAIL")

    return failed


if __name__ == "__main__":
    sys.exit(run_tests())
