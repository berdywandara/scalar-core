"""
GF(p^3) = GF(p)[X]/(X^3 - X - 1) arithmetic — Python impl#2.

Modulus: X^3 - X - 1, i.e. X^3 = X + 1. OSSIFIED [SCALAR-SECURITY §[PROOF-PARAMS]].
Reduction rule: whenever X^3 appears, replace with X + 1.

Elements represented as [a0, a1, a2] = a0 + a1*X + a2*X^2.
Convention matches p3-field CubicTrinomialExtensionField:
  value[0] = a0 (constant), value[1] = a1 (X coeff), value[2] = a2 (X^2 coeff).

Does NOT import from scalar-stark-p3 or scalar_crypto. [SCALAR-SECURITY §5.3, P4]
Ref: p3-field v0.6.1 src/extension/cubic_extension.rs trinomial_cubic_mul().
     p3-goldilocks v0.6.1 src/extension.rs CubicTrinomialExtendable.
"""

from .proof_params import GOLDILOCKS_P as P

# ── Base field (Goldilocks) arithmetic ───────────────────────────────────────
def fadd(a: int, b: int) -> int: return (a + b) % P
def fsub(a: int, b: int) -> int: return (a - b) % P
def fmul(a: int, b: int) -> int: return (a * b) % P
def fneg(a: int) -> int: return (-a) % P
def finv(a: int) -> int:
    """Modular inverse via Fermat: a^(p-2) mod p."""
    if a == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(a, P - 2, P)

# ── GF(p^3) = GF(p)[X]/(X^3 - X - 1) ───────────────────────────────────────
# Elements: [a0, a1, a2] where element = a0 + a1*X + a2*X^2

def ef_add(a: list[int], b: list[int]) -> list[int]:
    """Component-wise addition in GF(p^3)."""
    return [fadd(a[i], b[i]) for i in range(3)]

def ef_sub(a: list[int], b: list[int]) -> list[int]:
    """Component-wise subtraction in GF(p^3)."""
    return [fsub(a[i], b[i]) for i in range(3)]

def ef_neg(a: list[int]) -> list[int]:
    """Negation in GF(p^3)."""
    return [fneg(x) for x in a]

def ef_mul(a: list[int], b: list[int]) -> list[int]:
    """
    Multiplication in GF(p^3) = GF(p)[X]/(X^3 - X - 1).

    Uses trinomial_cubic_mul formula from p3-field v0.6.1:
      Modulus: X^3 = X + 1 (reduction rule).
      res[0] = a0*b0 + a1*b2 + a2*b1
      res[1] = a0*b1 + a1*(b0+b2) + a2*(b1+b2)
      res[2] = a0*b2 + a1*b1 + a2*(b0+b2)

    Derivation: (a0+a1X+a2X^2)(b0+b1X+b2X^2) mod (X^3-X-1)
      = a0b0 + (a0b1+a1b0)X + (a0b2+a1b1+a2b0)X^2
        + (a1b2+a2b1)X^3 + (a2b2)X^4
      Reduce: X^3=X+1, X^4=X^2+X
        X^3 term: (a1b2+a2b1)(X+1) = (a1b2+a2b1) + (a1b2+a2b1)X
        X^4 term: a2b2(X^2+X) = a2b2*X^2 + a2b2*X
    [p3-field cubic_extension.rs trinomial_cubic_mul()]
    """
    a0, a1, a2 = a
    b0, b1, b2 = b
    b0pb2 = fadd(b0, b2)
    b1pb2 = fadd(b1, b2)
    r0 = fadd(fadd(fmul(a0, b0), fmul(a1, b2)), fmul(a2, b1))
    r1 = fadd(fadd(fmul(a0, b1), fmul(a1, b0pb2)), fmul(a2, b1pb2))
    r2 = fadd(fadd(fmul(a0, b2), fmul(a1, b1)), fmul(a2, b0pb2))
    return [r0, r1, r2]

def ef_inv(a: list[int]) -> list[int]:
    """
    Inverse in GF(p^3) using Frobenius automorphism.
    a^{-1} = ProdConj(a) * Norm(a)^{-1}
    where ProdConj(a) = a^{p+p^2} and Norm(a) = a * ProdConj(a) ∈ GF(p).
    [p3-field cubic_extension.rs HasFrobenius::pseudo_inv()]
    """
    if a == [0, 0, 0]:
        raise ZeroDivisionError("inverse of zero element")
    a_p  = ef_frobenius(a)           # a^p
    prod = ef_mul(a, a_p)            # a * a^p = a^{p+1}
    prod_conj = ef_frobenius(prod)   # (a^{p+1})^p = a^{p^2+p}
    # norm = a * prod_conj should be in base field (a2=a1=0)
    norm_ef = ef_mul(a, prod_conj)
    norm = norm_ef[0]  # base field element (norm_ef[1] and [2] should be ~0)
    norm_inv = finv(norm)
    return [fmul(prod_conj[i], norm_inv) for i in range(3)]

def ef_frobenius(a: list[int]) -> list[int]:
    """
    Frobenius automorphism: a -> a^p.
    Uses FROBENIUS_MATRIX from p3-goldilocks v0.6.1 CubicTrinomialExtendable.
    [p3-goldilocks src/extension.rs]
    """
    # FROBENIUS_MATRIX[row][col] from p3-goldilocks v0.6.1:
    M = [
        [1,                    10615703402128488253, 6700183068485440220],
        [0,                    10050274602728160328, 14531223735771536287],
        [0,                    11746561000929144102, 8396469466686423992],
    ]
    a0, a1, a2 = a
    c0 = fadd(fadd(fmul(M[0][0], a0), fmul(M[0][1], a1)), fmul(M[0][2], a2))
    c1 = fadd(fadd(fmul(M[1][0], a0), fmul(M[1][1], a1)), fmul(M[1][2], a2))
    c2 = fadd(fadd(fmul(M[2][0], a0), fmul(M[2][1], a1)), fmul(M[2][2], a2))
    return [c0, c1, c2]

def ef_pow(a: list[int], n: int) -> list[int]:
    """Power by repeated squaring."""
    if n == 0:
        return [1, 0, 0]
    result = [1, 0, 0]
    base = [x for x in a]
    while n > 0:
        if n & 1:
            result = ef_mul(result, base)
        base = ef_mul(base, base)
        n >>= 1
    return result
