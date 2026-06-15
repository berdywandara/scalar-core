"""
Milestone-4a: GF(p^3) arithmetic cross-check — impl#2 (Python) vs impl#1 (Rust).
[SCALAR-SECURITY §5.3 Tier 2]
"""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from scalar_verifier.gfp3 import ef_add, ef_mul, ef_inv, ef_frobenius
from scalar_verifier.proof_params import GOLDILOCKS_P as P

def load():
    path = os.path.join(os.path.dirname(__file__), 'vectors', 'ef_vectors.json')
    with open(path) as f:
        return json.load(f)['vectors']

def run():
    passed = failed = 0
    for v in load():
        prim = v['primitive']
        note = v.get('note', '')
        try:
            if prim == 'ef_mul':
                got = ef_mul(v['a'], v['b'])
                exp = v['result']
            elif prim == 'ef_add':
                got = ef_add(v['a'], v['b'])
                exp = v['result']
            elif prim == 'ef_inv':
                got = ef_inv(v['a'])
                exp = v['result']
                # Extra: verify a * inv(a) == [1,0,0]
                prod = ef_mul(v['a'], got)
                if prod != [1, 0, 0]:
                    print(f"  FAIL [ef_inv verify] {note}: a*inv != [1,0,0], got {prod}")
                    failed += 1
                    continue
            elif prim == 'ef_frobenius':
                got = ef_frobenius(v['a'])
                exp = v['result']
            else:
                print(f"  SKIP [{prim}] {note}")
                continue

            if got == exp:
                print(f"  PASS [{prim}] {note}")
                passed += 1
            else:
                print(f"  FAIL [{prim}] {note}")
                print(f"    a={v['a']}")
                if 'b' in v: print(f"    b={v['b']}")
                print(f"    expected={exp}")
                print(f"    got     ={got}")
                for i in range(3):
                    if got[i] != exp[i]:
                        print(f"    diff at [{i}]: exp={exp[i]:#018x} got={got[i]:#018x}")
                        break
                failed += 1
        except Exception as e:
            print(f"  ERROR [{prim}] {note}: {e}")
            import traceback; traceback.print_exc()
            failed += 1

    # Extra self-consistency tests (no oracle needed)
    print("\n  --- Self-consistency tests ---")
    # a * a^{-1} == 1 for random-ish a
    for a in [[3,7,11],[1,0,0],[0,1,0],[0,0,1]]:
        inv_a = ef_inv(a)
        prod = ef_mul(a, inv_a)
        ok = prod == [1,0,0]
        print(f"  {'PASS' if ok else 'FAIL'} [self: a*inv==1] a={a}")
        if ok: passed += 1
        else: failed += 1

    # (a*b)*c == a*(b*c) associativity
    a,b,c = [1,2,3],[4,5,6],[7,8,9]
    lhs = ef_mul(ef_mul(a,b),c)
    rhs = ef_mul(a,ef_mul(b,c))
    ok = lhs == rhs
    print(f"  {'PASS' if ok else 'FAIL'} [self: associativity (a*b)*c==a*(b*c)]")
    if ok: passed += 1
    else: failed += 1

    # Frobenius: a^p == frobenius(a)
    a = [1,2,3]
    frob = ef_frobenius(a)
    a_pow_p = ef_pow_base(a, P)
    ok = frob == a_pow_p
    print(f"  {'PASS' if ok else 'FAIL'} [self: frobenius(a)==a^p]")
    if ok: passed += 1
    else: failed += 1

    print(f"\nResult: {passed} passed, {failed} failed / {passed+failed} total")
    return failed == 0

def ef_pow_base(a, n):
    """Compute a^n in GF(p^3) for self-test."""
    result = [1, 0, 0]
    base = list(a)
    while n > 0:
        if n & 1:
            result = ef_mul(result, base)
        base = ef_mul(base, base)
        n >>= 1
    return result

if __name__ == '__main__':
    print("=== Milestone-4a: GF(p^3) arithmetic cross-check ===")
    ok = run()
    sys.exit(0 if ok else 1)
