"""
Milestone-3: PI constraint checker cross-check — impl#2 (Python) vs impl#1 (Rust).
[SCALAR-SECURITY §5.3 Tier 2]
"""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from scalar_verifier.constraints import check_all_constraints

def load():
    path = os.path.join(os.path.dirname(__file__), 'vectors', 'pi_constraint_vectors.json')
    with open(path) as f:
        return json.load(f)['vectors']

def run():
    passed = failed = 0
    for v in load():
        if v['primitive'] != 'pi_check_all_constraints':
            continue
        note = v['note']
        pi = v['pi']
        exp_valid = v['expected_valid']
        exp_fail_idx = v.get('fail_constraint_idx')

        got_valid, got_fail_idx = check_all_constraints(pi)

        # Check valid/invalid matches
        ok_valid = got_valid == exp_valid
        # Check fail index matches (both None or both same int)
        ok_idx = got_fail_idx == exp_fail_idx

        if ok_valid and ok_idx:
            print(f"  PASS [{note}]")
            passed += 1
        else:
            print(f"  FAIL [{note}]")
            if not ok_valid:
                print(f"    valid: expected={exp_valid} got={got_valid}")
            if not ok_idx:
                print(f"    fail_idx: expected={exp_fail_idx} got={got_fail_idx}")
            failed += 1

    print(f"\nResult: {passed} passed, {failed} failed / {passed+failed} total")
    return failed == 0

if __name__ == '__main__':
    print("=== Milestone-3: PI constraint checker cross-check ===")
    ok = run()
    sys.exit(0 if ok else 1)
