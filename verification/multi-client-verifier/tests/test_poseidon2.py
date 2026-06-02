"""
Test vectors for Poseidon2 impl#2 — multi-client verification (MAD §15.3).

TV-1: OSSIFIED SCALAR-TECHNICAL §1.1 (CI gate in scalar-core)
TV-2: p3-goldilocks internal test (input [0..7])
TV-3..6: dump_rc_canonical.rs vectors from build_poseidon2_perm()
TV-7: p3-goldilocks internal test (input [1..8]) — from debug_ell
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from poseidon2 import poseidon2_permute, _apply_mat4, _external_mds_8

P = (1 << 64) - (1 << 32) + 1

TESTS = [
    # TV-1: OSSIFIED
    {"id": "TV-1 [0]*8 OSSIFIED",
     "input": [0]*8,
     "expected": [4904961330882102773, 6914533505831728251, 16060085509051262978,
                  161169382960502813, 8610401995229161121, 6947968519022847962,
                  9668808541865791489, 7055543217974479047]},
    # TV-2: p3-goldilocks test_default_goldilocks_poseidon2_width_8 [0..7]
    {"id": "TV-2 [0..7] p3-goldilocks",
     "input": [0,1,2,3,4,5,6,7],
     "expected": [0x020cf04a1b214d14,0x84e14aaaeacaed25,0x1ae0f640e81c7457,0xa4d204cbaeb0d8a5,
                  0x0cf637b627b3a7ff,0x788d304d948b486b,0x7327133ea1949af4,0xf415abb924da395b]},
    # TV-3..6: from dump_rc_canonical.rs (build_poseidon2_perm)
    {"id": "TV-3 [1,0,0,...,0]",
     "input": [1,0,0,0,0,0,0,0],
     "expected": [16231448827913418945,13580556839402552918,12346029782625336969,
                  6741913625119210497,13958835878204533235,9960643544227192043,
                  7967026258726722731,3359002280707353220]},
    {"id": "TV-4 [0,1,0,...,0]",
     "input": [0,1,0,0,0,0,0,0],
     "expected": [4582183166585288392,10002556425369572882,7842645509894997883,
                  4492944887968473356,5267036104049256697,9748689543000420289,
                  13288450556385172304,11225501811650087764]},
    {"id": "TV-5 [1,1,...,1]",
     "input": [1,1,1,1,1,1,1,1],
     "expected": [6468080781181127345,16367202205120260784,12214713415794497031,
                  12073078400405299643,127680313722865003,13716257572585366370,
                  4102962658555466810,10174564719208139770]},
    {"id": "TV-6 [100,200,...,800]",
     "input": [100,200,300,400,500,600,700,800],
     "expected": [8245328082886209093,16535849038554082506,17035232055457724023,
                  15656758379098614321,3209820046151731810,13492313676229607152,
                  1646619494427055162,8364233343890475733]},
    # TV-7: ELL sub-test
    {"id": "TV-7 ELL([1,2,3,4,5,6,7,8])",
     "input": None,  # sub-test only
     "expected": [73,82,91,76,101,110,119,104]},
]

def run():
    passed = 0
    failed = 0
    print("=" * 64)
    print("Poseidon2 impl#2 — test vectors (MAD §15.3)")
    print("=" * 64)

    # ELL sub-test (TV-7)
    got_ell = _external_mds_8([1,2,3,4,5,6,7,8])
    if got_ell == [73,82,91,76,101,110,119,104]:
        print("[PASS] TV-7 ELL([1..8]) sub-test")
        passed += 1
    else:
        print(f"[FAIL] TV-7 ELL expected [73,82,...,104] got {got_ell}")
        failed += 1

    for t in TESTS:
        if t["input"] is None:
            continue
        got = poseidon2_permute(t["input"])
        for v in got:
            assert 0 <= v < P, f"range error: {v}"
        if got == t["expected"]:
            print(f"[PASS] {t['id']}")
            passed += 1
        else:
            print(f"[FAIL] {t['id']}")
            for i,(e,g) in enumerate(zip(t["expected"],got)):
                if e!=g:
                    print(f"       diff@[{i}]: expected {hex(e)}, got {hex(g)}")
                    break
            failed += 1

    print("-" * 64)
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        print("FAIL"); sys.exit(1)
    else:
        print("PASS — all impl#2 test vectors match impl#1")

if __name__ == "__main__":
    run()
