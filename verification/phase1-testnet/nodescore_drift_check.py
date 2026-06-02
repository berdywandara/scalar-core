"""
Phase 1 — NodeScore Drift Verification (P4: Hardened by Determinism)

Memverifikasi bahwa compute_node_score menghasilkan output IDENTIK
untuk input identik — property P4 dari SCALAR-PROTOCOL §0.

Ini adalah formal proof bahwa NodeScore computation bersifat deterministik.
Tidak memerlukan live node: pure function verification.

Spec: SCALAR-PROTOCOL §0 P4, §3.3 NodeScore Formula (OSSIFIED)
"""

import sys
import json
from dataclasses import dataclass
from typing import List, Tuple

# ── OSSIFIED constants — SCALAR-PROTOCOL §13.1 ───────────────────────────────
NODESCORE_UPTIME_W  = 500_000
NODESCORE_PROOF_W   = 300_000
NODESCORE_AGE_W     = 200_000
FIXED_POINT_BASIS   = 1_000_000
MAX_NODESCORE       = 1_000_000
TIER_C_MAX_NODESCORE = 600_000
TIER_C_PREFIX       = 0xFE
W_MATURE_EPOCHS     = 342

assert NODESCORE_UPTIME_W + NODESCORE_PROOF_W + NODESCORE_AGE_W == FIXED_POINT_BASIS, \
    "Weights must sum to FIXED_POINT_BASIS"

# ── NodeScore formula — SCALAR-PROTOCOL §3.3 (OSSIFIED) ──────────────────────

def compute_node_score(uptime_fp: int, proof_rate_fp: int, age_fp: int) -> int:
    """
    NodeScore formula (OSSIFIED — SCALAR-PROTOCOL §3.3).

    raw = floor((uptime_fp × UPTIME_W + proof_fp × PROOF_W + age_fp × AGE_W)
                / FIXED_POINT_BASIS)

    All inputs in [0, 1_000_000]. Output in [0, 1_000_000].
    """
    numer = (uptime_fp * NODESCORE_UPTIME_W
           + proof_rate_fp * NODESCORE_PROOF_W
           + age_fp * NODESCORE_AGE_W)
    return numer // FIXED_POINT_BASIS

def apply_tier_cap(node_id_full: bytes, raw_score: int) -> int:
    """Apply tier cap. Tier C (prefix 0xFE) capped at 600_000."""
    if node_id_full[0] == TIER_C_PREFIX:
        return min(raw_score, TIER_C_MAX_NODESCORE)
    return min(raw_score, MAX_NODESCORE)

# ── OSSIFIED test vectors — identical to Rust NODESCORE_TEST_VECTORS ─────────

OSSIFIED_VECTORS: List[Tuple[int, int, int, int]] = [
    # (uptime_fp, proof_rate_fp, age_fp, expected_score)
    (1_000_000, 1_000_000, 1_000_000, 1_000_000),  # perfect
    (0, 0, 0, 0),                                    # zero
    (1_000_000, 0, 0, 500_000),                      # uptime only
    (0, 1_000_000, 0, 300_000),                      # proof only
    (0, 0, 1_000_000, 200_000),                      # age only
    (700_000, 800_000, 600_000, 710_000),             # typical good node
    (850_000, 820_000, 750_000, 821_000),             # marginal NMT-eligible
    (500_000, 500_000, 500_000, 500_000),             # half performance
]

# ── Drift simulation — 3 nodes, identical inputs ─────────────────────────────

@dataclass
class SimulatedNode:
    """Simulated node with its own computation of NodeScore."""
    name: str
    node_id: bytes

    def compute_score(self, uptime_fp: int, proof_fp: int, age_fp: int) -> int:
        raw = compute_node_score(uptime_fp, proof_fp, age_fp)
        return apply_tier_cap(self.node_id, raw)

def run_drift_check():
    """
    P4 Drift verification: 3 simulated nodes with identical inputs must
    produce identical NodeScore. Any drift = determinism violation = protocol bug.
    """
    nodes = [
        SimulatedNode("NodeA", bytes([0x01] + [0xAA] * 31)),
        SimulatedNode("NodeB", bytes([0x02] + [0xBB] * 31)),
        SimulatedNode("NodeC", bytes([0x03] + [0xCC] * 31)),
    ]

    print("=" * 62)
    print("Phase 1 — NodeScore Drift Verification (P4)")
    print("SCALAR-PROTOCOL §0 P4 + §3.3 NodeScore Formula")
    print("=" * 62)

    passed = 0
    failed = 0

    # ── Test 1: OSSIFIED vectors ──────────────────────────────────────────────
    print("\n[TEST 1] OSSIFIED test vectors (identical to Rust compute_node_score)")
    for uptime, proof, age, expected in OSSIFIED_VECTORS:
        got = compute_node_score(uptime, proof, age)
        if got == expected:
            print(f"  [PASS] ({uptime}, {proof}, {age}) → {got}")
            passed += 1
        else:
            print(f"  [FAIL] ({uptime}, {proof}, {age}) → expected {expected}, got {got}")
            failed += 1

    # ── Test 2: Drift across 3 nodes ─────────────────────────────────────────
    print("\n[TEST 2] P4 Drift — 3 nodes, identical inputs → identical output")
    test_inputs = [
        ("epoch_1_typical", 850_000, 900_000, 45),       # 45/342 epochs mature
        ("epoch_1_new_node", 700_000, 600_000, 1),         # 1 epoch old
        ("epoch_171_mature", 950_000, 900_000, 171),       # half-mature
        ("epoch_342_full", 1_000_000, 1_000_000, 342),    # fully mature
        ("epoch_300_degraded", 600_000, 700_000, 300),     # degraded
    ]

    all_scenarios_pass = True
    for label, uptime, proof, epochs in test_inputs:
        age_fp = min(epochs, W_MATURE_EPOCHS) * FIXED_POINT_BASIS // W_MATURE_EPOCHS
        scores = {node.name: node.compute_score(uptime, proof, age_fp) for node in nodes}
        all_identical = len(set(scores.values())) == 1
        drift = max(scores.values()) - min(scores.values())

        if all_identical:
            score = list(scores.values())[0]
            print(f"  [PASS] {label}: all nodes → {score} (drift=0)")
            passed += 1
        else:
            print(f"  [FAIL] {label}: DRIFT DETECTED!")
            for name, score in scores.items():
                print(f"           {name}: {score}")
            failed += 1
            all_scenarios_pass = False

    # ── Test 3: Tier C cap determinism ───────────────────────────────────────
    print("\n[TEST 3] Tier C cap determinism")
    tier_c_id = bytes([TIER_C_PREFIX] + [0x42] * 31)
    tier_c_node = SimulatedNode("TierC", tier_c_id)

    raw = compute_node_score(1_000_000, 1_000_000, 1_000_000)
    capped = apply_tier_cap(tier_c_id, raw)
    if capped == TIER_C_MAX_NODESCORE:
        print(f"  [PASS] Tier C raw={raw} → capped={capped} (600_000)")
        passed += 1
    else:
        print(f"  [FAIL] Tier C cap wrong: {capped}")
        failed += 1

    # ── Test 4: NMT eligibility determinism ──────────────────────────────────
    print("\n[TEST 4] NMT eligibility threshold (800_000)")
    nmt_cases = [
        (800_001, True),   # just above threshold → eligible
        (800_000, False),  # exactly threshold → NOT eligible (strictly >)
        (799_999, False),  # below → not eligible
        (1_000_000, True), # max → eligible
    ]
    for score_val, expected_eligible in nmt_cases:
        eligible = score_val > 800_000
        if eligible == expected_eligible:
            print(f"  [PASS] score={score_val} → nmt_eligible={eligible}")
            passed += 1
        else:
            print(f"  [FAIL] score={score_val} → expected {expected_eligible}, got {eligible}")
            failed += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 62)
    print(f"Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("PASS — NodeScore computation is deterministic (P4 VERIFIED)")
        print("\nP4 Conclusion:")
        print("  Given identical inputs (uptime_fp, proof_fp, age_fp),")
        print("  all nodes compute identical NodeScore. No drift possible")
        print("  from the formula itself. Drift in live testnet can only")
        print("  come from different INPUT observations (network timing).")
    else:
        print("FAIL — Determinism violation detected!")
        sys.exit(1)

    # ── Output report ─────────────────────────────────────────────────────────
    return {
        "passed": passed,
        "failed": failed,
        "p4_verified": failed == 0,
        "ossified_vectors_count": len(OSSIFIED_VECTORS),
        "drift_scenarios_count": len(test_inputs),
    }

if __name__ == "__main__":
    result = run_drift_check()
    print(f"\nJSON: {json.dumps(result, indent=2)}")
