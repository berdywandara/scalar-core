# TLA+ Verification Report — ScalarGovernanceVote

**Property:** NoGovernanceDoubleVote  
**Status:** PASS — No error found  
**Date:** 2026-06-14  
**TLC Version:** 2026.05.26.235334  
**Spec:** ScalarGovernanceVote.tla  
**Config:** ScalarGovernanceVote.cfg  

---

## What Was Verified

In plain language: we proved that no node can finalize two votes for
the same proposal, under any possible ordering of events — including
network delays, concurrent submission attempts, and race conditions.

The model checked all possible interleavings of 3 nodes voting on
2 proposals (75,001 states, 15,625 distinct states).

---

## Model Parameters

| Parameter | Value |
|-----------|-------|
| NODES | {n1, n2, n3} |
| PROPOSALS | {p1, p2} |
| States generated | 75,001 |
| Distinct states | 15,625 |
| State graph depth | 25 |
| Workers | 2 |
| Runtime | ~11 seconds |

---

## Properties Verified

### Safety Invariants (must hold in EVERY state)

| Invariant | Result | Description |
|-----------|--------|-------------|
| TypeOK | PASS | All variables have correct types |
| NoGovernanceDoubleVote | PASS | No (node, proposal) pair finalized twice |
| AtomicGateEnforcement | PASS | Blocked pairs were already finalized — gate is atomic |
| IrreversibleFinalization | PASS | Finalized votes cannot be removed |
| NoFinalizationBypass | PASS | Level-2 only reachable via Level-1 optimistic |

### Temporal Property (must hold eventually)

| Property | Result | Description |
|----------|--------|-------------|
| EventualFinalization | PASS | Every submitted vote eventually finalized or blocked |

---

## What the Model Represents in Code

The TLA+ model maps directly to `CommitStark::commit_governance_vote()`
in `core/scalar-consensus/src/commit_stark.rs`:
TLA+ Action          | Rust Implementation

─────────────────────┼────────────────────────────────────────────

SubmitVote           | vote_payload submitted to network

PromoteToOptimistic  | Level-1 MicroCommitment quorum reached

FinalizeVote         | commit_governance_vote() → Ok(StarkFinal)

AttemptDoubleVote    | commit_governance_vote() → Err(GovernanceVoteAlreadyFinalized)

The `finalized_votes: HashSet<([u8;32],[u8;32])>` in Rust enforces
the same invariant that TLA+ verified: set insertion is idempotent,
and the gate checks membership before inserting.

---

## Scope and Limitations

This verification covers the **finality gate logic** only.

Not covered (pending ADR-SEC-023 and Phase 0):
- Cryptographic soundness of the vote_payload signature (SLH-DSA)
- Network-level Byzantine fault tolerance
- Cross-chain replay attacks (chain_id binding not modeled)
- Liveness under Byzantine validators (only crash-stop modeled)

---

## Reference

- SCALAR-PROTOCOL §4.5, §13.1 — IRREVERSIBLE_ACTION_SET
- SCALAR-SECURITY §2.1 — NoGovernanceDoubleVote property
- `core/scalar-consensus/src/commit_stark.rs` — implementation
- ADR-SEC-024 — cubic field construction (separate concern)
