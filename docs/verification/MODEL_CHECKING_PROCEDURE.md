# Formal Verification Procedure — Scalar Network
## Spec §15.1, §15.4, §15.5

### Prasyarat
- Java 17+ (OpenJDK recommended)
- TLA+ Tools v1.8+ (https://lamport.azurewebsites.net/tla/tools.html)
- Apalache v0.44+ (https://github.com/informalsystems/apalache) — optional

### Invariant CC (§15.4) — Model Checking

1. Create `verification/invariant_cc.cfg`:
CONSTANTS Nullifiers={n1,n2,n3,n4,n5} MaxEpoch=5
SPECIFICATION Spec
INVARIANTS TypeInvariant InvariantCC ZeroGapProperty

2. Run TLC:
java -cp tla2tools.jar tlc2.TLC invariant_cc.tla -config invariant_cc.cfg

3. Expected: No error. `THEOREM Spec => []InvariantCC` holds.

### Deferred Emission Pool (§15.5)

Run: `java -cp tla2tools.jar tlc2.TLC deferred_pool.tla -config deferred_pool.cfg`

### Audit Requirement (§15.1)
Two independent firms must verify these models before mainnet.
TLC + Apalache results documented.
