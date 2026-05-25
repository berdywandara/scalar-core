# Pending Design Decisions — Pre-Genesis
## Audit Findings Requiring Team Confirmation

### D.1 K9-02 — `scalar_utxo_v2` (DOMAIN_UTXO_SMT) Not in OSSIFIED Registry

**Current state**: `core/scalar-emission/src/utxo_set_smt.rs` defines
`DOMAIN_UTXO_SMT = b"scalar_utxo_v2"` (18 bytes). This separator is NOT
registered in `core/scalar-crypto/src/domain.rs` (§2.3 OSSIFIED registry).

**Two options**:

| Option | Action | Impact |
|--------|--------|--------|
| A | Register `scalar_utxo_v2` as new OSSIFIED separator in `domain.rs` | Changes on-chain `utxo_set_root` — requires hard fork after genesis |
| B | Replace with existing OSSIFIED separator `scalar_smt_active` (17 bytes) | Keeps registry clean; `utxo_set_root` recomputation needed pre-genesis |

**Trade-off**:
- Option A: cleaner semantics (UTXO set ≠ active nullifier SMT), but adds new OSSIFIED constant
- Option B: no new constant, but reuses a separator already used for NullifierSet active layer — potential domain collision risk

**Recommendation**: Option A (register as OSSIFIED). The UTXO set is conceptually distinct from the NullifierSet active layer. Reusing `scalar_smt_active` risks domain collision.

---

### D.2 K2-04 — Struct Naming: `NodeHeartbeat` vs `HeartbeatUnit`

**Current state**: `scalar-emission/src/liveness.rs` defines `NodeHeartbeat`.
The spec (§7.3) names it `HeartbeatUnit`.

**Decision needed**: Rename to `HeartbeatUnit` for spec consistency, or keep
`NodeHeartbeat` and update spec. This is a cosmetic change — no protocol impact.

**Recommendation**: Rename to `HeartbeatUnit`. The spec is the source of truth.

---

### D.3 Catatan — UtxoSetSMT::compute_root is Sequential Hash, Not SMT

**Current state**: `UtxoSetSMT::compute_root()` uses `BLAKE3(DOMAIN_UTXO_SMT || c0 || c1 || ...)` — sequential hash of all commitments, not a true Sparse Merkle Tree.

**Spec requirement** (§8.5, §16.1): The spec names this "UtxoSetSMT" and references membership proofs. If true SMT membership proofs are required for UTXO set verification (CB constraint), this implementation is insufficient.

**Decision needed**: 
- (a) Accept sequential hash for UTXO set root (no per-UTXO membership proof needed for CB constraint — membership is verified out-of-circuit via the canonical ordering proof)
- (b) Replace with true SMT for per-UTXO membership proofs in-circuit

**Recommendation**: (a) for genesis. The CB constraint in Transfer Circuit uses the root as a public input, with membership verified by the prover (who has the full UTXO set). A true SMT can be added post-genesis as a non-breaking upgrade.

---

### D.4 K5-02 Status — In-Circuit Mutual Exclusion (INV-4.6)

**Resolved in FASE A**: `transfer_air.rs` column 7 enforces `single_utxo_source` IN-CIRCUIT via Winterfell boundary assertion. The out-of-circuit guard in `air.rs` remains as defense-in-depth. No decision needed.
