# Design Decisions — Pre-Genesis Final Record

All decisions documented below have been **resolved** by the protocol architect.
Items that still require team confirmation before testnet/mainnet are tagged
`AWAITING CONFIRMATION`.

---

### D.1 K9-02 – `scalar_utxo_v2` (DOMAIN_UTXO_SMT) Not in OSSIFIED Registry

**FINAL DECISION: OPTION A – APPROVED WITH MODIFICATION**  
**Status: RESOLVED**

The UTXO-set root domain separator `b"scalar_utxo_v2"` (18 bytes) was not listed
in the OSSIFIED domain registry (§2.3).

**Actions taken:**

1. Registered `b"scalar_utxo_set"` (15 bytes) as the canonical OSSIFIED constant
   `DOMAIN_UTXO_SMT` in `core/scalar-crypto/src/domain.rs`. The version suffix
   `_v2` was dropped to match the naming convention of all other separators.
2. Updated `core/scalar-emission/src/utxo_set_smt.rs` to use
   `DOMAIN_UTXO_SMT = b"scalar_utxo_set"`.
3. Replaced raw literals in `scalar-wallet-core` and `scalar-compliance` with
   the imported constant.
4. **Pre-genesis action required:** recompute `utxo_set_root` with the final
   separator before the genesis ceremony.

Reusing `scalar_smt_active` was rejected: the UTXO set (CB constraint) and the
NullifierSet active layer (CC constraint) serve different cryptographic purposes
and MUST use distinct domain separators (§2.3).

---

### D.2 K2-04 – Struct Naming: `NodeHeartbeat` vs `HeartbeatUnit`

**FINAL DECISION: RENAME TO `HeartbeatUnit` – APPROVED**  
**Status: RESOLVED**

The Rust struct was named `NodeHeartbeat` while the specification (§7.3) and
the optimisation document consistently use `HeartbeatUnit`.

**Actions taken:**

1. Renamed the struct and all references in **11 files** across
   `scalar-emission`, `scalar-network`, and `scalar-node`.
2. Verified that the wire format is unaffected (Rust struct names are not
   serialised).
3. The specification requires no changes — it already uses `HeartbeatUnit`
   throughout.

---

### D.3 – `UtxoSetSMT::compute_root`: Sequential Hash vs True SMT

**FINAL DECISION: OPTION (a) WITH CONDITIONS – APPROVED FOR GENESIS ONLY**  
**Status: RESOLVED WITH CONDITIONS**

The current implementation uses a sequential hash
(`BLAKE3(DOMAIN || c0 || c1 || ...)`) rather than a true Sparse Merkle Tree.
The architect accepted this for genesis under three **non-negotiable conditions**:

1. **Master Spec §4.3 CB constraint** must document that the pre-genesis
   implementation uses sequential hash verification (witness O(n)) and will be
   replaced by `IMT_MembershipVerify` (witness O(log n)) per the
   *Scalar_Optimalisasi_PraGenesis* §3.1 architecture.
2. The source file `core/scalar-emission/src/utxo_set_smt.rs` now carries an
   explicit comment:
// PRE-GENESIS TEMPORARY: Sequential hash, witness O(n).
// Must be replaced with IMT-based EpochSMT before testnet
// with full client proving. See §3.1 Scalar_Optimalisasi_PraGenesis.
// TRACKING: D3 decision – docs/decisions/DESIGN_DECISIONS_PENDING.md

3. The sequential hash is an **intermediate computation** on the path to the
IMT-based EpochSMT. Implementation phases 2 (IMT) and 4 (Quaternary SMT)
of the optimisation roadmap must be completed before mainnet.

**Correction from original recommendation:** the statement "a true SMT can be
added post-genesis as a non-breaking upgrade" is inaccurate. The replacement
must occur **before** testnet with full client proving, because it affects the
CB constraint and the witness structure of the Transfer Circuit. A post-genesis
change would require a hard fork.

**Current explicit limitations:**
- Witness size grows O(n) with the number of UTXOs.
- Per-UTXO Merkle-path verification is not supported.
- Suitable only for genesis with a small UTXO set.
- MUST NOT enter production/testnet with full client proving.

---

### D.4 K5-02 – In-Circuit Mutual Exclusion (INV-4.6)

**Status: RESOLVED (FASE A)**

The Winterfell AIR in `transfer_air.rs` enforces `single_utxo_source` in-circuit
(column 7 boundary assertion). The out-of-circuit guard in `air.rs` is retained
as defence-in-depth. No team decision is required.
