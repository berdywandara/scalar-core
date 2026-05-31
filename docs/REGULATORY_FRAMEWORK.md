# Appendix A — Regulatory Framework

**Document:** `SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY`  
**Specification:** `SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY` (2026-07-15)  
**Status:** Final — Part of the canonical specification

> This document is an integral part of the Scalar Network protocol documentation (SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY).  
> None of its provisions modify the core protocol, zero-knowledge circuits, or fundamental privacy guarantees of Scalar.

---

## A.1 Foundational Principle

Scalar is designed with **privacy-by-default** and **trustless verification** as non-negotiable properties. As a direct consequence:

- Any form of surveillance or audit that depends on access to individual transaction data **cannot be performed at the consensus layer**.
- This framework acknowledges that reality and offers a set of voluntary tools and limited auditability that still allow various stakeholders to verify **system-level integrity** without opening user privacy.

---

## A.2 Design Constraints with Compliance Implications

| Design Characteristic | Regulatory Implication |
|---|---|
| Transactions fully private via STARK proof | Regulators cannot see sender, recipient, or amount on-chain |
| No public addresses; UTXOs are cryptographic commitments only | Passive monitoring of fund flows is impossible |
| Single nullifier prevents double-spend but cannot be linked to a specific transaction | Regulators can verify no inflation or double-spend; individual coin tracing is not possible |
| No forced disclosure or admin key | No on-chain mechanism for freezing, seizure, or forced reversal |
| ViewKey is voluntary and held only by the user | Incoming transaction audit is only possible if the user explicitly shares their ViewKey |

---

## A.3 What Can Be Audited Publicly

Any party running a full node can independently verify the following properties **without permission**:

### A.3.1 Total Supply Integrity

```
total_pou_minted_sscl ≤ S_E (1,890,000,000,000,000 sSCL)
```

Verified via `AccountingState` and circuit constraint MC3. Any node can recompute this from genesis.

### A.3.2 Absence of Double-Spend

`NullifierSet` (NS_ACTIVE + NS_CHECKPOINT) contains no duplicates. Verified via STARK proofs and SMT root.

### A.3.3 Emission Formula Compliance

```
E(k) = E₀ × (1 − M_E(k−1) / S_E)²
```

This is computed deterministically. Every node can recompute it from `committed_manifest` and compare.

### A.3.4 Aggregate Network Health

Number of active nodes, uptime distribution, NodeScore distribution — available without revealing individual user identities.

### A.3.5 Historical Nullifier Integrity

`NS_CHECKPOINT` provides a cryptographic STARK proof that the full nullifier history has not been manipulated.

---

## A.4 Tools Available to Regulators and Auditors

### A.4.1 `scalar-audit` Crate

A dedicated read-only crate. No private key access. Only ZK verification and state inspection.

```rust
let report = scalar_sdk::audit::generate_audit_report();
// Returns PublicAuditState:
//   - total_pou_minted_sscl
//   - supply_cap_remaining_sscl
//   - active_nodes
//   - epoch_emission_actual_sscl
//   - nullifier_root
//   - security_fund_balance_sscl
//   - deferred_emission_pool_sscl
```

Available public API functions:

| Function ID | Name | Description |
|---|---|---|
| F1 | `query_scarcity_proof()` | Total minted supply, remaining emission capacity from public `AccountingState` |
| F2 | `query_monetary_policy_score()` | Inflation rate, emission per epoch — computed from public on-chain data |
| F3 | `query_network_health()` | Active node count, NodeScore distribution, average uptime |
| F4 | `query_node_reputation()` | NodeScore for a given `node_id` (pseudonym; score computed from public heartbeats) |
| F7 | `build_payment_proof()` | Proves a confirmed transaction occurred by referencing an existing STARK proof |
| F8 | `build_timestamp_record()` | Records a document hash on-chain via a standard transaction (fee: 40 sSCL) |
| F9 | `build_indelible_record()` | Same as F8; for permanent archival |
| F10 | `build_credential_proof()` | Proves ownership of a key or claim based on existing commitments/transactions |
| F11 | `query_uptime_sla()` | Historical uptime record for a node from public heartbeat data |
| TRCM | Transaction Risk & Compliance Module | Optional client-side pattern analysis on public data (see A.4.3) |
| W3C-VC | Verifiable Credentials | Voluntary KYC/credential issuance referencing UTXO commitments (see A.4.4) |

### A.4.2 ViewKey Sharing (Voluntary)

A user may share their `ViewKey` with a trusted auditor. The auditor can then:

- View **incoming** transactions received by the user
- Verify balances (no spending capability)

The auditor **cannot** see the user's outgoing transactions or any other user's data.

```
ViewKey = BLAKE3(AccountKey_i || "view")
// Derived in wallet — see §13.1
```

### A.4.3 Transaction Risk & Compliance Module (TRCM)

**Status:** Proposed — SDK implementation, no protocol change required.

TRCM runs entirely client-side. It analyzes **public data only** (timestamps, fee volume, transaction count distributions) to produce a compliance risk score. TRCM never accesses private keys or individual transaction data.

Implementation is optional. Operators (exchanges, custodians) may integrate TRCM into their own applications. It does not modify consensus behavior.

### A.4.4 W3C Verifiable Credentials (W3C-VC)

**Status:** Proposed — Option A (no new circuit required).

Credential issuers (e.g., exchanges, KYC providers) can:

- Issue credentials that reference a user's UTXO commitment
- Prove UTXO ownership without revealing its value
- Utilize `build_credential_proof()` for verification

The **Issuer Registry** is stored off-chain (SDK configuration), managed by application developers — not by consensus. Updating the registry requires no fork.

---

## A.5 Guidance for Regulators

### A.5.1 What Cannot Be Done in Scalar

| Action | Status |
|---|---|
| Trace individual fund flows on-chain | ❌ Impossible by design |
| Freeze assets by protocol command | ❌ No admin key exists |
| Recover funds from confirmed transactions | ❌ Mathematically irreversible |
| Monitor user balances without permission | ❌ Not possible |
| Automatically filter transactions at the consensus layer | ❌ Not possible |

### A.5.2 What Can Be Done in Scalar

| Action | Status |
|---|---|
| Verify monetary integrity independently (no hidden inflation) | ✅ Any full node |
| Request voluntary audit from entities willing to share ViewKey | ✅ Voluntary |
| Encourage exchanges/custodians to integrate TRCM or W3C-VC | ✅ SDK layer |
| Risk analysis based on public aggregate data (volume, fee distribution) | ✅ Public data |

---

## A.6 Anti-Backdoor Statement

There is **no "master key," "admin key," or equivalent mechanism** in Scalar. All OSSIFIED parameters (see §17.1 of the specification) can only be modified through a hard fork requiring strong majority consensus. The protocol provides no capability to:

- Issue SCL beyond the emission formula
- Reverse or cancel any confirmed transaction
- Selectively censor transactions at the consensus layer

Every compliance module (TRCM, W3C-VC) operates at the SDK layer, is optional, transparent, and cannot compel unwilling users.

---

## A.7 Stakeholder Summary

| Stakeholder | Available Tools | Nature |
|---|---|---|
| Central Bank / Monetary Authority | `scalar-audit` — monitor supply and inflation | Public, permissionless |
| Financial Regulator | TRCM, W3C-VC via service providers | Optional |
| Forensic Auditor | ViewKey (with user consent), `scalar-audit` | Voluntary |
| Application Developer | `scalar-sdk` public API | Open |
| End User | Full privacy by default; may voluntarily share ViewKey | Default private |

---

## A.8 Final Provisions

This document is included in the official Scalar specification release as **Appendix A — Regulatory Framework**. Its contents may be updated through the Layer 2 governance process (for TRCM/W3C-VC sections) or through specification amendments by the specification team.

No provision of this appendix will ever:
- Weaken the privacy guarantees of the core protocol layer
- Add compelled disclosure mechanisms
- Alter consensus-layer behavior

> *"Privacy is a right, not a crime. Compliance is a choice, not a compulsion."*

---

*Aligned with SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY — 2026-07-15*
