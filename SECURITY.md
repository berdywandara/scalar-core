# Security Policy — Scalar Network

**Specification version:** `Scalar_Master_Technical_Spec_v11.1-FINAL` (2026-07-15)  
**Repository:** `github.com/berdywandara/scalar-core`

---

## Scope

This policy covers security vulnerabilities in:

- All crates under `crates/` (scalar-crypto, scalar-nullifier, scalar-stark, scalar-network, scalar-consensus, scalar-emission, scalar-node, scalar-wallet-core, scalar-audit, scalar-governance, scalar-sdk)
- Protocol specification deviations that would allow double-spend, supply cap bypass, or de-anonymization
- Cryptographic primitive misuse or implementation errors
- Network-layer attacks (eclipse, Sybil, DoS against NMT peers)

---

## Supported Versions

| Version | Supported |
|---|---|
| v11.1-FINAL (SPEC_VERSION 0x06) | ✅ Active |
| v11.0 (SPEC_VERSION 0x05) | ⚠️ Transition only (4-epoch window) |
| < v11.0 | ❌ Not supported |

---

## Reporting a Vulnerability

> **Do not open a public GitHub issue for security vulnerabilities.**

### Preferred Channel

Report privately via **GitHub Security Advisories**:

1. Navigate to `https://github.com/berdywandara/scalar-core/security/advisories`
2. Click **"New draft security advisory"**
3. Fill in the template below and submit

### Report Template

```
Title: [Short description of the vulnerability]

Affected component: [crate name / protocol section]
Specification reference: [e.g., §4.3 CC, §6.3 checkpoint, §8.2 DMM]
CRYPTO_VERSION: [0x03 if applicable]

Description:
[Clear explanation of the vulnerability]

Impact:
[What an attacker can achieve — e.g., double-spend, supply inflation,
 de-anonymization, liveness failure]

Reproduction steps:
[Minimal steps or proof-of-concept code]

Suggested fix (optional):
[Your recommendation]
```

### Response Timeline

| Milestone | Target |
|---|---|
| Acknowledgement | ≤ 48 hours |
| Severity assessment | ≤ 5 business days |
| Fix or mitigation plan communicated | ≤ 14 days |
| Public disclosure (coordinated) | ≤ 90 days from report |

---

## Severity Classification

| Severity | Examples |
|---|---|
| **Critical** | Double-spend possible; supply cap bypass (S_MAX exceeded); full de-anonymization of transaction graph; STARK soundness break |
| **High** | NullifierSet integrity violation; DMM manipulation that produces diverging manifests; governance capture via protocol bug |
| **Medium** | Liveness failure under realistic network conditions; Tier C NodeScore cap bypass; NMT peer eclipse without Sybil investment |
| **Low** | Timing side-channel in non-critical path; implementation divergence from spec with no security impact; documentation error |

---

## Cryptographic Trust Assumptions

Scalar's security reduces to exactly three assumptions. A report that breaks any of these is **Critical**:

1. **BLAKE3 collision resistance** — used for MAC, key derivation, Fiat-Shamir transcript, tx ordering
2. **Poseidon2 collision resistance** — used for all in-circuit commitments, nullifiers, Merkle trees
3. **Goldilocks field arithmetic correctness** (`p = 2⁶⁴ − 2³² + 1`)

There is no trusted setup, no elliptic curve, no administrator key. A vulnerability in a higher-level protocol component (e.g., DMM bootstrapping, UTXO ordering) that does not break these primitives is still a valid report.

---

## Known Design Trade-offs (Not Vulnerabilities)

The following are intentional design decisions documented in Appendix A (Regulatory Framework):

| Property | Status |
|---|---|
| Post-hack on-chain tracing | Impossible by design (privacy guarantee) |
| Forced asset freeze/seizure | Not possible; no admin key exists |
| Transaction censorship at consensus layer | Not possible; CC constraint is ossified |
| ViewKey disclosure | Voluntary only; never compelled by protocol |

Reports requesting these capabilities will not be treated as vulnerabilities.

---

## Pre-Mainnet Mandatory Audit Requirements

The following verifications are **required before mainnet** and are relevant context for any security report:

- [ ] Two independent STARK implementations (Winterfell + second) — proofs must be mutually verifiable
- [ ] Two independent Argon2id constant-time implementations — byte-identical test vectors (SCL-SPEC-SEED-001)
- [ ] Formal verification of CC dual non-membership invariant (TLA+ or Coq) — §15.4
- [ ] Formal verification of Deferred Emission Pool invariant — §15.5
- [ ] Proving time benchmark ≤ 500 ms for 10-in/10-out — §15.6
- [ ] Two independent firm security audits of circuits and protocol

If you discover that any of these requirements are violated in the current implementation, please report it.

---

## OSSIFIED Parameters

The following parameters **cannot change without a protocol-level hard fork**. A report claiming these values are wrong in the implementation is high priority:

| Parameter | Canonical Value |
|---|---|
| `S_MAX` | 21,000,000 SCL |
| `S_E` | 18,900,000 SCL |
| FRI blowup factor | 8 |
| FRI queries | 84 |
| Grinding bits | 20 |
| `CRYPTO_VERSION_CURRENT` | `0x03` |
| `SPEC_VERSION_MANIFEST` | `0x06` |
| All domain separators | See §2.3 of spec |
| UTXO denominations D1–D17 | 1 sSCL → 10¹⁶ sSCL |

---

## Bug Bounty

A formal bug bounty program will be announced prior to public testnet. Until then, responsible disclosure is recognized with public credit in release notes (with your consent).

---

## Contact

Primary: GitHub Security Advisories (preferred)  
Secondary: Open a **private** discussion in the repository's Security tab

*This policy is effective as of 2026-07-15 and applies to all versions from v11.1-FINAL onward.*
