# Security Policy

Scalar Network is post-quantum digital cash. Security is not a feature — it is the foundation. This document describes how to responsibly report vulnerabilities and what to expect in return.

---

## Scope

Security reports are accepted for the following components:

| Component | Scope |
|---|---|
| Transfer Circuit (C1–C10) | **Critical** — any soundness bypass or privacy leak |
| Mint Claim Circuit (MC1–MC5) | **Critical** — any supply cap bypass |
| NullifierSet (HOT/WARM/COLD/ARCH) | **Critical** — any double-spend enablement |
| CryptoVersion Registry | **High** — any version confusion or downgrade attack |
| Argon2id NodeID generation | **High** — any Sybil cost reduction |
| Pheromone reconciliation | **High** — any consensus manipulation |
| Eclipse defense | **High** — any bypass of 5-layer eclipse protection |
| Dandelion++ routing | **Medium** — any deanonymization path |
| Governance (conviction, GovernanceID) | **Medium** — any power manipulation |
| scalar-ffi bindings | **Medium** — memory safety, pointer handling |
| Key derivation chain | **High** — any key leakage or derivation weakness |

**Out of scope:** UI cosmetic issues, documentation errors, theoretical attacks requiring >2⁶⁴ operations, issues already publicly disclosed.

---

## Severity Classification

### Critical
Vulnerabilities that directly break one of the four core properties:

- **No Blockchain:** State manipulation without valid STARK proof
- **Privacy by Default:** Extraction of private witness from public inputs
- **Mathematical Truth:** STARK soundness bypass — invalid proof accepted as valid
- **Supply Cap:** Any path to mint beyond 21,000,000 SCL

Critical issues receive immediate response. The network may halt until resolved.

### High
Vulnerabilities that significantly degrade security without directly breaking core properties:

- Double-spend enablement via NullifierSet weakness
- Sybil attack cost reduction (Argon2id bypass)
- Eclipse attack that bypasses all 5 defense layers
- Governance power manipulation exceeding documented bounds
- Key derivation weakness exposing SpendKey or NodeKey

### Medium
Vulnerabilities that reduce privacy or increase attack surface:

- Deanonymization via timing, routing, or padding analysis
- GovernanceID linkage to transaction history
- Partial eclipse or reconciliation manipulation

### Low
Issues that represent hardening opportunities without active exploit path.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via one of the following channels:

1. **GitHub Private Security Advisory** (preferred)
   Navigate to: `https://github.com/berdywandara/scalar-core/security/advisories/new`

2. **Direct contact**
   Reach the original architect via contact information in `AUTHORS.md`.

### What to Include

A useful report contains:

- **Description** — what the vulnerability is and where it lives in the codebase
- **Impact** — which of the four core properties (or secondary properties) is affected
- **Reproduction** — minimal steps or proof-of-concept code to demonstrate the issue
- **Suggested fix** — optional, but appreciated
- **Your contact** — so we can coordinate disclosure and credit

You do not need to have a complete exploit. A credible description of the attack path is sufficient.

---

## Response Timeline

| Stage | Target Timeline |
|---|---|
| Acknowledgement of report | Within 48 hours |
| Initial severity assessment | Within 7 days |
| Fix development begins | Within 14 days for Critical/High |
| Coordinated disclosure | 90 days after report (or sooner if fix is ready) |
| Public CVE / advisory | At time of coordinated disclosure |

For **Critical** vulnerabilities affecting soundness or supply cap, we will coordinate an accelerated timeline with the reporter.

---

## Disclosure Policy

Scalar follows **coordinated disclosure**:

- Reporter notifies us privately
- We develop and test a fix
- We agree on a disclosure date (default: 90 days from report)
- Fix is released and advisory is published simultaneously
- Reporter is credited unless they request anonymity

We will not pursue legal action against researchers who follow this policy in good faith.

---

## What We Will Not Do

- We will not ask you to sign an NDA to receive acknowledgement
- We will not threaten legal action for good-faith security research
- We will not silently patch without credit to the reporter
- We will not dismiss reports without explanation

---

## Bug Bounty

Scalar Network does not currently operate a formal paid bug bounty program. Reporters of **Critical** and **High** severity issues will be:

- Credited in the public security advisory
- Listed in `AUTHORS.md` under the Security Researchers section (with permission)
- Eligible for reward from the Protocol Security Fund (5% of fees) once the network is live, at the discretion of the community

---

## Cryptographic Vulnerability Monitoring

Per spec §2.3, the Scalar community conducts active cryptanalysis monitoring every 6 months covering:

- Poseidon2 algebraic cryptanalysis publications
- STARK soundness research
- BLAKE3 and SHA3 security status
- SPHINCS+ security analysis updates

If you are aware of a published cryptanalytic result that materially affects Scalar's security assumptions, please report it even if it does not constitute an immediately exploitable vulnerability. The CryptoVersion Registry exists precisely to enable cryptographic agility in response to such findings.

---

## Known Security Properties and Accepted Risks

The following are **known design decisions**, not vulnerabilities:

| Property | Status |
|---|---|
| Proving requires plaintext private witness in RAM | Accepted risk. Mitigation: HSM recommended for high-commitment nodes, TrustZone for mobile, memory zeroization after proving. |
| STARK soundness error ε ≈ 2⁻⁶¹⁴⁴ per proof | Negligible. Not a vulnerability. |
| Governance Layer 2 parameters adjustable by 75%+60% threshold | By design. Layer 1 ossified parameters are circuit-enforced and cannot be changed by governance. |
| Single STARK implementation (Winterfell) pre-mainnet | Known gap. Second independent implementation required before mainnet per spec §2.2. |
| NS_WARM/NS_COLD false positives possible | By design. False positives only reject honest double-spend attempts. False negatives are mathematically impossible. |

---

## Security Contact

See `AUTHORS.md` for contact information.

> *Mathematical truth cannot be argued with. STARK proof validity is objective and deterministic. A superintelligent AI cannot make an invalid proof valid. This is the foundation Scalar is built on.*