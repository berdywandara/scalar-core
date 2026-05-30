//! Privacy Layer (D-017). MAD §5.3, §12.1, §12.2.
//!
//! Three components:
//!   1. ValueCommitment — Poseidon2 hash-based, quantum-resistant (§5.3)
//!   2. StealthAddress   — hash-based stealth address, ECDH-free (§12.1)
//!   3. ZkKycCredential  — selective disclosure credential (§12.2)
//!
//! DOMAIN SEPARATORS (OSSIFIED — MAD §1.4):
//!   Viewing key:  b"scalar_view"
//!   Spending key: b"scalar_spend"
//!   Stealth addr: b"scalar_stealth"
//!
//! QUANTUM RESISTANCE:
//!   No ECC/ECDH used anywhere in this module.
//!   All operations are hash-based (BLAKE3 or Poseidon2).
//!   Secure against Grover's algorithm with 256-bit outputs.

use crate::poseidon2_t8::poseidon2_permute_t8;

// ── Domain separators (OSSIFIED) ──────────────────────────────────────────────

const DOMAIN_VIEW: &[u8] = b"scalar_view";
const DOMAIN_SPEND: &[u8] = b"scalar_spend";
const DOMAIN_STEALTH: &[u8] = b"scalar_stealth";

// ── 1. VALUE COMMITMENT (§5.3) ────────────────────────────────────────────────
//
// value_commitment = Poseidon2([value, blinding_factor, salt, 0, 0, 0, 0, 0])
//
// NOT homomorphic (intentional — no ECC). Sum verified explicitly in-circuit.
// Quantum-resistant: no elliptic curve operations.

/// A Poseidon2 value commitment. MAD §5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueCommitment {
    /// The commitment output: 4 x u64 Goldilocks elements (first 4 of Poseidon2 state).
    pub commitment: [u64; 4],
}

/// Committed value with blinding factor. MAD §5.3.
#[derive(Debug, Clone)]
pub struct ValueCommitmentOpening {
    /// The committed value (sSCL). Spec §5.3.
    pub value: u64,
    /// 256-bit blinding factor. Must be sampled uniformly at random.
    pub blinding_factor: u64,
    /// Salt. Spec §5.3.
    pub salt: u64,
}

impl ValueCommitmentOpening {
    /// Compute the commitment for this opening. MAD §5.3.
    pub fn commit(&self) -> ValueCommitment {
        let input = [self.value, self.blinding_factor, self.salt, 0, 0, 0, 0, 0];
        let output = poseidon2_permute_t8(&input);
        ValueCommitment {
            commitment: [output[0], output[1], output[2], output[3]],
        }
    }

    /// Verify that this opening matches a given commitment. MAD §5.3.
    pub fn verify(&self, commitment: &ValueCommitment) -> bool {
        self.commit() == *commitment
    }
}

/// Commitment error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitmentError {
    #[error("Commitment verification failed: opening does not match commitment")]
    OpeningMismatch,
}

// ── 2. STEALTH ADDRESS (§12.1) ────────────────────────────────────────────────
//
// master_key:   256-bit random, user secret
// viewing_key:  BLAKE3("scalar_view"  || master_key || nonce)
// spending_key: BLAKE3("scalar_spend" || master_key || nonce)
// stealth_addr: BLAKE3("scalar_stealth" || recipient_viewing_key || tx_counter)
//
// QUANTUM RESISTANCE: fully hash-based, no ECDH.
// TRADE-OFF: sender must know recipient's viewing_key (not passive).

/// A user's stealth address key material. MAD §12.1.
#[derive(Debug, Clone)]
pub struct StealthKeyPair {
    /// viewing_key = BLAKE3("scalar_view" || master_key || nonce). MAD §12.1.
    pub viewing_key: [u8; 32],
    /// spending_key = BLAKE3("scalar_spend" || master_key || nonce). MAD §12.1.
    pub spending_key: [u8; 32],
}

impl StealthKeyPair {
    /// Derive viewing + spending keys from master_key and nonce. MAD §12.1.
    pub fn derive(master_key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        let viewing_key = {
            let mut h = blake3::Hasher::new();
            h.update(DOMAIN_VIEW);
            h.update(master_key);
            h.update(nonce);
            *h.finalize().as_bytes()
        };
        let spending_key = {
            let mut h = blake3::Hasher::new();
            h.update(DOMAIN_SPEND);
            h.update(master_key);
            h.update(nonce);
            *h.finalize().as_bytes()
        };
        Self {
            viewing_key,
            spending_key,
        }
    }
}

/// A one-time stealth address. MAD §12.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StealthAddress(pub [u8; 32]);

impl StealthAddress {
    /// Generate a one-time stealth address for a recipient. MAD §12.1.
    ///
    /// `recipient_viewing_key`: the recipient's viewing key (shared out-of-band).
    /// `tx_counter`: monotonic counter from sender (prevents address reuse).
    pub fn generate(recipient_viewing_key: &[u8; 32], tx_counter: u64) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_STEALTH);
        h.update(recipient_viewing_key);
        h.update(&tx_counter.to_le_bytes());
        Self(*h.finalize().as_bytes())
    }

    /// Scan: check if this stealth address belongs to `keys`. MAD §12.1.
    ///
    /// Recipient tries each on-chain stealth address with their viewing_key
    /// to see if it was generated for them.
    ///
    /// `tx_counter`: the counter used to generate this address (from tx metadata).
    pub fn matches(&self, keys: &StealthKeyPair, tx_counter: u64) -> bool {
        let expected = Self::generate(&keys.viewing_key, tx_counter);
        *self == expected
    }
}

// ── 3. ZK-KYC CREDENTIAL (§12.2) ─────────────────────────────────────────────
//
// Credential from approved issuer (regulated entity). MAD §12.2.
// ZK proof that user has valid credential without revealing identity.
//
// In-circuit verification uses ScalarPoseidon2Air (existing infrastructure).
// This module provides out-of-circuit credential structures and verification.

/// Compliance property that can be proved via ZK-KYC. MAD §12.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ComplianceProperty {
    /// User is not on sanctions list.
    NotSanctioned,
    /// User is from an approved jurisdiction.
    ApprovedJurisdiction { jurisdiction_id: u32 },
    /// User has passed AML screening.
    AmlScreeningPassed,
    /// User meets minimum age requirement.
    AgeVerified { min_age: u8 },
}

/// ZK-KYC credential issued by a regulated entity. MAD §12.2.
#[derive(Debug, Clone)]
pub struct ZkKycCredential {
    /// Commitment to holder identity: BLAKE3(identity_secret || salt). MAD §12.2.
    /// Not reversible without identity_secret.
    pub holder_id_commitment: [u8; 32],
    /// Issuer public key (SLH-DSA). MAD §12.2.
    pub issuer_pubkey: Vec<u8>,
    /// Epoch number after which credential expires. MAD §12.2.
    pub expiry_epoch: u64,
    /// Compliance properties this credential attests to. MAD §12.2.
    pub properties: Vec<ComplianceProperty>,
    /// SLH-DSA signature over credential fields. MAD §12.2.
    pub issuer_signature: Vec<u8>,
}

/// Commitment to identity used in ZK-KYC. MAD §12.2.
pub fn commit_holder_identity(identity_secret: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"scalar_kyc_id"); // domain separator
    h.update(identity_secret);
    h.update(salt);
    *h.finalize().as_bytes()
}

/// Canonical bytes for issuer to sign. MAD §12.2.
///
/// Issuer signs: BLAKE3("scalar_kyc_sig" || holder_id_commitment || expiry_bytes || properties_hash)
pub fn credential_signing_bytes(
    holder_id_commitment: &[u8; 32],
    expiry_epoch: u64,
    properties: &[ComplianceProperty],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"scalar_kyc_sig");
    h.update(holder_id_commitment);
    h.update(&expiry_epoch.to_le_bytes());
    for prop in properties {
        let prop_bytes = encode_property(prop);
        h.update(&prop_bytes);
    }
    *h.finalize().as_bytes()
}

fn encode_property(prop: &ComplianceProperty) -> Vec<u8> {
    match prop {
        ComplianceProperty::NotSanctioned => vec![0x01],
        ComplianceProperty::ApprovedJurisdiction { jurisdiction_id } => {
            let mut v = vec![0x02];
            v.extend_from_slice(&jurisdiction_id.to_le_bytes());
            v
        }
        ComplianceProperty::AmlScreeningPassed => vec![0x03],
        ComplianceProperty::AgeVerified { min_age } => vec![0x04, *min_age],
    }
}

/// Errors for ZK-KYC operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KycError {
    #[error("Credential expired at epoch {expiry}, current epoch {current}")]
    Expired { expiry: u64, current: u64 },

    #[error("Issuer not in approved issuer list")]
    UnapprovedIssuer,

    #[error("Required property {0:?} not in credential")]
    MissingProperty(String),

    #[error("Credential signature verification failed")]
    InvalidSignature,
}

/// Out-of-circuit ZK-KYC verification. MAD §12.2.
///
/// Verifies that:
///   1. current_epoch <= credential.expiry_epoch
///   2. issuer is in approved_issuers list
///   3. required_property is in credential.properties
///
/// Note: signature verification is performed in-circuit (ScalarPoseidon2Air).
/// This function provides the out-of-circuit property check only.
pub fn verify_credential_properties(
    credential: &ZkKycCredential,
    current_epoch: u64,
    required_property: &ComplianceProperty,
    approved_issuers: &[[u8; 32]], // BLAKE3 of approved issuer pubkeys
) -> Result<(), KycError> {
    // Check expiry
    if current_epoch > credential.expiry_epoch {
        return Err(KycError::Expired {
            expiry: credential.expiry_epoch,
            current: current_epoch,
        });
    }

    // Check issuer approval
    let issuer_hash: [u8; 32] = *blake3::hash(&credential.issuer_pubkey).as_bytes();
    if !approved_issuers.contains(&issuer_hash) {
        return Err(KycError::UnapprovedIssuer);
    }

    // Check required property
    if !credential.properties.contains(required_property) {
        return Err(KycError::MissingProperty(format!("{required_property:?}")));
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ValueCommitment ───────────────────────────────────────────────

    #[test]
    fn test_commitment_deterministic() {
        let o = ValueCommitmentOpening {
            value: 1000,
            blinding_factor: 42,
            salt: 7,
        };
        assert_eq!(o.commit(), o.commit(), "Commitment must be deterministic");
    }

    #[test]
    fn test_commitment_verify_correct_opening() {
        let o = ValueCommitmentOpening {
            value: 500_000,
            blinding_factor: 0xDEAD,
            salt: 0xBEEF,
        };
        let c = o.commit();
        assert!(o.verify(&c));
    }

    #[test]
    fn test_commitment_verify_wrong_value() {
        let o = ValueCommitmentOpening {
            value: 100,
            blinding_factor: 1,
            salt: 2,
        };
        let c = o.commit();
        let wrong = ValueCommitmentOpening {
            value: 101,
            blinding_factor: 1,
            salt: 2,
        };
        assert!(!wrong.verify(&c));
    }

    #[test]
    fn test_commitment_verify_wrong_blinding() {
        let o = ValueCommitmentOpening {
            value: 100,
            blinding_factor: 1,
            salt: 0,
        };
        let c = o.commit();
        let wrong = ValueCommitmentOpening {
            value: 100,
            blinding_factor: 2,
            salt: 0,
        };
        assert!(!wrong.verify(&c));
    }

    #[test]
    fn test_different_values_different_commitments() {
        let a = ValueCommitmentOpening {
            value: 1,
            blinding_factor: 0,
            salt: 0,
        }
        .commit();
        let b = ValueCommitmentOpening {
            value: 2,
            blinding_factor: 0,
            salt: 0,
        }
        .commit();
        assert_ne!(a, b);
    }

    // ── StealthAddress ────────────────────────────────────────────────

    #[test]
    fn test_stealth_key_derivation_deterministic() {
        let mk = [0xAAu8; 32];
        let nonce = [0x01u8; 16];
        let k1 = StealthKeyPair::derive(&mk, &nonce);
        let k2 = StealthKeyPair::derive(&mk, &nonce);
        assert_eq!(k1.viewing_key, k2.viewing_key);
        assert_eq!(k1.spending_key, k2.spending_key);
    }

    #[test]
    fn test_viewing_spending_keys_differ() {
        let k = StealthKeyPair::derive(&[0xBBu8; 32], &[0x00u8; 16]);
        assert_ne!(k.viewing_key, k.spending_key);
    }

    #[test]
    fn test_stealth_address_matches_correct_counter() {
        let mk = [0xCCu8; 32];
        let nonce = [0x02u8; 16];
        let keys = StealthKeyPair::derive(&mk, &nonce);
        let addr = StealthAddress::generate(&keys.viewing_key, 42);
        assert!(addr.matches(&keys, 42));
    }

    #[test]
    fn test_stealth_address_wrong_counter_no_match() {
        let keys = StealthKeyPair::derive(&[0xDDu8; 32], &[0x03u8; 16]);
        let addr = StealthAddress::generate(&keys.viewing_key, 1);
        assert!(!addr.matches(&keys, 2), "Different counter must not match");
    }

    #[test]
    fn test_stealth_address_wrong_viewing_key_no_match() {
        let keys1 = StealthKeyPair::derive(&[0x11u8; 32], &[0u8; 16]);
        let keys2 = StealthKeyPair::derive(&[0x22u8; 32], &[0u8; 16]);
        let addr = StealthAddress::generate(&keys1.viewing_key, 0);
        assert!(!addr.matches(&keys2, 0));
    }

    #[test]
    fn test_different_counters_different_addresses() {
        let keys = StealthKeyPair::derive(&[0xEEu8; 32], &[0u8; 16]);
        let a0 = StealthAddress::generate(&keys.viewing_key, 0);
        let a1 = StealthAddress::generate(&keys.viewing_key, 1);
        assert_ne!(a0, a1, "Each tx_counter must produce unique address");
    }

    // ── ZK-KYC ───────────────────────────────────────────────────────

    fn make_credential(expiry: u64, props: Vec<ComplianceProperty>) -> (ZkKycCredential, [u8; 32]) {
        let issuer_pk = vec![0xABu8; 32]; // mock SLH-DSA pubkey
        let issuer_hash: [u8; 32] = *blake3::hash(&issuer_pk).as_bytes();
        let cred = ZkKycCredential {
            holder_id_commitment: [0x11u8; 32],
            issuer_pubkey: issuer_pk,
            expiry_epoch: expiry,
            properties: props,
            issuer_signature: vec![0u8; 64],
        };
        (cred, issuer_hash)
    }

    #[test]
    fn test_kyc_valid_credential() {
        let (cred, issuer_hash) = make_credential(100, vec![ComplianceProperty::NotSanctioned]);
        let result = verify_credential_properties(
            &cred,
            50,
            &ComplianceProperty::NotSanctioned,
            &[issuer_hash],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_kyc_expired_credential() {
        let (cred, issuer_hash) = make_credential(50, vec![ComplianceProperty::NotSanctioned]);
        let err = verify_credential_properties(
            &cred,
            51,
            &ComplianceProperty::NotSanctioned,
            &[issuer_hash],
        )
        .unwrap_err();
        assert!(matches!(err, KycError::Expired { .. }));
    }

    #[test]
    fn test_kyc_unapproved_issuer() {
        let (cred, _) = make_credential(100, vec![ComplianceProperty::NotSanctioned]);
        let wrong_issuer = [0xFFu8; 32];
        let err = verify_credential_properties(
            &cred,
            50,
            &ComplianceProperty::NotSanctioned,
            &[wrong_issuer],
        )
        .unwrap_err();
        assert_eq!(err, KycError::UnapprovedIssuer);
    }

    #[test]
    fn test_kyc_missing_property() {
        let (cred, issuer_hash) = make_credential(100, vec![ComplianceProperty::NotSanctioned]);
        let err = verify_credential_properties(
            &cred,
            50,
            &ComplianceProperty::AmlScreeningPassed,
            &[issuer_hash],
        )
        .unwrap_err();
        assert!(matches!(err, KycError::MissingProperty(_)));
    }

    #[test]
    fn test_kyc_jurisdiction_property() {
        let prop = ComplianceProperty::ApprovedJurisdiction {
            jurisdiction_id: 62,
        }; // ID
        let (cred, issuer_hash) = make_credential(200, vec![prop.clone()]);
        assert!(verify_credential_properties(&cred, 100, &prop, &[issuer_hash]).is_ok());
    }

    #[test]
    fn test_commit_holder_identity_deterministic() {
        let secret = b"user_identity_secret";
        let salt = [0x42u8; 32];
        let h1 = commit_holder_identity(secret, &salt);
        let h2 = commit_holder_identity(secret, &salt);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_credential_signing_bytes_deterministic() {
        let holder = [0x01u8; 32];
        let props = vec![ComplianceProperty::NotSanctioned];
        let b1 = credential_signing_bytes(&holder, 100, &props);
        let b2 = credential_signing_bytes(&holder, 100, &props);
        assert_eq!(b1, b2);
    }
}
