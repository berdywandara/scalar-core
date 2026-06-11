//! GovernanceID keypair primitive — SLH-DSA-SHAKE-128s (FIPS 205).
//!
//! Spec (OSSIFIED): SCALAR-PROTOCOL §11.1, §13.1; SCALAR-SECURITY §5.3 (KAT).
//!
//!   GovernanceID_seed = BLAKE3(AccountKey || "governance")
//!   kg_randomness     = BLAKE3-XOF[derive_key](context, GovernanceID_seed)[0..48]
//!   SK.seed = kg[0..16] ; SK.prf = kg[16..32] ; PK.seed = kg[32..48]
//!   (GovernanceID_pub, _priv) = SLH-DSA-SHAKE-128s.KeyGen(SK.seed, SK.prf, PK.seed)
//!
//! Draw order SK.seed -> SK.prf -> PK.seed verified against fips205 v0.4.1 source.
//! Single source of truth for the full AccountKey -> GovernanceID keypair derivation.
//! Sign/verify helpers and C1-BIND wiring are tracked separately (G-24).

use blake3::Hasher;
use fips205::slh_dsa_shake_128s::{try_keygen_with_rng, PK_LEN, SK_LEN};
use fips205::traits::SerDes;
use rand_core_06::{CryptoRng, Error, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// OSSIFIED context string — Zero-Versioning Policy: NO version suffix.
pub const GOVERNANCE_KEYGEN_CONTEXT: &str = "scalar.governance.slhdsa-shake-128s.keygen";
/// OSSIFIED domain separator for GovernanceID_seed = BLAKE3(AccountKey || "governance").
/// Spec: SCALAR-PROTOCOL §11.1/§13.1.
pub const GOVERNANCE_SEED_DOMAIN: &[u8] = b"governance";
/// SLH-DSA-SHAKE-128s public-key length (GovernanceID_pub). FIPS 205.
pub const GOVERNANCE_PUB_LEN: usize = 32;
/// SLH-DSA-SHAKE-128s secret-key length. FIPS 205.
pub const GOVERNANCE_SEC_LEN: usize = 64;
const _: () = assert!(
    GOVERNANCE_PUB_LEN == PK_LEN,
    "PK_LEN must be 32 (SLH-DSA-SHAKE-128s)"
);
const _: () = assert!(
    GOVERNANCE_SEC_LEN == SK_LEN,
    "SK_LEN must be 64 (SLH-DSA-SHAKE-128s)"
);

/// Deterministic RNG yielding exactly kg_randomness[0..48], in order.
struct FixedRng {
    buf: [u8; 48],
    pos: usize,
}
impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for x in dest.iter_mut() {
            *x = self.buf[self.pos];
            self.pos += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for FixedRng {}

/// Expand GovernanceID_seed (32B) -> 48B keygen randomness via BLAKE3-XOF (derive_key mode).
fn kg_randomness(gov_seed: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut h = Hasher::new_derive_key(GOVERNANCE_KEYGEN_CONTEXT);
    h.update(gov_seed);
    h.finalize_xof().fill(&mut out);
    out
}

/// GovernanceID secret key (cold). Zeroized on drop; intentionally NOT `Clone`
/// so a high-value cold key cannot be copied freely in memory. For signing,
/// borrow via `as_bytes()` or move the wrapper (move semantics).
pub struct GovernanceSecret([u8; GOVERNANCE_SEC_LEN]);

impl GovernanceSecret {
    /// Borrow the raw secret-key bytes (e.g. for signing). Does not copy them out.
    pub fn as_bytes(&self) -> &[u8; GOVERNANCE_SEC_LEN] {
        &self.0
    }
}

// Manual Zeroize / ZeroizeOnDrop (avoids relying on the derive-macro feature).
impl Zeroize for GovernanceSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for GovernanceSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for GovernanceSecret {}

/// GovernanceID keypair. `public` is GovernanceID_pub (C1-BIND); `secret` is a
/// zeroize-on-drop wrapper. NOT `Clone` — borrow `&keypair.secret` or move it.
pub struct GovernanceKeypair {
    /// SLH-DSA public key — GovernanceID_pub, bound by C1-BIND.
    pub public: [u8; GOVERNANCE_PUB_LEN],
    /// SLH-DSA secret key (cold), zeroized on drop.
    pub secret: GovernanceSecret,
}

/// Derive the GovernanceID SLH-DSA keypair from GovernanceID_seed.
pub fn governance_keypair_from_seed(gov_seed: &[u8; 32]) -> GovernanceKeypair {
    let mut rng = FixedRng {
        buf: kg_randomness(gov_seed),
        pos: 0,
    };
    // Public API returns (PublicKey, PrivateKey).
    let (pk, sk) = try_keygen_with_rng(&mut rng)
        .expect("fips205 keygen from a full fixed buffer is infallible");
    GovernanceKeypair {
        public: pk.into_bytes(),
        secret: GovernanceSecret(sk.into_bytes()),
    }
}

/// GovernanceID_seed = BLAKE3(AccountKey || "governance"). Spec §11.1 (OSSIFIED).
fn governance_seed_from_account_key(account_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(account_key);
    h.update(GOVERNANCE_SEED_DOMAIN);
    *h.finalize().as_bytes()
}

/// Derive the GovernanceID keypair directly from AccountKey — the full OSSIFIED
/// construction and single source of truth. Spec §11.1/§13.1.
pub fn governance_keypair_from_account_key(account_key: &[u8; 32]) -> GovernanceKeypair {
    governance_keypair_from_seed(&governance_seed_from_account_key(account_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KAT_SEED: [u8; 32] = [0x42u8; 32];
    // OSSIFIED KAT — SCALAR-PROTOCOL §11.1, SCALAR-SECURITY §5.3.
    // GovernanceID_seed = 0x42 x 32  =>  GovernanceID_pub = cf35fc52...be7fed08
    const KAT_PUB: [u8; 32] = [
        0xcf, 0x35, 0xfc, 0x52, 0x6b, 0x3e, 0x20, 0x0c, 0xdc, 0x7d, 0x9e, 0xba, 0xce, 0xc1, 0x96,
        0xad, 0x09, 0x43, 0xb1, 0xc5, 0xa4, 0xd2, 0xf0, 0x24, 0x64, 0x11, 0x73, 0xf1, 0xbe, 0x7f,
        0xed, 0x08,
    ];

    #[test]
    fn test_context_is_zero_versioned() {
        assert_eq!(
            GOVERNANCE_KEYGEN_CONTEXT,
            "scalar.governance.slhdsa-shake-128s.keygen"
        );
        assert!(!GOVERNANCE_KEYGEN_CONTEXT.contains(".v"));
    }

    #[test]
    fn test_governance_seed_domain_ossified() {
        assert_eq!(GOVERNANCE_SEED_DOMAIN, b"governance");
    }

    #[test]
    fn test_governance_keypair_kat() {
        let kp = governance_keypair_from_seed(&KAT_SEED);
        assert_eq!(kp.public, KAT_PUB, "GovernanceID_pub KAT mismatch");
    }

    #[test]
    fn test_governance_keypair_deterministic() {
        let a = governance_keypair_from_seed(&KAT_SEED);
        let b = governance_keypair_from_seed(&KAT_SEED);
        assert_eq!(a.public, b.public);
        assert_eq!(a.secret.as_bytes(), b.secret.as_bytes());
    }

    #[test]
    fn test_governance_different_seed_different_pub() {
        let a = governance_keypair_from_seed(&[0x42u8; 32]);
        let b = governance_keypair_from_seed(&[0x43u8; 32]);
        assert_ne!(a.public, b.public);
    }

    #[test]
    fn test_from_account_key_matches_two_step() {
        // from_account_key == BLAKE3(account_key || "governance") then from_seed.
        let ak = [0x07u8; 32];
        let direct = governance_keypair_from_account_key(&ak);
        let mut h = Hasher::new();
        h.update(&ak);
        h.update(GOVERNANCE_SEED_DOMAIN);
        let seed = *h.finalize().as_bytes();
        let two_step = governance_keypair_from_seed(&seed);
        assert_eq!(direct.public, two_step.public);
        assert_eq!(direct.secret.as_bytes(), two_step.secret.as_bytes());
    }
}
