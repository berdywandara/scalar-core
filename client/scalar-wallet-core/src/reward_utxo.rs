// Reward UTXO — bridge from PoU reward manifest to spendable UTXO. Spec §5.2, §13.1.
//
// Flow:
//   1. Node receives reward_amount_sscl from committed EpochRewardManifest (MC1).
//   2. Node calls build_reward_utxo() to construct a UTXO commitment.
//   3. UTXO commitment is inserted into UtxoSetSMT (spec §8.5, §16.1).
//   4. Wallet can spend the UTXO using SpendKey + ZK transfer proof.
//
// UTXO commitment formula (spec §3.4):
//   commitment = Poseidon2(
//       DOMAIN_COMMITMENT_V2 ||
//       value_sscl           ||
//       owner_pubkey         ||  // SpendKey-derived pubkey
//       secret               ||  // spending secret
//       salt                 ||  // Poseidon2(secret || DOMAIN_SALT_V1)
//   )
//
// Since Poseidon2 is in-circuit only, out-of-circuit commitment uses
// BLAKE3 as a placeholder. Production ZK proof uses Poseidon2 in-circuit.
// Hash discipline: BLAKE3 out-circuit — spec §2.1.

use blake3::Hasher;
use scalar_emission::mint_nullifier::MintNullifierSet;
use scalar_emission::EmissionError;

// ── Domain separators — spec §2.3, OSSIFIED ──────────────────────────────────

/// UTXO commitment domain separator. OSSIFIED — spec §2.3.
pub const DOMAIN_COMMITMENT_V2: &[u8] = scalar_emission::utxo_set_smt::DOMAIN_UTXO_SMT;

/// Salt derivation domain separator. OSSIFIED — spec §2.3.
pub const DOMAIN_SALT_V1: &[u8] = b"scalar_salt_v1";

// ── RewardUtxo — spendable output from PoU reward ────────────────────────────

/// A spendable UTXO produced from a PoU reward claim. Spec §5.2, §3.4.
///
/// After MC1–MC5 verification, the node constructs this UTXO and inserts
/// its commitment into the UtxoSetSMT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardUtxo {
    /// UTXO commitment = BLAKE3(DOMAIN_COMMITMENT_V2 || value || owner_pubkey
    ///                          || secret || salt). Spec §3.4.
    pub commitment: [u8; 32],
    /// Reward value in sSCL. Spec §3.1.
    pub value_sscl: u64,
    /// Epoch in which this reward was minted. Spec §5.2.
    pub epoch_id: u64,
    /// Node ID that earned this reward. Spec §5.2 MC2.
    pub node_id_full: [u8; 32],
    /// Mint nullifier — proves MC2 anti double-claim. Spec §5.2 MC2.
    pub mint_nullifier: u64,
}

// ── Salt derivation — spec §3.4 ──────────────────────────────────────────────

/// Derive UTXO salt = BLAKE3(DOMAIN_SALT_V1 || secret). Spec §3.4.
///
/// Out-of-circuit. Production ZK uses Poseidon2(secret || DOMAIN_SALT_V1).
pub fn derive_utxo_salt(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN_SALT_V1);
    hasher.update(secret);
    *hasher.finalize().as_bytes()
}

// ── UTXO commitment — spec §3.4 ──────────────────────────────────────────────

/// Compute UTXO commitment out-of-circuit (BLAKE3 placeholder). Spec §3.4.
///
/// commitment = BLAKE3(
///     DOMAIN_COMMITMENT_V2 ||
///     value_sscl_le64      ||
///     owner_pubkey         ||
///     secret               ||
///     salt                 ||
/// )
///
/// Production ZK proof uses Poseidon2 in-circuit for the same inputs.
pub fn compute_utxo_commitment(
    value_sscl: u64,
    owner_pubkey: &[u8; 32],
    secret: &[u8; 32],
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN_COMMITMENT_V2);
    hasher.update(&value_sscl.to_le_bytes());
    hasher.update(owner_pubkey);
    hasher.update(secret);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

// ── build_reward_utxo — main entry point ─────────────────────────────────────

/// Build a spendable RewardUtxo from a verified PoU reward claim. Spec §5.2.
///
/// Prerequisites (caller must ensure before calling):
///   - MC1–MC5 all verified (crypto_version, nullifier, supply cap,
///     reward validity, node authorization).
///   - reward_amount_sscl > 0.
///
/// Parameters:
///   `node_id_full`       : 32-byte node ID.
///   `epoch_id`           : epoch being claimed.
///   `reward_amount_sscl` : reward in sSCL from manifest.
///   `owner_pubkey`       : SpendKey-derived pubkey (wallet owner). Spec §13.1.
///   `spending_secret`    : per-UTXO spending secret (random, wallet-generated).
///   `nullifier_set`      : MintNullifierSet to enforce MC2 anti double-claim.
///
/// Returns RewardUtxo on success, EmissionError on double-claim or zero reward.
pub fn build_reward_utxo(
    node_id_full: &[u8; 32],
    epoch_id: u64,
    reward_amount_sscl: u64,
    owner_pubkey: &[u8; 32],
    spending_secret: &[u8; 32],
    nullifier_set: &mut MintNullifierSet,
) -> Result<RewardUtxo, EmissionError> {
    if reward_amount_sscl == 0 {
        return Err(EmissionError::ZeroTotalWeight);
    }

    // MC2: record claim — returns Err(AlreadyClaimed) on double-claim.
    let mint_nullifier = nullifier_set.record_claim(node_id_full, epoch_id)?;

    // Derive salt from spending_secret per spec §3.4.
    let salt = derive_utxo_salt(spending_secret);

    // Compute UTXO commitment.
    let commitment =
        compute_utxo_commitment(reward_amount_sscl, owner_pubkey, spending_secret, &salt);

    Ok(RewardUtxo {
        commitment,
        value_sscl: reward_amount_sscl,
        epoch_id,
        node_id_full: *node_id_full,
        mint_nullifier,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_emission::mint_nullifier::MintNullifierSet;

    fn node_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = seed;
        id
    }

    fn owner_pubkey(seed: u8) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = seed;
        pk[31] = seed;
        pk
    }

    fn spending_secret(seed: u8) -> [u8; 32] {
        let mut s = [0xFFu8; 32];
        s[0] = seed;
        s
    }

    // ── commitment tests ──────────────────────────────────────────────────────

    #[test]
    fn test_commitment_deterministic() {
        let val = 1_000_000u64;
        let pk = owner_pubkey(0x01);
        let sec = spending_secret(0x01);
        let salt = derive_utxo_salt(&sec);
        let c1 = compute_utxo_commitment(val, &pk, &sec, &salt);
        let c2 = compute_utxo_commitment(val, &pk, &sec, &salt);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_differs_by_value() {
        let pk = owner_pubkey(0x01);
        let sec = spending_secret(0x01);
        let salt = derive_utxo_salt(&sec);
        let c1 = compute_utxo_commitment(1_000_000, &pk, &sec, &salt);
        let c2 = compute_utxo_commitment(2_000_000, &pk, &sec, &salt);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_differs_by_owner() {
        let sec = spending_secret(0x01);
        let salt = derive_utxo_salt(&sec);
        let c1 = compute_utxo_commitment(1_000_000, &owner_pubkey(0x01), &sec, &salt);
        let c2 = compute_utxo_commitment(1_000_000, &owner_pubkey(0x02), &sec, &salt);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_nonzero() {
        let sec = spending_secret(0x01);
        let salt = derive_utxo_salt(&sec);
        let c = compute_utxo_commitment(100, &owner_pubkey(0x01), &sec, &salt);
        assert_ne!(c, [0u8; 32]);
    }

    #[test]
    fn test_domain_separator_commitment_ossified() {
        assert_eq!(DOMAIN_COMMITMENT_V2, b"scalar_utxo_v2");
    }

    #[test]
    fn test_domain_separator_salt_ossified() {
        assert_eq!(DOMAIN_SALT_V1, b"scalar_salt_v1");
    }

    // ── salt derivation tests ─────────────────────────────────────────────────

    #[test]
    fn test_salt_deterministic() {
        let sec = spending_secret(0x42);
        assert_eq!(derive_utxo_salt(&sec), derive_utxo_salt(&sec));
    }

    #[test]
    fn test_salt_differs_by_secret() {
        let s1 = derive_utxo_salt(&spending_secret(0x01));
        let s2 = derive_utxo_salt(&spending_secret(0x02));
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_salt_nonzero() {
        assert_ne!(derive_utxo_salt(&[0u8; 32]), [0u8; 32]);
    }

    // ── build_reward_utxo tests ───────────────────────────────────────────────

    #[test]
    fn test_build_reward_utxo_success() {
        let mut ns = MintNullifierSet::new();
        let utxo = build_reward_utxo(
            &node_id(0x01),
            5,
            1_000_000,
            &owner_pubkey(0x01),
            &spending_secret(0x01),
            &mut ns,
        );
        assert!(utxo.is_ok());
        let u = utxo.unwrap();
        assert_eq!(u.value_sscl, 1_000_000);
        assert_eq!(u.epoch_id, 5);
        assert_eq!(u.node_id_full, node_id(0x01));
        assert_ne!(u.commitment, [0u8; 32]);
    }

    #[test]
    fn test_build_reward_utxo_double_claim_rejected() {
        let mut ns = MintNullifierSet::new();
        let sec = spending_secret(0x01);
        build_reward_utxo(
            &node_id(0x01),
            5,
            1_000_000,
            &owner_pubkey(0x01),
            &sec,
            &mut ns,
        )
        .unwrap();
        let result = build_reward_utxo(
            &node_id(0x01),
            5,
            1_000_000,
            &owner_pubkey(0x01),
            &sec,
            &mut ns,
        );
        assert!(
            matches!(result, Err(EmissionError::AlreadyClaimed { epoch_id: 5 })),
            "Double claim must be rejected"
        );
    }

    #[test]
    fn test_build_reward_utxo_different_epochs_allowed() {
        let mut ns = MintNullifierSet::new();
        let sec = spending_secret(0x01);
        let pk = owner_pubkey(0x01);
        assert!(build_reward_utxo(&node_id(0x01), 1, 500_000, &pk, &sec, &mut ns).is_ok());
        assert!(build_reward_utxo(&node_id(0x01), 2, 500_000, &pk, &sec, &mut ns).is_ok());
    }

    #[test]
    fn test_build_reward_utxo_zero_reward_rejected() {
        let mut ns = MintNullifierSet::new();
        let result = build_reward_utxo(
            &node_id(0x01),
            1,
            0,
            &owner_pubkey(0x01),
            &spending_secret(0x01),
            &mut ns,
        );
        assert!(result.is_err(), "Zero reward must be rejected");
    }

    #[test]
    fn test_build_reward_utxo_commitment_unique_per_secret() {
        // Different spending_secret → different commitment (fungibility).
        let mut ns = MintNullifierSet::new();
        let pk = owner_pubkey(0x01);
        let u1 = build_reward_utxo(
            &node_id(0x01),
            1,
            500_000,
            &pk,
            &spending_secret(0x01),
            &mut ns,
        )
        .unwrap();
        let u2 = build_reward_utxo(
            &node_id(0x02),
            1,
            500_000,
            &pk,
            &spending_secret(0x02),
            &mut ns,
        )
        .unwrap();
        assert_ne!(
            u1.commitment, u2.commitment,
            "Different secrets must produce different commitments"
        );
    }

    #[test]
    fn test_nullifier_recorded_after_build() {
        let mut ns = MintNullifierSet::new();
        assert!(!ns.is_claimed(&node_id(0x05), 10));
        build_reward_utxo(
            &node_id(0x05),
            10,
            100_000,
            &owner_pubkey(0x01),
            &spending_secret(0x01),
            &mut ns,
        )
        .unwrap();
        assert!(ns.is_claimed(&node_id(0x05), 10));
    }
}
