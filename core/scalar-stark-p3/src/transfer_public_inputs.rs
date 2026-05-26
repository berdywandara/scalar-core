//! Transfer Circuit Public Inputs — Plonky3 format. P3-R4a.
//!
//! Converts TransferPublicInputs (scalar-stark) into Goldilocks field elements
//! for use as public_values in p3-uni-stark prove/verify calls.
//!
//! Spec §4.2: Public inputs for Transfer Circuit CA-CG.
//! Field: Goldilocks (p = 2^64 - 2^32 + 1). OSSIFIED — spec §4.4.
//!
//! Public input layout (indices, OSSIFIED):
//!   [0]     fee_total_sscl          (CD)
//!   [1]     sum_inputs_sscl         (CD)
//!   [2]     sum_outputs_sscl        (CD)
//!   [3]     crypto_version          (CG)
//!   [4]     entry_timestamp_ms_lo   (CG) — lower 32 bits
//!   [5]     entry_timestamp_ms_hi   (CG) — upper 32 bits
//!   [6]     current_timestamp_ms_lo (CG)
//!   [7]     current_timestamp_ms_hi (CG)
//!   [8..15] utxo_set_root           (CB) — 8x u32 LE chunks as field elements
//!   [16]    cb_membership_verified  (CB) — 0 or 1
//!   [17..24] nullifier_active_root  (CC) — 8x u32 LE chunks
//!   [25..32] nullifier_archived_root(CC) — 8x u32 LE chunks
//!   [33]    cc_nonmembership_verified (CC) — 0 or 1
//!   [34]    output_nonzero          (CE) — 0 or 1
//!   [35]    single_utxo_source      (INV-4.6) — 0 or 1

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;

/// Total number of public input field elements for Transfer Circuit. OSSIFIED.
pub const TRANSFER_PI_LEN: usize = 36;

/// T_MAX_WAIT = 30 minutes in ms. OSSIFIED — spec §4.3 CG.
pub const T_MAX_WAIT_MS: u64 = 30 * 60 * 1_000;

/// Valid crypto versions. OSSIFIED — spec §4.3 CG.
pub const VALID_CRYPTO_VERSION: u8 = 0x01;

/// Fee floor in sSCL. OSSIFIED — spec §9.1.
pub const FEE_FLOOR_SSCL: u64 = 40;

// ── TransferPublicInputsP3 ────────────────────────────────────────────────────

/// Transfer Circuit public inputs in a format suitable for Plonky3.
/// Maps to/from Goldilocks field element vectors for p3-uni-stark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPublicInputsP3 {
    /// CD: fee total in sSCL. Spec §4.2.
    pub fee_total_sscl: u64,
    /// CD: sum of input values. Spec §4.3 CD.
    pub sum_inputs_sscl: u64,
    /// CD: sum of output values. Spec §4.3 CD.
    pub sum_outputs_sscl: u64,
    /// CG: crypto version. Spec §4.2.
    pub crypto_version: u8,
    /// CG: entry timestamp (ms). Spec §4.2.
    pub entry_timestamp_ms: u64,
    /// CG: current timestamp (ms). Spec §4.2.
    pub current_timestamp_ms: u64,
    /// CB: UTXO set root (snapshot epoch k-1). Spec §4.2, §8.5.
    pub utxo_set_root: [u8; 32],
    /// CB: membership verified out-of-circuit. Spec §4.3 CB.
    pub cb_membership_verified: bool,
    /// CC: NullifierSet active root. Spec §4.2.
    pub nullifier_active_root: [u8; 32],
    /// CC: NullifierSet archived root. Spec §4.2.
    pub nullifier_archived_root: [u8; 32],
    /// CC: dual non-membership verified out-of-circuit. Spec §4.3 CC.
    pub cc_nonmembership_verified: bool,
    /// CE: first output commitment non-zero. Spec §4.3 CE.
    pub output_nonzero: bool,
    /// INV-4.6: exactly one UTXO source active. Spec §3.1.3.
    pub single_utxo_source: bool,
}

impl TransferPublicInputsP3 {
    /// Serialize to Goldilocks field elements for p3-uni-stark public_values.
    /// Layout is OSSIFIED — indices must not change. See module doc.
    pub fn to_goldilocks(&self) -> Vec<Goldilocks> {
        let mut v = Vec::with_capacity(TRANSFER_PI_LEN);

        // [0..2] CD: value conservation
        v.push(Goldilocks::new(self.fee_total_sscl));
        v.push(Goldilocks::new(self.sum_inputs_sscl));
        v.push(Goldilocks::new(self.sum_outputs_sscl));

        // [3] CG: crypto version
        v.push(Goldilocks::new(self.crypto_version as u64));

        // [4..7] CG: timestamps (split into lo/hi u32 to fit Goldilocks)
        v.push(Goldilocks::new(self.entry_timestamp_ms & 0xFFFF_FFFF));
        v.push(Goldilocks::new(self.entry_timestamp_ms >> 32));
        v.push(Goldilocks::new(self.current_timestamp_ms & 0xFFFF_FFFF));
        v.push(Goldilocks::new(self.current_timestamp_ms >> 32));

        // [8..15] CB: utxo_set_root as 8 x u32 LE chunks
        push_bytes32(&mut v, &self.utxo_set_root);

        // [16] CB: membership verified flag
        v.push(Goldilocks::new(self.cb_membership_verified as u64));

        // [17..24] CC: nullifier_active_root
        push_bytes32(&mut v, &self.nullifier_active_root);

        // [25..32] CC: nullifier_archived_root
        push_bytes32(&mut v, &self.nullifier_archived_root);

        // [33] CC: non-membership verified flag
        v.push(Goldilocks::new(self.cc_nonmembership_verified as u64));

        // [34] CE: output non-zero flag
        v.push(Goldilocks::new(self.output_nonzero as u64));

        // [35] INV-4.6: single UTXO source flag
        v.push(Goldilocks::new(self.single_utxo_source as u64));

        debug_assert_eq!(v.len(), TRANSFER_PI_LEN);
        v
    }

    /// Deserialize from Goldilocks field elements. Inverse of to_goldilocks().
    pub fn from_goldilocks(v: &[Goldilocks]) -> Option<Self> {
        if v.len() < TRANSFER_PI_LEN {
            return None;
        }

        let entry_ts = v[4].as_canonical_u64() | (v[5].as_canonical_u64() << 32);
        let current_ts = v[6].as_canonical_u64() | (v[7].as_canonical_u64() << 32);

        Some(Self {
            fee_total_sscl: v[0].as_canonical_u64(),
            sum_inputs_sscl: v[1].as_canonical_u64(),
            sum_outputs_sscl: v[2].as_canonical_u64(),
            crypto_version: v[3].as_canonical_u64() as u8,
            entry_timestamp_ms: entry_ts,
            current_timestamp_ms: current_ts,
            utxo_set_root: read_bytes32(&v[8..16]),
            cb_membership_verified: v[16].as_canonical_u64() != 0,
            nullifier_active_root: read_bytes32(&v[17..25]),
            nullifier_archived_root: read_bytes32(&v[25..33]),
            cc_nonmembership_verified: v[33].as_canonical_u64() != 0,
            output_nonzero: v[34].as_canonical_u64() != 0,
            single_utxo_source: v[35].as_canonical_u64() != 0,
        })
    }
}

/// Push 32 bytes as 8 Goldilocks field elements (4 bytes each, LE). OSSIFIED layout.
fn push_bytes32(v: &mut Vec<Goldilocks>, bytes: &[u8; 32]) {
    for chunk in bytes.chunks(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap()) as u64;
        v.push(Goldilocks::new(val));
    }
}

/// Read 8 Goldilocks field elements back into 32 bytes. Inverse of push_bytes32.
fn read_bytes32(v: &[Goldilocks]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, fe) in v.iter().take(8).enumerate() {
        let val = fe.as_canonical_u64() as u32;
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    out
}

// ── Constraint checkers — used by Transfer AIR eval() ────────────────────────

/// CD: value conservation. sum_inputs == sum_outputs + fee. Spec §4.3 CD.
pub fn check_cd_conservation(pi: &TransferPublicInputsP3) -> bool {
    pi.sum_inputs_sscl == pi.sum_outputs_sscl.saturating_add(pi.fee_total_sscl)
}

/// CD: fee floor. fee >= FEE_FLOOR_SSCL. Spec §9.1.
pub fn check_cd_fee_floor(pi: &TransferPublicInputsP3) -> bool {
    pi.fee_total_sscl >= FEE_FLOOR_SSCL
}

/// CG: crypto version valid. Spec §4.3 CG.
pub fn check_cg_version(pi: &TransferPublicInputsP3) -> bool {
    pi.crypto_version == VALID_CRYPTO_VERSION
}

/// CG: transaction within T_MAX_WAIT window. Spec §4.3 CG.
pub fn check_cg_timestamp(pi: &TransferPublicInputsP3) -> bool {
    if pi.current_timestamp_ms < pi.entry_timestamp_ms {
        return false;
    }
    (pi.current_timestamp_ms - pi.entry_timestamp_ms) <= T_MAX_WAIT_MS
}

/// CE: output commitment non-zero. Spec §4.3 CE.
pub fn check_ce_output_nonzero(pi: &TransferPublicInputsP3) -> bool {
    pi.output_nonzero
}

/// INV-4.6: exactly one UTXO source. Spec §3.1.3.
pub fn check_inv46_single_source(pi: &TransferPublicInputsP3) -> bool {
    pi.single_utxo_source
}

/// CB: membership verified. Spec §4.3 CB.
pub fn check_cb_membership(pi: &TransferPublicInputsP3) -> bool {
    pi.cb_membership_verified
}

/// CC: dual non-membership verified. Spec §4.3 CC.
pub fn check_cc_nonmembership(pi: &TransferPublicInputsP3) -> bool {
    pi.cc_nonmembership_verified
}

/// Run all constraint checks. Returns index of first failing constraint, or Ok.
/// Used as pre-flight before proving (defense-in-depth).
/// Constraints are evaluated by the AIR; this is a fast error-reporting layer.
pub fn check_all_constraints(pi: &TransferPublicInputsP3) -> Result<(), usize> {
    if !check_cd_conservation(pi) {
        return Err(0);
    }
    if !check_cd_fee_floor(pi) {
        return Err(1);
    }
    if !check_cg_version(pi) {
        return Err(2);
    }
    if !check_cg_timestamp(pi) {
        return Err(3);
    }
    if !check_cb_membership(pi) {
        return Err(4);
    }
    if !check_cc_nonmembership(pi) {
        return Err(5);
    }
    if !check_ce_output_nonzero(pi) {
        return Err(6);
    }
    if !check_inv46_single_source(pi) {
        return Err(7);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_pi() -> TransferPublicInputsP3 {
        TransferPublicInputsP3 {
            fee_total_sscl: 40,
            sum_inputs_sscl: 1_000_000_040,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0xAAu8; 32],
            nullifier_archived_root: [0xBBu8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
        }
    }

    #[test]
    fn test_pi_len_ossified() {
        assert_eq!(TRANSFER_PI_LEN, 36);
    }

    #[test]
    fn test_to_goldilocks_len() {
        let pi = valid_pi();
        let v = pi.to_goldilocks();
        assert_eq!(v.len(), TRANSFER_PI_LEN);
    }

    #[test]
    fn test_roundtrip_to_from_goldilocks() {
        // Serialization roundtrip must be lossless.
        let pi = valid_pi();
        let v = pi.to_goldilocks();
        let pi2 = TransferPublicInputsP3::from_goldilocks(&v).unwrap();
        assert_eq!(pi, pi2, "roundtrip must be lossless");
    }

    #[test]
    fn test_roundtrip_zero_roots() {
        let mut pi = valid_pi();
        pi.utxo_set_root = [0u8; 32];
        pi.nullifier_active_root = [0u8; 32];
        pi.nullifier_archived_root = [0u8; 32];
        let v = pi.to_goldilocks();
        let pi2 = TransferPublicInputsP3::from_goldilocks(&v).unwrap();
        assert_eq!(pi, pi2);
    }

    #[test]
    fn test_check_cd_conservation_valid() {
        assert!(check_cd_conservation(&valid_pi()));
    }

    #[test]
    fn test_check_cd_conservation_invalid() {
        let mut pi = valid_pi();
        pi.sum_inputs_sscl = 500; // doesn't balance
        assert!(!check_cd_conservation(&pi));
    }

    #[test]
    fn test_check_cd_fee_floor_valid() {
        assert!(check_cd_fee_floor(&valid_pi()));
    }

    #[test]
    fn test_check_cd_fee_floor_invalid() {
        let mut pi = valid_pi();
        pi.fee_total_sscl = 10; // below floor
        assert!(!check_cd_fee_floor(&pi));
    }

    #[test]
    fn test_check_cg_version_valid() {
        assert!(check_cg_version(&valid_pi()));
    }

    #[test]
    fn test_check_cg_version_invalid() {
        let mut pi = valid_pi();
        pi.crypto_version = 0xFF;
        assert!(!check_cg_version(&pi));
    }

    #[test]
    fn test_check_cg_timestamp_valid() {
        assert!(check_cg_timestamp(&valid_pi()));
    }

    #[test]
    fn test_check_cg_timestamp_expired() {
        let mut pi = valid_pi();
        pi.current_timestamp_ms = pi.entry_timestamp_ms + T_MAX_WAIT_MS + 1;
        assert!(!check_cg_timestamp(&pi));
    }

    #[test]
    fn test_check_all_constraints_valid() {
        assert!(check_all_constraints(&valid_pi()).is_ok());
    }

    #[test]
    fn test_check_all_constraints_cd_fail() {
        let mut pi = valid_pi();
        pi.sum_inputs_sscl = 0;
        assert_eq!(check_all_constraints(&pi), Err(0)); // conservation
    }

    #[test]
    fn test_check_all_constraints_fee_floor_fail() {
        let mut pi = valid_pi();
        pi.fee_total_sscl = 10;
        pi.sum_inputs_sscl = pi.sum_outputs_sscl + 10; // keep conservation valid
        assert_eq!(check_all_constraints(&pi), Err(1)); // fee floor
    }

    #[test]
    fn test_from_goldilocks_too_short() {
        let v = vec![Goldilocks::new(0); 10];
        assert!(TransferPublicInputsP3::from_goldilocks(&v).is_none());
    }

    #[test]
    fn test_t_max_wait_ossified() {
        assert_eq!(T_MAX_WAIT_MS, 1_800_000);
    }

    #[test]
    fn test_fee_floor_ossified() {
        assert_eq!(FEE_FLOOR_SSCL, 40);
    }
}
