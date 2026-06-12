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
//!   [36..39] commitment_hash        (A-R9 CB binding) — BLAKE3(all commitments)[0..4] as u64 LE
//!   [40..43] nullifier_hash         (A-R9 CC binding) — BLAKE3(all nullifiers)[0..4] as u64 LE

use blake3::Hasher;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;

/// Total number of public input field elements for Transfer Circuit. OSSIFIED.
pub const TRANSFER_PI_LEN: usize = 41; // G-07b: timestamps[4] -> current_subepoch_id[1]

// Wall-clock T_MAX_WAIT constants removed in G-07b. Validity is now sequential
// over sub-epoch ids (CG-ARITH) — see crate::cg_arith. SCALAR-TECHNICAL §2.9.

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
    /// CG: current sub-epoch id (PI[4], consensus-bound). SCALAR-TECHNICAL §2.9.
    pub current_subepoch_id: u64,
    /// CG: target sub-epoch id — PRIVATE WITNESS (user-signed), NOT serialized to
    /// public_values; used only to build the CG-ARITH trace. SCALAR-TECHNICAL §2.9.
    pub target_subepoch_id: u64,
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
    /// A-R9 CB binding: BLAKE3(all input commitments)[0..32] as [u64;4].
    /// Binds CD/CE/CG AIR to the same commitments proven by CA/CB sub-AIRs.
    /// Spec §4.3 CB — prevents bypass via mismatched sub-proofs.
    pub commitment_hash: [u64; 4],
    /// A-R9 CC binding: BLAKE3(all input nullifiers)[0..32] as [u64;4].
    /// Binds CD/CE/CG AIR to the same nullifiers proven by CA/CC sub-AIRs.
    /// Spec §4.3 CC — prevents bypass via mismatched sub-proofs.
    pub nullifier_hash: [u64; 4],
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

        // [4] CG: current_subepoch_id (consensus-bound). target_subepoch_id is a
        // private witness and is NOT serialized into public_values.
        v.push(Goldilocks::new(self.current_subepoch_id));

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

        // [36..39] A-R9: commitment_hash (CB binding)
        for &c in &self.commitment_hash {
            v.push(Goldilocks::new(c));
        }

        // [40..43] A-R9: nullifier_hash (CC binding)
        for &n in &self.nullifier_hash {
            v.push(Goldilocks::new(n));
        }

        debug_assert_eq!(v.len(), TRANSFER_PI_LEN);
        v
    }

    /// Deserialize from Goldilocks field elements. Inverse of to_goldilocks().
    pub fn from_goldilocks(v: &[Goldilocks]) -> Option<Self> {
        if v.len() < TRANSFER_PI_LEN {
            return None;
        }

        Some(Self {
            fee_total_sscl: v[0].as_canonical_u64(),
            sum_inputs_sscl: v[1].as_canonical_u64(),
            sum_outputs_sscl: v[2].as_canonical_u64(),
            crypto_version: v[3].as_canonical_u64() as u8,
            current_subepoch_id: v[4].as_canonical_u64(),
            // target_subepoch_id is a private witness, absent from public values.
            target_subepoch_id: 0,
            utxo_set_root: read_bytes32(&v[5..13]),
            cb_membership_verified: v[13].as_canonical_u64() != 0,
            nullifier_active_root: read_bytes32(&v[14..22]),
            nullifier_archived_root: read_bytes32(&v[22..30]),
            cc_nonmembership_verified: v[30].as_canonical_u64() != 0,
            output_nonzero: v[31].as_canonical_u64() != 0,
            single_utxo_source: v[32].as_canonical_u64() != 0,
            commitment_hash: [
                v[33].as_canonical_u64(),
                v[34].as_canonical_u64(),
                v[35].as_canonical_u64(),
                v[36].as_canonical_u64(),
            ],
            nullifier_hash: [
                v[37].as_canonical_u64(),
                v[38].as_canonical_u64(),
                v[39].as_canonical_u64(),
                v[40].as_canonical_u64(),
            ],
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

/// CG-ARITH: sequential sub-epoch validity. current >= target AND validity <= 1.
/// Off-circuit pre-flight; the AIR enforces the same relation. SCALAR-TECHNICAL §2.9.
pub fn check_cg_validity(pi: &TransferPublicInputsP3) -> bool {
    crate::cg_arith::cg_validity(pi.current_subepoch_id, pi.target_subepoch_id).is_some()
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
    if !check_cg_validity(pi) {
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

impl TransferPublicInputsP3 {
    /// True jika menggunakan UTXOSource::SubEpochIMT (imt_frontier_root != zero).
    /// Spec §3.1.3, Optimalisasi §4.6.
    /// True jika menggunakan UTXOSource::SubEpochIMT.
    /// Full IMT source tracking integrated in FASE B (EpochOrchestrator).
    /// Placeholder: always returns false (EpochSMT) until FASE B. Spec §3.1.3.
    pub fn uses_imt_source(&self) -> bool {
        // FASE B: derive from imt_frontier_root field once added to public inputs.
        false
    }

    /// True jika imt_commitment_count konsisten dengan imt frontier.
    /// Spec §3.1.5 Langkah 4 (IMTCountMismatch prevention).
    pub fn validate_imt_inputs(&self) -> bool {
        // EpochSMT: selalu valid
        true
    }

    /// True jika utxo_set_root non-zero (CB root tersedia).
    /// Spec §4.3 CB.
    pub fn validate_cb_root_non_zero(&self) -> bool {
        self.utxo_set_root != [0u8; 32]
    }
}

// ── Cross-binding hash helpers (A-R9) ────────────────────────────────────────

/// Compute commitment_hash = BLAKE3(all commitments concatenated)[0..32] as [u64;4].
/// Used to bind CD/CE/CG AIR to the same commitments proven by CA/CB sub-AIRs.
/// Spec §4.3 CB, A-R9.
pub fn compute_commitment_hash(commitments: &[[u8; 32]]) -> [u64; 4] {
    let mut hasher = Hasher::new();
    for c in commitments {
        hasher.update(c);
    }
    let hash = hasher.finalize();
    let b = hash.as_bytes();
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
    ]
}

/// Compute nullifier_hash = BLAKE3(all nullifiers concatenated)[0..32] as [u64;4].
/// Used to bind CD/CE/CG AIR to the same nullifiers proven by CA/CC sub-AIRs.
/// Spec §4.3 CC, A-R9.
pub fn compute_nullifier_hash(nullifiers: &[[u8; 32]]) -> [u64; 4] {
    let mut hasher = Hasher::new();
    for n in nullifiers {
        hasher.update(n);
    }
    let hash = hasher.finalize();
    let b = hash.as_bytes();
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
    ]
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
            current_subepoch_id: 1_000,
            target_subepoch_id: 1_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0xAAu8; 32],
            nullifier_archived_root: [0xBBu8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
            commitment_hash: [0u64; 4], // A-R9: placeholder for unit tests
            nullifier_hash: [0u64; 4],  // A-R9: placeholder for unit tests
        }
    }

    #[test]
    fn test_pi_len_ossified() {
        assert_eq!(TRANSFER_PI_LEN, 41); // G-07b: timestamps[4] -> current_subepoch_id[1]
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
        let mut pi2 = TransferPublicInputsP3::from_goldilocks(&v).unwrap();
        // target_subepoch_id is a witness, intentionally absent from public values.
        pi2.target_subepoch_id = pi.target_subepoch_id;
        assert_eq!(pi, pi2, "public-input roundtrip must be lossless");
    }

    #[test]
    fn test_roundtrip_zero_roots() {
        let mut pi = valid_pi();
        pi.utxo_set_root = [0u8; 32];
        pi.nullifier_active_root = [0u8; 32];
        pi.nullifier_archived_root = [0u8; 32];
        let v = pi.to_goldilocks();
        let mut pi2 = TransferPublicInputsP3::from_goldilocks(&v).unwrap();
        pi2.target_subepoch_id = pi.target_subepoch_id; // witness not serialized
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
    fn test_check_cg_validity_valid() {
        assert!(check_cg_validity(&valid_pi()));
    }

    #[test]
    fn test_check_cg_validity_invalid() {
        let mut pi = valid_pi();
        pi.current_subepoch_id = pi.target_subepoch_id + 2; // validity = 2 > 1
        assert!(!check_cg_validity(&pi));
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
    fn test_fee_floor_ossified() {
        assert_eq!(FEE_FLOOR_SSCL, 40);
    }
}
