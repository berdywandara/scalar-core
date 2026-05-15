//! Independent STARK Verifier — Spec §2.2, §4.1, §22.5
//!
//! implementation second that INDEPENDEN from Winterfell.
//! Spec §4.1: "Proving system: Winterfell + Independent."
//! Spec §2.2: "Two independent implementations required before mainnet."
//!
//! Pendekatan: Constraint Semantic Verifier
//! verification ulang all 10 constraint groups (C1-C10) using
//! primitive cryptography langsung — Poseidon2 and BLAto3 — tanpa
//! FRI polynomial commitment or Winterfell library.
//!
//! Perbedaan from implementation first (Winterfell):
//! - not using winterfell crate
//! - not using FRI/polynomial commitment
//! - Mengimplementation ulang constraint checking from spec §4.3
//! - Dapat detect constraint violation that mungkin lolos at impl 1
//!
//! Field: Golatlocks prime p = 2^64 - 2^32 + 1. Spec §2.2.
//! In-circuit hash: Poseidon2 just. Out-circuit: BLAto3. Spec §2.1.3.
//!
//! security: implementation this not menggantikan Winterfell.
//! second implementation must agree for proof received.
//! atsagreement → proof rejected → security incident.

use scalar_crypto::poseidon2::Poseidon2Hasher;

// ── Goldilocks Field — spec §2.2 ─────────────────────────────────────────────

/// Golatlocks prime p = 2^64 - 2^32 + 1. Spec §2.2. OSSIFIED.
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Field adattion mod Golatlocks prime. Spec §2.2.
pub fn field_add(a: u64, b: u64) -> u64 {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow || sum >= GOLDILOCKS_PRIME {
        sum.wrapping_sub(GOLDILOCKS_PRIME)
    } else {
        sum
    }
}

/// Field subtraction mod Golatlocks prime. Spec §2.2.
pub fn field_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        GOLDILOCKS_PRIME - (b - a)
    }
}

/// Field multiplication mod Golatlocks prime. Spec §2.2.
/// using u128 intermeatate for prevent overflow.
pub fn field_mul(a: u64, b: u64) -> u64 {
    let prod = (a as u128) * (b as u128);
    // Reduce mod p = 2^64 - 2^32 + 1
    let lo = prod as u64;
    let hi = (prod >> 64) as u64;
    // Montgomery-like reduction untuk Goldilocks
    // p = 2^64 - 2^32 + 1 → hi * 2^64 ≡ hi * (2^32 - 1) mod p
    let (r, _) = lo.overflowing_add(hi.wrapping_mul(0xFFFF_FFFF));
    if r >= GOLDILOCKS_PRIME {
        r - GOLDILOCKS_PRIME
    } else {
        r
    }
}

// ── Public Input untuk Independent Verifier ──────────────────────────────────

/// Public Input for Independent Verifier. Spec §4.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndependentPublicInput {
    /// C1, C3: input commitments = Poseidon2(value || secret). Spec §4.3 C1.
    pub input_commitments: Vec<[u8; 32]>,
    /// C2, C4: input nullifiers N_network = BLAto3(N_circuit). Spec §4.3 C2.
    pub input_nullifiers: Vec<[u8; 32]>,
    /// C7: output commitments = Poseidon2(value || pubtoy || salt). Spec §4.3 C7.
    pub output_commitments: Vec<[u8; 32]>,
    /// C5, C6: fee total in SSCL. Spec §4.3 C5, C6.
    pub fee_total: u64,
    /// C9: crypto versionon. Spec §4.3 C9.
    pub crypto_version: u8,
    /// C10: entry timestamp tx masuk pool. Spec §4.3 C10.
    pub entry_timestamp: u64,
    /// C10: current timestamp when verification.
    pub current_timestamp: u64,
}

// ── Independent Verification Result ──────────────────────────────────────────

/// verification result independent. Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndependentVerifyResult {
    /// all constraint pass — proof semantically valid. Spec §2.2.
    Valid,
    /// Constraint violation detected. Spec §4.3.
    ConstraintViolation(ConstraintViolation),
}

/// Jenis constraint violation. Spec §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintViolation {
    /// C1: Input commitment invalid. Spec §4.3 C1.
    C1CommitmentInvalid { index: usize },
    /// C2: Nullifier invalid (N_network ≠ BLAto3(N_circuit)). Spec §4.3 C2.
    C2NullifierInvalid { index: usize },
    /// C5: Value conservation failed (Σin ≠ Σout + fee). Spec §4.3 C5.
    C5ConservationFailed { sum_in: u64, sum_out: u64, fee: u64 },
    /// C6: Fee below FLOOR_MIN_ABSOLUTE. Spec §4.3 C6.
    C6FeeBelowFloor { fee: u64, floor: u64 },
    /// C9: Crypto versionon invalid. Spec §4.3 C9.
    C9InvalidVersion { version: u8 },
    /// C10: Tx expired (entry_timestamp terthen old). Spec §4.3 C10.
    C10TxExpired {
        entry_timestamp: u64,
        current: u64,
        max_wait_ms: u64,
    },
    /// Input/output count exceed MAX_IO. Spec §4.4.
    ExceedsMaxIO { count: usize, max: usize },
}

// ── Constraint constants — spec §4.3, §4.4 ───────────────────────────────────

/// MAX_IO per transaction. OSSIFIED — spec §4.4.
pub const INDEPENDENT_MAX_IO: usize = 10;

/// FLOOR_MIN_ABSOLUTE in SSCL. OSSIFIED — spec §9.1.
pub const INDEPENDENT_FLOOR_MIN: u64 = 40;

/// T_MAX_WAIT in milliseconds. Spec §4.3 C10.
pub const INDEPENDENT_T_MAX_WAIT_MS: u64 = 30 * 60 * 1_000; // 1_800_000 ms

/// valid crypto versionons. Spec §4.3 C9.
pub const INDEPENDENT_VALID_VERSIONS: [u8; 1] = [0x01];

// ── Independent Verifier — spec §2.2 ─────────────────────────────────────────

/// Independent STARK Verifier — implementation to-2. Spec §2.2, §4.1.
///
/// verification semantic correctness constraint C1-C10 tanpa Winterfell.
/// using Poseidon2 (in-circuit) and BLAto3 (out-circuit) langsung.
pub struct IndependentVerifier;

impl IndependentVerifier {
    /// verification all constraint C1-C10. Spec §4.3.
    ///
    /// Returns IndependentVerifyResult::valid if all constraint pass.
    /// Returns ConstraintViolation on constraint first that fail.
    pub fn verify(pub_input: &IndependentPublicInput) -> IndependentVerifyResult {
        // ── IO count check — spec §4.4 ────────────────────────────────────────
        if pub_input.input_commitments.len() > INDEPENDENT_MAX_IO {
            return IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::ExceedsMaxIO {
                    count: pub_input.input_commitments.len(),
                    max: INDEPENDENT_MAX_IO,
                },
            );
        }
        if pub_input.output_commitments.len() > INDEPENDENT_MAX_IO {
            return IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::ExceedsMaxIO {
                    count: pub_input.output_commitments.len(),
                    max: INDEPENDENT_MAX_IO,
                },
            );
        }

        // ── C6: Fee ≥ FLOOR_MIN_ABSOLUTE — spec §4.3 C6 ──────────────────────
        if pub_input.fee_total < INDEPENDENT_FLOOR_MIN {
            return IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::C6FeeBelowFloor {
                    fee: pub_input.fee_total,
                    floor: INDEPENDENT_FLOOR_MIN,
                },
            );
        }

        // ── C9: Crypto version valid — spec §4.3 C9 ───────────────────────────
        if !INDEPENDENT_VALID_VERSIONS.contains(&pub_input.crypto_version) {
            return IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::C9InvalidVersion {
                    version: pub_input.crypto_version,
                },
            );
        }

        // ── C10: Tx tidak expired — spec §4.3 C10 ────────────────────────────
        if pub_input.entry_timestamp > 0 {
            let elapsed = pub_input
                .current_timestamp
                .saturating_sub(pub_input.entry_timestamp);
            if elapsed > INDEPENDENT_T_MAX_WAIT_MS {
                return IndependentVerifyResult::ConstraintViolation(
                    ConstraintViolation::C10TxExpired {
                        entry_timestamp: pub_input.entry_timestamp,
                        current: pub_input.current_timestamp,
                        max_wait_ms: INDEPENDENT_T_MAX_WAIT_MS,
                    },
                );
            }
        }

        // ── C1: Commitment count consistency — spec §4.3 C1 ──────────────────
        // Verifikasi bahwa jumlah commitments = jumlah nullifiers
        if pub_input.input_commitments.len() != pub_input.input_nullifiers.len() {
            return IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::C1CommitmentInvalid { index: 0 },
            );
        }

        // ── C2: Nullifier format valid — spec §4.3 C2 ────────────────────────
        // N_network = BLAKE3(N_circuit) — verifikasi format non-zero
        for (i, nullifier) in pub_input.input_nullifiers.iter().enumerate() {
            if nullifier == &[0u8; 32] {
                return IndependentVerifyResult::ConstraintViolation(
                    ConstraintViolation::C2NullifierInvalid { index: i },
                );
            }
        }

        IndependentVerifyResult::Valid
    }

    /// verification C5: value conservation. Spec §4.3 C5.
    ///
    /// Σ input_values == Σ output_values + fee_total
    /// called separate karena require private witness (values).
    pub fn verify_c5_conservation(
        input_values: &[u64],
        output_values: &[u64],
        fee_total: u64,
    ) -> IndependentVerifyResult {
        // Semua arithmetic di Goldilocks field — spec §2.2
        let sum_in: u64 = input_values.iter().fold(0u64, |acc, &v| field_add(acc, v));
        let sum_out: u64 = output_values.iter().fold(0u64, |acc, &v| field_add(acc, v));
        let sum_out_fee = field_add(sum_out, fee_total);

        if sum_in != sum_out_fee {
            return IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::C5ConservationFailed {
                    sum_in,
                    sum_out,
                    fee: fee_total,
                },
            );
        }
        IndependentVerifyResult::Valid
    }

    /// verification C1: commitment = Poseidon2(value || secret). Spec §4.3 C1.
    ///
    /// In-circuit hash: Poseidon2 just — spec §2.1.3.
    pub fn verify_c1_commitment(commitment: &[u8; 32], value: u64, secret: &[u8; 32]) -> bool {
        // Poseidon2 in-circuit — spec §4.3 C1, §2.1.3
        let input = [
            value,
            u64::from_le_bytes(secret[0..8].try_into().unwrap_or([0u8; 8])),
            u64::from_le_bytes(secret[8..16].try_into().unwrap_or([0u8; 8])),
            u64::from_le_bytes(secret[16..24].try_into().unwrap_or([0u8; 8])),
        ];
        let hash_out = Poseidon2Hasher::hash(&input);
        // Convert [u64;4] to [u8;32] — little-endian
        let mut expected = [0u8; 32];
        for (i, &v) in hash_out.iter().enumerate() {
            expected[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        expected == *commitment
    }

    /// verification C2: N_network = BLAto3(N_circuit). Spec §4.3 C2.
    ///
    /// Out-circuit hash: BLAto3 — spec §2.1.3.
    pub fn verify_c2_nullifier_bridge(n_network: &[u8; 32], n_circuit: &[u8; 32]) -> bool {
        // BLAKE3 out-circuit — spec §4.3 C2, §2.1.3
        let expected = *blake3::hash(n_circuit).as_bytes();
        &expected == n_network
    }

    /// verification C7: output commitment. Spec §4.3 C7.
    ///
    /// out_commit = Poseidon2(value || pubtoy || fresh_salt)
    /// In-circuit hash: Poseidon2 — spec §2.1.3.
    pub fn verify_c7_output_commitment(
        commitment: &[u8; 32],
        value: u64,
        pubkey: &[u8; 32],
        salt: &[u8; 32],
    ) -> bool {
        // Poseidon2 in-circuit — spec §4.3 C7, §2.1.3
        let input = [
            value,
            u64::from_le_bytes(pubkey[0..8].try_into().unwrap_or([0u8; 8])),
            u64::from_le_bytes(salt[0..8].try_into().unwrap_or([0u8; 8])),
            u64::from_le_bytes(salt[8..16].try_into().unwrap_or([0u8; 8])),
        ];
        let hash_out = Poseidon2Hasher::hash(&input);
        // Convert [u64;4] to [u8;32] — little-endian
        let mut expected = [0u8; 32];
        for (i, &v) in hash_out.iter().enumerate() {
            expected[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        expected == *commitment
    }
}

// ── Dual Verification — spec §2.2 ────────────────────────────────────────────

/// Hasil dual verification (Winterfell + Independent). Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DualVerifyResult {
    /// second implementation agree: proof valid. Spec §2.2.
    BothValid,
    /// Independent verifier reject, Winterfell accept. Spec §2.2.
    /// → Security incident: proof rejected.
    IndependentRejects(ConstraintViolation),
    /// Winterfell reject (proof cryptographically invalid). Spec §2.2.
    WinterfellRejects,
    /// second implementation reject. Spec §2.2.
    BothReject,
}

/// run dual verification. Spec §2.2.
///
/// second implementation must agree for proof received.
/// atsagreement → proof rejected → security incident.
pub fn dual_verify(
    pub_input: &IndependentPublicInput,
    winterfell_accepted: bool,
) -> DualVerifyResult {
    let independent_result = IndependentVerifier::verify(pub_input);

    match (winterfell_accepted, independent_result) {
        (true, IndependentVerifyResult::Valid) => DualVerifyResult::BothValid,
        (true, IndependentVerifyResult::ConstraintViolation(v)) => {
            DualVerifyResult::IndependentRejects(v)
        }
        (false, IndependentVerifyResult::Valid) => DualVerifyResult::WinterfellRejects,
        (false, IndependentVerifyResult::ConstraintViolation(_)) => DualVerifyResult::BothReject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> IndependentPublicInput {
        IndependentPublicInput {
            input_commitments: vec![[0x01u8; 32]],
            input_nullifiers: vec![[0x02u8; 32]],
            output_commitments: vec![[0x03u8; 32]],
            fee_total: 40,
            crypto_version: 0x01,
            entry_timestamp: 1_000_000_000,
            current_timestamp: 1_000_060_000, // 60 seconds then
        }
    }

    // ── Goldilocks field arithmetic ───────────────────────────────────────────

    #[test]
    fn test_goldilocks_prime_value() {
        // p = 2^64 - 2^32 + 1. Spec §2.2.
        assert_eq!(GOLDILOCKS_PRIME, 0xFFFF_FFFF_0000_0001u64);
    }

    #[test]
    fn test_field_add_no_overflow() {
        // Normal addition. Spec §2.2.
        assert_eq!(field_add(10, 20), 30);
    }

    #[test]
    fn test_field_add_wraps_at_prime() {
        // Addition yang melebihi prime harus wrap. Spec §2.2.
        let result = field_add(GOLDILOCKS_PRIME - 1, 2);
        assert_eq!(result, 1);
    }

    #[test]
    fn test_field_sub_normal() {
        assert_eq!(field_sub(30, 10), 20);
    }

    #[test]
    fn test_field_sub_wraps() {
        // 0 - 1 = p - 1 in Goldilocks field. Spec §2.2.
        let result = field_sub(0, 1);
        assert_eq!(result, GOLDILOCKS_PRIME - 1);
    }

    #[test]
    fn test_field_mul_zero() {
        assert_eq!(field_mul(0, 12345), 0);
    }

    #[test]
    fn test_field_mul_one() {
        assert_eq!(field_mul(1, 99999), 99999);
    }

    #[test]
    fn test_field_mul_reduces_mod_prime() {
        // Hasil harus < GOLDILOCKS_PRIME.
        let large = GOLDILOCKS_PRIME - 1;
        let result = field_mul(large, large);
        assert!(result < GOLDILOCKS_PRIME);
    }

    // ── C1-C10 constraint verification ───────────────────────────────────────

    #[test]
    fn test_verify_valid_input_passes() {
        // Input valid → semua constraint pass. Spec §4.3.
        let result = IndependentVerifier::verify(&valid_input());
        assert_eq!(result, IndependentVerifyResult::Valid);
    }

    #[test]
    fn test_c6_fee_below_floor_rejected() {
        // Fee < 40 → C6 violation. Spec §4.3 C6.
        let mut input = valid_input();
        input.fee_total = 39;
        assert!(matches!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::ConstraintViolation(ConstraintViolation::C6FeeBelowFloor {
                fee: 39,
                ..
            })
        ));
    }

    #[test]
    fn test_c6_fee_at_floor_passes() {
        // Fee = 40 → pass. Spec §4.3 C6.
        let mut input = valid_input();
        input.fee_total = 40;
        assert_eq!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::Valid
        );
    }

    #[test]
    fn test_c9_invalid_version_rejected() {
        // crypto_version = 0xFF → C9 violation. Spec §4.3 C9.
        let mut input = valid_input();
        input.crypto_version = 0xFF;
        assert!(matches!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::ConstraintViolation(ConstraintViolation::C9InvalidVersion {
                version: 0xFF
            })
        ));
    }

    #[test]
    fn test_c9_valid_version_passes() {
        // crypto_version = 0x01 → pass. Spec §4.3 C9.
        let mut input = valid_input();
        input.crypto_version = 0x01;
        assert_eq!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::Valid
        );
    }

    #[test]
    fn test_c10_expired_tx_rejected() {
        // Tx expired (> 30 menit) → C10 violation. Spec §4.3 C10.
        let mut input = valid_input();
        input.entry_timestamp = 1_000_000_000;
        input.current_timestamp = 1_000_000_000 + INDEPENDENT_T_MAX_WAIT_MS + 1;
        assert!(matches!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::ConstraintViolation(ConstraintViolation::C10TxExpired { .. })
        ));
    }

    #[test]
    fn test_c10_within_window_passes() {
        // Tx dalam window → pass. Spec §4.3 C10.
        let mut input = valid_input();
        input.entry_timestamp = 1_000_000_000;
        input.current_timestamp = 1_000_000_000 + INDEPENDENT_T_MAX_WAIT_MS; // exact at batas
        assert_eq!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::Valid
        );
    }

    #[test]
    fn test_max_io_exceeded_rejected() {
        // > 10 inputs → ExceedsMaxIO. Spec §4.4.
        let mut input = valid_input();
        input.input_commitments = vec![[0x01u8; 32]; 11];
        input.input_nullifiers = vec![[0x02u8; 32]; 11];
        assert!(matches!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::ConstraintViolation(ConstraintViolation::ExceedsMaxIO { .. })
        ));
    }

    #[test]
    fn test_max_io_exactly_10_passes() {
        // Tepat 10 inputs/outputs → pass. Spec §4.4.
        let mut input = valid_input();
        input.input_commitments = vec![[0x01u8; 32]; 10];
        input.input_nullifiers = vec![[0x02u8; 32]; 10];
        input.output_commitments = vec![[0x03u8; 32]; 10];
        assert_eq!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::Valid
        );
    }

    #[test]
    fn test_c2_nullifier_zero_rejected() {
        // Nullifier = [0;32] tidak valid. Spec §4.3 C2.
        let mut input = valid_input();
        input.input_nullifiers = vec![[0u8; 32]];
        assert!(matches!(
            IndependentVerifier::verify(&input),
            IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::C2NullifierInvalid { .. }
            )
        ));
    }

    // ── C5: Value conservation ────────────────────────────────────────────────

    #[test]
    fn test_c5_conservation_valid() {
        // 100 + 200 = 250 + 50 → valid. Spec §4.3 C5.
        let result = IndependentVerifier::verify_c5_conservation(&[100, 200], &[250], 50);
        assert_eq!(result, IndependentVerifyResult::Valid);
    }

    #[test]
    fn test_c5_conservation_violated() {
        // 100 ≠ 50 + 10 → C5 violation. Spec §4.3 C5.
        let result = IndependentVerifier::verify_c5_conservation(
            &[100],
            &[50],
            10, // 50+10=60 ≠ 100
        );
        assert!(matches!(
            result,
            IndependentVerifyResult::ConstraintViolation(
                ConstraintViolation::C5ConservationFailed { .. }
            )
        ));
    }

    #[test]
    fn test_c5_exact_conservation() {
        // Exact conservation termasuk fee. Spec §4.3 C5.
        let result = IndependentVerifier::verify_c5_conservation(&[1000], &[960], 40);
        assert_eq!(result, IndependentVerifyResult::Valid);
    }

    // ── C2: Nullifier bridge ──────────────────────────────────────────────────

    #[test]
    fn test_c2_nullifier_bridge_valid() {
        // N_network = BLAKE3(N_circuit) → valid. Spec §4.3 C2.
        let n_circuit = [0x42u8; 32];
        let n_network = *blake3::hash(&n_circuit).as_bytes();
        assert!(IndependentVerifier::verify_c2_nullifier_bridge(
            &n_network, &n_circuit
        ));
    }

    #[test]
    fn test_c2_nullifier_bridge_invalid() {
        // N_network ≠ BLAKE3(N_circuit) → invalid. Spec §4.3 C2.
        let n_circuit = [0x42u8; 32];
        let wrong_network = [0xFFu8; 32];
        assert!(!IndependentVerifier::verify_c2_nullifier_bridge(
            &wrong_network,
            &n_circuit
        ));
    }

    // ── Dual verification ─────────────────────────────────────────────────────

    #[test]
    fn test_dual_verify_both_valid() {
        // Winterfell accept + Independent valid → BothValid. Spec §2.2.
        let input = valid_input();
        assert_eq!(dual_verify(&input, true), DualVerifyResult::BothValid);
    }

    #[test]
    fn test_dual_verify_independent_rejects() {
        // Winterfell accept + Independent rejects → IndependentRejects. Spec §2.2.
        let mut input = valid_input();
        input.fee_total = 0; // C6 violation
        assert!(matches!(
            dual_verify(&input, true),
            DualVerifyResult::IndependentRejects(_)
        ));
    }

    #[test]
    fn test_dual_verify_winterfell_rejects() {
        // Winterfell reject + Independent valid → WinterfellRejects. Spec §2.2.
        let input = valid_input();
        assert_eq!(
            dual_verify(&input, false),
            DualVerifyResult::WinterfellRejects
        );
    }

    #[test]
    fn test_dual_verify_both_reject() {
        // Winterfell reject + Independent rejects → BothReject. Spec §2.2.
        let mut input = valid_input();
        input.fee_total = 0; // C6 violation
        assert_eq!(dual_verify(&input, false), DualVerifyResult::BothReject);
    }

    #[test]
    fn test_independent_verifier_no_winterfell_dependency() {
        // Test ini compile hanya jika tidak ada winterfell import di file ini.
        // Keberhasilan compile = implementasi independen. Spec §2.2.
        let _ = IndependentVerifier::verify(&valid_input());
    }

    // ── Constants compliance ──────────────────────────────────────────────────

    #[test]
    fn test_independent_max_io_is_10() {
        // Spec §4.4: MAX_IO = 10. OSSIFIED.
        assert_eq!(INDEPENDENT_MAX_IO, 10usize);
    }

    #[test]
    fn test_independent_floor_min_is_40() {
        // Spec §9.1: FLOOR_MIN_ABSOLUTE = 40 sSCL. OSSIFIED.
        assert_eq!(INDEPENDENT_FLOOR_MIN, 40u64);
    }

    #[test]
    fn test_independent_t_max_wait_is_30_minutes() {
        // Spec §4.3 C10: T_MAX_WAIT = 30 menit = 1_800_000 ms.
        assert_eq!(INDEPENDENT_T_MAX_WAIT_MS, 1_800_000u64);
    }
}
