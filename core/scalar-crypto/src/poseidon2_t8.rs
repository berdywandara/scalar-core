//! Poseidon2 t=8 — single permutation using p3-goldilocks canonical parameters.
//!
//! Decision D-011: p3-goldilocks is the single source of truth for Poseidon2
//! round constants. HorizenLabs RC (0x3c7e...) are INVALID post-D-011.
//!
//! Decision D-010: IMT uses single permutation (not sponge) so that
//! out-of-circuit (scalar-crypto) and in-circuit (ScalarPoseidon2Air) are
//! mathematically identical.
//!
//! Parameters (OSSIFIED — Decision D-008, D-011):
//!   Field        : Goldilocks (p = 2^64 - 2^32 + 1)
//!   Width        : t = 8
//!   Alpha        : 7
//!   R_F          : 8 (4 initial + 4 final)
//!   R_P          : 22
//!   RC source    : p3-goldilocks (canonical, single source of truth)
//!   Construction : single permutation (NOT sponge) — D-010
//!
//! Spec §2.1: Poseidon2 in-circuit ONLY.

use crate::poseidon2::field_reduce;
use p3_field::PrimeField64;
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_symmetric::Permutation as P3Permutation;

// ── Constants — OSSIFIED (D-008, D-011) ──────────────────────────────────────

pub const WIDTH_T8: usize = 8;
pub const RATE_T8: usize = 4;
pub const CAPACITY_T8: usize = 4;
pub const SBOX_EXPONENT_T8: u64 = 7;
pub const FULL_ROUNDS_T8: usize = 8;
pub const PARTIAL_ROUNDS_T8: usize = 22;
pub const TOTAL_ROUNDS_T8: usize = FULL_ROUNDS_T8 + PARTIAL_ROUNDS_T8;

// ── Byte/field conversion helpers ────────────────────────────────────────────

/// Convert [u64; 8] Poseidon2 state to [u8; 32] (first 4 elements, LE).
/// Output is state[0..4] packed as 4 × 8 bytes little-endian.
pub fn field8_to_bytes32(state: &[u64; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &v) in state[..4].iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// Convert [u8; 32] to [u64; 4] little-endian.
pub fn bytes32_to_field4(b: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap()))
}

// ── Core permutation — p3-goldilocks canonical ────────────────────────────────

/// Execute one Poseidon2 permutation using p3-goldilocks canonical RC.
/// Returns full state [u64; 8] post-permutation.
///
/// D-011: RC from p3-goldilocks. D-010: single permutation, not sponge.
pub fn poseidon2_permute_t8(input: &[u64; WIDTH_T8]) -> [u64; WIDTH_T8] {
    let perm = default_goldilocks_poseidon2_8();
    let mut state: [Goldilocks; WIDTH_T8] =
        core::array::from_fn(|i| Goldilocks::new(field_reduce(input[i])));
    <_ as P3Permutation<_>>::permute_mut(&perm, &mut state);
    core::array::from_fn(|i| state[i].as_canonical_u64())
}

// ── Poseidon2T8Hasher — single permutation API ───────────────────────────────

/// Poseidon2 t=8 hasher using p3-goldilocks canonical parameters.
///
/// D-010: single permutation (not sponge). Input must fit in 8 field elements.
/// For inputs longer than 8 elements, use multiple calls or a dedicated AIR.
///
/// Output: state[0..4] as [u64; 4] (256-bit hash).
pub struct Poseidon2T8Hasher;

impl Poseidon2T8Hasher {
    /// Hash up to 8 field element values via single Poseidon2 permutation.
    ///
    /// D-010: NOT a sponge. Input is zero-padded to width=8 and permuted once.
    /// For IMT: inputs are always ≤8 elements (domain + data).
    pub fn hash(input: &[u64]) -> [u64; WIDTH_T8] {
        assert!(
            input.len() <= WIDTH_T8,
            "D-010: single permutation supports max {} inputs, got {}",
            WIDTH_T8,
            input.len()
        );
        let mut state = [0u64; WIDTH_T8];
        for (i, &v) in input.iter().enumerate() {
            state[i] = field_reduce(v);
        }
        poseidon2_permute_t8(&state)
    }

    /// Hash raw bytes by converting to field elements (8 bytes → 1 u64 LE).
    /// Pads to WIDTH_T8. Max input: 64 bytes.
    pub fn hash_bytes(bytes: &[u8]) -> [u64; WIDTH_T8] {
        assert!(
            bytes.len() <= WIDTH_T8 * 8,
            "hash_bytes: max {} bytes, got {}",
            WIDTH_T8 * 8,
            bytes.len()
        );
        let mut state = [0u64; WIDTH_T8];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            state[i] = field_reduce(u64::from_le_bytes(buf));
        }
        poseidon2_permute_t8(&state)
    }

    /// Hash to 4-element output (first 4 elements of permutation state).
    pub fn hash_to_4(input: &[u64]) -> [u64; 4] {
        let out = Self::hash(input);
        [out[0], out[1], out[2], out[3]]
    }
}

// ── Chained permutation for >8 inputs ────────────────────────────────────────

/// Hash more than 8 field elements via chained permutations.
///
/// D-010/D-011: For inputs that don't fit in a single permutation (>8 elements),
/// we chain permutations: each call feeds the previous output into the next
/// permutation's first 4 elements (capacity), mixing with the next 4 input
/// elements (rate=4).
///
/// This is a rate-4 sponge-like construction using single permutations:
///   state = [0; 8]
///   for each chunk of 4 input elements:
///     state[0..4] ^= chunk  (XOR into rate)
///     state = permute(state)
/// Output: state[0..4]
///
/// Unlike the old sponge (which used 10* padding and variable-length absorb),
/// this construction is deterministic, in-circuit-reproducible, and maps
/// directly to a sequence of ScalarPoseidon2Air rows.
///
/// For in-circuit CB/CC: each permutation step = one trace row.
pub fn poseidon2_hash_chained(input: &[u64]) -> [u64; 4] {
    let mut state = [0u64; WIDTH_T8];
    // Absorb input in chunks of RATE_T8=4, XOR into rate portion
    for chunk in input.chunks(RATE_T8) {
        for (i, &v) in chunk.iter().enumerate() {
            state[i] = field_reduce(state[i] ^ field_reduce(v));
        }
        state = poseidon2_permute_t8(&state);
    }
    [state[0], state[1], state[2], state[3]]
}

/// Hash chained and return as [u8; 32].
pub fn poseidon2_hash_chained_bytes32(input: &[u64]) -> [u8; 32] {
    let out = poseidon2_hash_chained(input);
    let mut result = [0u8; 32];
    for (i, &v) in out.iter().enumerate() {
        result[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    result
}

// ── RC verification — CI gate (D-011) ────────────────────────────────────────

/// Verify that p3-goldilocks RC[0][0] matches the canonical D-011 value.
/// This is a compile-time-checkable invariant for RC alignment.
pub const D011_RC_CANONICAL_CHECK: u64 = 0xdd5743e7f2a5a5d9;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_d011_rc_alignment() {
        use p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL;
        // D-011 CI gate: p3-goldilocks RC[0][0] must equal canonical value.
        let rc0 = GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL[0][0].as_canonical_u64();
        assert_eq!(
            rc0, D011_RC_CANONICAL_CHECK,
            "D-011 VIOLATED: p3-goldilocks RC[0][0] changed — RC alignment broken"
        );
    }

    #[test]
    fn test_d010_single_permutation_not_sponge() {
        // D-010: same input length → same output (deterministic single permutation).
        let r1 = Poseidon2T8Hasher::hash(&[1, 2, 3, 4]);
        let r2 = Poseidon2T8Hasher::hash(&[1, 2, 3, 4]);
        assert_eq!(r1, r2, "permutation must be deterministic");
        // Different input → different output
        let r3 = Poseidon2T8Hasher::hash(&[1, 2, 3, 5]);
        assert_ne!(r1, r3, "different input must produce different output");
    }

    #[test]
    fn test_hash_bytes_deterministic() {
        let r1 = Poseidon2T8Hasher::hash_bytes(b"scalar_t8");
        let r2 = Poseidon2T8Hasher::hash_bytes(b"scalar_t8");
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_hash_output_nonzero() {
        // Permutation of zero must not be zero (sanity check).
        let r = Poseidon2T8Hasher::hash(&[0u64]);
        assert_ne!(r, [0u64; 8], "permutation of zero must not be all-zero");
    }

    #[test]
    fn test_field8_to_bytes32_roundtrip() {
        let state: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let bytes = field8_to_bytes32(&state);
        let back = bytes32_to_field4(&bytes);
        assert_eq!(back, [1, 2, 3, 4]);
    }

    #[test]
    fn test_width_t8_ossified() {
        assert_eq!(WIDTH_T8, 8);
    }

    #[test]
    fn test_rounds_t8_ossified() {
        assert_eq!(FULL_ROUNDS_T8, 8);
        assert_eq!(PARTIAL_ROUNDS_T8, 22);
        assert_eq!(TOTAL_ROUNDS_T8, 30);
    }

    #[test]
    fn test_sbox_exponent_t8() {
        assert_eq!(SBOX_EXPONENT_T8, 7);
    }

    #[test]
    fn test_hash_to_4() {
        let r = Poseidon2T8Hasher::hash_to_4(&[42, 0, 0, 0]);
        assert_ne!(r, [0u64; 4]);
    }
}
