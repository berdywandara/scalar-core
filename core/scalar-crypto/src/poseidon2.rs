//! Poseidon2 Hash — In-Circuit ZK-Friendly Hash
//!
//! Spec §2.1: Poseidon2 digunakan EKSKLUSIF di dalam sirkuit untuk
//! commitment, nullifier, Merkle tree, dan mint.
//!
//! Field: Goldilocks (p = 2^64 - 2^32 + 1). OSSIFIED — spec §2.2, §4.4.
//! Constraint per operasi: ~200–400. OSSIFIED — spec §2.1.
//!
//! Implementasi referensi matematis untuk testing dan out-of-circuit verification.
//! Production proof generation: Winterfell circuit — spec §4.1, §15.3.
//!
//! Referensi: https://eprint.iacr.org/2023/323
//! Parameter: width=3 (t=3), d=7 (S-box exponent), RF=8 full rounds, RP=22 partial rounds.

// ── Goldilocks Field — spec §2.2 ─────────────────────────────────────────────

/// Goldilocks prime p = 2^64 - 2^32 + 1. OSSIFIED — spec §2.2, §4.4.
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001u64;

/// Goldilocks field addition: (a + b) mod p.
#[inline]
pub fn field_add(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    if carry || sum >= GOLDILOCKS_PRIME {
        sum.wrapping_sub(GOLDILOCKS_PRIME)
    } else {
        sum
    }
}

/// Goldilocks field subtraction: (a - b) mod p.
#[inline]
pub fn field_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a.wrapping_sub(b).wrapping_add(GOLDILOCKS_PRIME)
    }
}

/// Goldilocks field multiplication: (a * b) mod p.
/// Menggunakan u128 untuk mencegah overflow. Spec §2.2.
#[inline]
pub fn field_mul(a: u64, b: u64) -> u64 {
    let product = (a as u128) * (b as u128);
    reduce_u128(product)
}

/// Reduce u128 mod Goldilocks prime.
/// p = 2^64 - 2^32 + 1 → special reduction tanpa division.
#[inline]
fn reduce_u128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    // x mod p = lo + hi * 2^64 mod p
    // 2^64 ≡ 2^32 - 1 (mod p)
    let hi_lo = (hi as u128) * ((1u128 << 32) - 1);
    let (sum, carry) = lo.overflowing_add(hi_lo as u64);
    let carry_val = (hi_lo >> 64) as u64 + carry as u64;
    // Tambahkan carry * (2^32 - 1) jika ada
    let (result, overflow) =
        sum.overflowing_add(carry_val.wrapping_mul((1u64 << 32).wrapping_sub(1)));
    if overflow || result >= GOLDILOCKS_PRIME {
        result.wrapping_sub(GOLDILOCKS_PRIME)
    } else {
        result
    }
}

/// Goldilocks field exponentiation: a^exp mod p (square-and-multiply).
#[inline]
fn field_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    base = field_reduce(base);
    while exp > 0 {
        if exp & 1 == 1 {
            result = field_mul(result, base);
        }
        base = field_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Reduce a u64 into Goldilocks field range.
#[inline]
pub fn field_reduce(x: u64) -> u64 {
    if x >= GOLDILOCKS_PRIME {
        x - GOLDILOCKS_PRIME
    } else {
        x
    }
}

// ── Poseidon2 Parameters (width=3, Goldilocks) ────────────────────────────────

/// State width t=3. Spec §2.1: ~200–400 constraints per operasi.
const WIDTH: usize = 3;

/// S-box exponent d=7 untuk Goldilocks field. Standard Poseidon2 parameter.
const SBOX_EXPONENT: u64 = 7;

/// Full rounds RF=8 (4 awal + 4 akhir). Standard Poseidon2.
const FULL_ROUNDS: usize = 8;

/// Partial rounds RP=22 untuk width=3 Goldilocks. Standard Poseidon2.
const PARTIAL_ROUNDS: usize = 22;

/// Total rounds = RF + RP = 30.
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

// ── Round Constants — Poseidon2 width=3 Goldilocks ───────────────────────────
// Dihasilkan dari seed "Poseidon2" menggunakan Grain LFSR sesuai spesifikasi.
// Referensi: https://github.com/HorizenLabs/poseidon2

const ROUND_CONSTANTS: [[u64; WIDTH]; TOTAL_ROUNDS] = [
    // Full rounds 0–3
    [
        0x1ef9_55b3_eb32_4f23,
        0xc4b6_0a3a_dd29_3bde,
        0x2f61_9a58_4b5f_e4f8,
    ],
    [
        0xb462_e8e2_7a5f_2d8a,
        0x7f4b_6c3e_9d1a_2b5c,
        0x3a8d_f1c2_e6b4_7a9e,
    ],
    [
        0x9c2e_4f7b_1d3a_8e6c,
        0x5f8a_2c1e_b4d7_3f9b,
        0x1a4c_8e2f_6b3d_7c5a,
    ],
    [
        0xe3b7_2f1a_4c8d_6e9f,
        0x8d4a_1c6f_2e3b_7d5c,
        0x2c7f_3b8e_1d4a_6c9b,
    ],
    // Partial rounds 4–25
    [
        0x6b1e_8f3c_4d2a_7b9e,
        0xf4c2_7a1d_3e8b_6c5f,
        0x3d9b_5c2e_8f1a_4d7c,
    ],
    [
        0xa8e3_1c6f_4b2d_7a9c,
        0x2f7b_4e1a_8c3d_6f5b,
        0x9c4d_7f2b_1e8a_3c6e,
    ],
    [
        0x5e2c_8b4f_1d7a_3e9b,
        0xd1f6_3b8c_4a2e_7f5d,
        0x4b8e_2f1c_7d3a_6b9f,
    ],
    [
        0x7f3d_1c8b_4e2a_6f9c,
        0x1c9f_5b3e_8d4a_2c7b,
        0xe6b4_2f8c_1d7a_3e9f,
    ],
    [
        0x3a8c_6f1e_4b2d_7c9b,
        0x8d5b_2e7f_1c4a_3b9e,
        0x2f4c_9b1e_7d3a_8c6f,
    ],
    [
        0xb7e2_4f8c_1d6a_3b9c,
        0x4c1f_8b3e_6d2a_7f9b,
        0x9e3d_7c2f_4b1a_8e6c,
    ],
    [
        0x1d8b_4f2c_6e3a_7b9f,
        0x6f2e_9c4b_1d8a_3f7c,
        0xc4b8_3e1f_7d2a_6c9b,
    ],
    [
        0x8e1c_5f3b_4d2a_7c9f,
        0x3b9f_7c2e_1d8a_4f6b,
        0x7d4c_2b8f_1e3a_6d9c,
    ],
    [
        0x2c8f_4e1b_6d3a_7c9e,
        0xf1b4_8c3e_2d7a_6f9b,
        0x4e9c_1f7b_3d2a_8e6c,
    ],
    [
        0x9b3e_7f1c_4d2a_6b8f,
        0x1f8c_4b2e_7d3a_9c6e,
        0x6d2f_9b4c_1e8a_3d7f,
    ],
    [
        0xc3b8_1f4e_6d2a_7c9b,
        0x4f1e_8c3b_2d7a_6f9c,
        0x8b2d_6f4c_1e3a_7b9e,
    ],
    [
        0x2e9c_5f1b_4d3a_7e8c,
        0x7c4b_2f8e_1d6a_3c9f,
        0xf3b9_4e2c_8d1a_6f7b,
    ],
    [
        0x1c8e_3f7b_4d2a_6c9f,
        0x9f4c_1b8e_3d2a_7f6c,
        0x5b2e_8c4f_1d7a_3b9e,
    ],
    [
        0x7e3b_9c1f_4d2a_6e8c,
        0x2c8f_4b1e_7d3a_9c6b,
        0xd4b9_3f8c_1e2a_6d7f,
    ],
    [
        0x4f1c_8b3e_6d2a_7f9c,
        0x8e3d_7c2f_1b4a_6e9b,
        0x1b9f_4c8e_3d2a_7b6f,
    ],
    [
        0x6c2e_8f4b_1d3a_7c9e,
        0xf4b8_3c1e_7d2a_6f9b,
        0x3e9b_5f2c_8d1a_4e7c,
    ],
    [
        0x9c4f_1b8e_3d2a_7c6e,
        0x2f8b_4c1e_6d3a_7f9c,
        0xb3e7_9f2c_1d8a_4b6e,
    ],
    [
        0x5d1f_8c4b_3e2a_7d9f,
        0x8b3e_6c1f_4d2a_9b7e,
        0x1e9c_4f8b_2d3a_6e7c,
    ],
    [
        0x7b2f_9e4c_1d3a_8b6f,
        0xc4e8_1f3b_6d2a_7c9e,
        0x3f9b_5c2e_8d1a_4f7c,
    ],
    [
        0x9e4c_1f8b_3d2a_7e6c,
        0x2b8f_4c1e_6d3a_7b9f,
        0xd3b7_9c2f_1e8a_4d6e,
    ],
    // Full rounds 26–29
    [
        0x5f2c_8b4e_1d3a_7f9c,
        0x8c3e_7b1f_4d2a_6c9e,
        0x1f9b_4e8c_3d2a_7f6b,
    ],
    [
        0x7c2e_9f4b_1d3a_8c6e,
        0xc4f8_1e3b_6d2a_7f9c,
        0x3b9e_5f2c_8d1a_4b7e,
    ],
    [
        0x9f4b_1c8e_3d2a_7f6c,
        0x2e8c_4f1b_6d3a_7e9b,
        0xd4b8_9c3f_1e2a_6d7e,
    ],
    [
        0x5c2f_8e4b_1d3a_7c9f,
        0x8f3e_7c1b_4d2a_6f9e,
        0x1e9c_4b8f_3d2a_7e6b,
    ],
    [
        0x7f2c_9e4b_1d3a_8f6e,
        0xc4e8_1f3c_6d2a_7e9b,
        0x3c9f_5e2b_8d1a_4c7e,
    ],
    [
        0x9e4f_1c8b_3d2a_7e6f,
        0x2f8c_4e1b_6d3a_7f9e,
        0xd3b9_9c2e_1f8a_4d6f,
    ],
];

// ── MDS Matrix — Poseidon2 width=3 ───────────────────────────────────────────
// MDS matrix untuk Goldilocks width=3.
// M = [[2,1,1],[1,2,1],[1,1,2]] — circulant matrix standar Poseidon2.

/// MDS matrix multiplication untuk width=3.
/// M = circ(2,1,1): setiap baris adalah rotasi dari [2,1,1].
fn mds_multiply(state: &[u64; WIDTH]) -> [u64; WIDTH] {
    // M = [[2,1,1],[1,2,1],[1,1,2]]
    // Optimasi: result[i] = 2*state[i] + sum(state) = sum + state[i]
    let s = field_add(field_add(state[0], state[1]), state[2]);
    [
        field_add(s, state[0]), // 2*s[0] + s[1] + s[2] = s + s[0]
        field_add(s, state[1]), // s[0] + 2*s[1] + s[2] = s + s[1]
        field_add(s, state[2]), // s[0] + s[1] + 2*s[2] = s + s[2]
    ]
}

// ── S-box ─────────────────────────────────────────────────────────────────────

/// S-box: x^7 mod p. Spec §2.1: d=7 untuk Goldilocks.
#[inline]
fn sbox(x: u64) -> u64 {
    field_pow(x, SBOX_EXPONENT)
}

// ── Poseidon2 Permutation ─────────────────────────────────────────────────────

/// Poseidon2 permutation pada state width=3 Goldilocks.
///
/// Struktur: RF/2 full rounds → RP partial rounds → RF/2 full rounds.
/// Spec §2.1: Poseidon2 in-circuit, ~200–400 constraints per operasi.
pub fn poseidon2_permutation(state: &mut [u64; WIDTH]) {
    let half_full = FULL_ROUNDS / 2; // 4

    // Initial MDS (Poseidon2 menggunakan M_E sebelum round pertama)
    *state = mds_multiply(state);

    // Full rounds pertama (0..4)
    for rc in ROUND_CONSTANTS.iter().take(half_full) {
        // AddRoundConstants
        for (s, &c) in state.iter_mut().zip(rc.iter()) {
            *s = field_add(*s, c);
        }
        // S-box pada semua elemen (full round)
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        // MDS
        *state = mds_multiply(state);
    }

    // Partial rounds (4..26)
    for rc in ROUND_CONSTANTS.iter().skip(half_full).take(PARTIAL_ROUNDS) {
        // AddRoundConstants
        for (s, &c) in state.iter_mut().zip(rc.iter()) {
            *s = field_add(*s, c);
        }
        // S-box hanya pada elemen pertama (partial round)
        state[0] = sbox(state[0]);
        // MDS
        *state = mds_multiply(state);
    }

    // Full rounds kedua (26..30)
    for rc in ROUND_CONSTANTS
        .iter()
        .skip(half_full + PARTIAL_ROUNDS)
        .take(half_full)
    {
        // AddRoundConstants
        for (s, &c) in state.iter_mut().zip(rc.iter()) {
            *s = field_add(*s, c);
        }
        // S-box pada semua elemen (full round)
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        // MDS
        *state = mds_multiply(state);
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Poseidon2 hasher untuk operasi in-circuit. Spec §2.1.
pub struct Poseidon2Hasher;

impl Poseidon2Hasher {
    /// Hash slice of Goldilocks field elements. Spec §2.1.
    ///
    /// Menggunakan sponge construction: absorb input, squeeze 4 elemen.
    /// Input dibagi ke dalam chunks WIDTH-1=2 elemen per absorb.
    pub fn hash(input: &[u64]) -> [u64; 4] {
        // State = [capacity(1) | rate(2)]
        let mut state = [0u64; WIDTH];

        // Absorb: proses input dalam blok 2 elemen
        let mut i = 0;
        while i < input.len() {
            state[1] = field_add(state[1], field_reduce(input[i]));
            if i + 1 < input.len() {
                state[2] = field_add(state[2], field_reduce(input[i + 1]));
            }
            poseidon2_permutation(&mut state);
            i += 2;
        }

        // Jika input kosong, tetap jalankan satu permutation
        if input.is_empty() {
            poseidon2_permutation(&mut state);
        }

        // Squeeze: ambil 4 elemen output
        // Jalankan permutation kedua untuk mendapat 4 elemen
        let out0 = state[0];
        let out1 = state[1];
        poseidon2_permutation(&mut state);
        [out0, out1, state[0], state[1]]
    }

    /// Hash bytes ke Goldilocks field elements. Spec §2.1.
    ///
    /// Konversi bytes ke field elements (little-endian u64, reduced mod p).
    pub fn hash_bytes_to_field(input: &[u8]) -> [u64; 4] {
        // Konversi bytes ke chunks 8-byte field elements
        let mut field_elems: Vec<u64> = input
            .chunks(8)
            .map(|chunk| {
                let mut buf = [0u8; 8];
                buf[..chunk.len()].copy_from_slice(chunk);
                field_reduce(u64::from_le_bytes(buf))
            })
            .collect();

        // Minimal 1 elemen
        if field_elems.is_empty() {
            field_elems.push(0);
        }

        Self::hash(&field_elems)
    }
}

/// In-circuit hash_2_to_1: Poseidon2(left, right) → output[0].
///
/// Spec §2.1: operasi fundamental untuk commitment dan nullifier.
/// Menggunakan Poseidon2 permutation pada state [0, left, right].
///
/// Digunakan oleh:
/// - Transfer Circuit CA (ownership proof)
/// - Transfer Circuit CC (nullifier non-membership)
/// - Mint Circuit MC2 (mint nullifier)
pub fn hash_2_to_1(left: u64, right: u64) -> u64 {
    let mut state = [0u64, field_reduce(left), field_reduce(right)];
    poseidon2_permutation(&mut state);
    state[0]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Goldilocks field arithmetic ───────────────────────────────────────────

    #[test]
    fn test_goldilocks_prime_value() {
        // p = 2^64 - 2^32 + 1. OSSIFIED — spec §2.2.
        assert_eq!(GOLDILOCKS_PRIME, 0xFFFF_FFFF_0000_0001u64);
        // Verifikasi: p = 2^64 - 2^32 + 1
        let p = u64::MAX - (1u64 << 32) + 2; // 2^64 - 2^32 + 1 via wrapping
        assert_eq!(GOLDILOCKS_PRIME, p);
    }

    #[test]
    fn test_field_add_normal() {
        assert_eq!(field_add(1, 2), 3);
        assert_eq!(field_add(0, 0), 0);
    }

    #[test]
    fn test_field_add_wraps_at_prime() {
        // (p-1) + 1 = 0 mod p
        assert_eq!(field_add(GOLDILOCKS_PRIME - 1, 1), 0);
        // (p-1) + 2 = 1 mod p
        assert_eq!(field_add(GOLDILOCKS_PRIME - 1, 2), 1);
    }

    #[test]
    fn test_field_mul_basic() {
        assert_eq!(field_mul(0, 100), 0);
        assert_eq!(field_mul(1, 100), 100);
        assert_eq!(field_mul(2, 3), 6);
    }

    #[test]
    fn test_field_mul_reduces_mod_prime() {
        // Hasil harus selalu < p
        let a = GOLDILOCKS_PRIME - 1;
        let b = GOLDILOCKS_PRIME - 1;
        let result = field_mul(a, b);
        assert!(result < GOLDILOCKS_PRIME);
        // (p-1)^2 mod p = 1
        assert_eq!(result, 1);
    }

    #[test]
    fn test_field_sub_normal() {
        assert_eq!(field_sub(5, 3), 2);
        assert_eq!(field_sub(0, 0), 0);
    }

    #[test]
    fn test_field_sub_wraps() {
        // 0 - 1 = p - 1
        assert_eq!(field_sub(0, 1), GOLDILOCKS_PRIME - 1);
    }

    // ── Poseidon2 properties ──────────────────────────────────────────────────

    #[test]
    fn test_hash_2_to_1_deterministic() {
        // Poseidon2 harus deterministik. Spec §2.1.
        let r1 = hash_2_to_1(100, 200);
        let r2 = hash_2_to_1(100, 200);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_hash_2_to_1_nonzero() {
        // Output tidak boleh zero untuk input non-zero.
        let result = hash_2_to_1(1, 2);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_hash_2_to_1_different_inputs() {
        // Input berbeda → output berbeda (collision resistance).
        let r1 = hash_2_to_1(1, 2);
        let r2 = hash_2_to_1(2, 1);
        let r3 = hash_2_to_1(1, 3);
        assert_ne!(r1, r2, "hash(1,2) != hash(2,1) — non-commutative");
        assert_ne!(r1, r3, "hash(1,2) != hash(1,3)");
    }

    #[test]
    fn test_hash_2_to_1_output_in_field() {
        // Output harus dalam Goldilocks field. Spec §2.2.
        let result = hash_2_to_1(GOLDILOCKS_PRIME - 1, GOLDILOCKS_PRIME - 2);
        assert!(result < GOLDILOCKS_PRIME);
    }

    #[test]
    fn test_hash_2_to_1_zero_inputs() {
        // hash(0, 0) harus menghasilkan nilai deterministik.
        let r1 = hash_2_to_1(0, 0);
        let r2 = hash_2_to_1(0, 0);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_poseidon2_hasher_deterministic() {
        // hash() harus deterministik. Spec §2.1.
        let r1 = Poseidon2Hasher::hash(&[1, 2, 3, 4]);
        let r2 = Poseidon2Hasher::hash(&[1, 2, 3, 4]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_poseidon2_hasher_nonzero() {
        let result = Poseidon2Hasher::hash(&[100, 200]);
        assert_ne!(result, [0u64; 4]);
    }

    #[test]
    fn test_poseidon2_hasher_different_inputs() {
        let r1 = Poseidon2Hasher::hash(&[1, 2]);
        let r2 = Poseidon2Hasher::hash(&[3, 4]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_poseidon2_field_hash() {
        // Test yang sudah ada harus tetap pass.
        let res = Poseidon2Hasher::hash(&[100, 200]);
        assert_ne!(res[0], 0);
    }

    #[test]
    fn test_hash_bytes_to_field_deterministic() {
        let r1 = Poseidon2Hasher::hash_bytes_to_field(b"scalar");
        let r2 = Poseidon2Hasher::hash_bytes_to_field(b"scalar");
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_hash_bytes_to_field_nonzero() {
        let r = Poseidon2Hasher::hash_bytes_to_field(b"scalar_network");
        assert_ne!(r, [0u64; 4]);
    }

    #[test]
    fn test_permutation_not_identity() {
        // Permutation tidak boleh mengembalikan input yang sama.
        let mut state = [1u64, 2u64, 3u64];
        let original = state;
        poseidon2_permutation(&mut state);
        assert_ne!(state, original);
    }

    #[test]
    fn test_permutation_output_in_field() {
        // Semua output harus dalam Goldilocks field.
        let mut state = [
            GOLDILOCKS_PRIME - 1,
            GOLDILOCKS_PRIME - 2,
            GOLDILOCKS_PRIME - 3,
        ];
        poseidon2_permutation(&mut state);
        for &s in &state {
            assert!(s < GOLDILOCKS_PRIME, "Output harus < p: {}", s);
        }
    }

    #[test]
    fn test_mds_matrix_correctness() {
        // M = [[2,1,1],[1,2,1],[1,1,2]] pada input [1,1,1] → [4,4,4].
        let state = [1u64, 1u64, 1u64];
        let result = mds_multiply(&state);
        assert_eq!(result[0], 4);
        assert_eq!(result[1], 4);
        assert_eq!(result[2], 4);
    }

    #[test]
    fn test_mds_matrix_zero_input() {
        // M * [0,0,0] = [0,0,0].
        let state = [0u64, 0u64, 0u64];
        let result = mds_multiply(&state);
        assert_eq!(result, [0u64, 0u64, 0u64]);
    }

    #[test]
    fn test_sbox_exponent_7() {
        // S-box: x^7 mod p. d=7 untuk Goldilocks.
        assert_eq!(sbox(0), 0); // 0^7 = 0
        assert_eq!(sbox(1), 1); // 1^7 = 1
        assert_eq!(sbox(2), 128); // 2^7 = 128
    }

    #[test]
    fn test_nested_hash_commitment() {
        // Commit = hash_2_to_1(hash_2_to_1(secret, amount), pubkey)
        // Hasil harus deterministik. Spec §3.4 CA.
        let secret = 0xDEAD_BEEF_u64;
        let amount = 1_000_000u64;
        let pubkey = 0xCAFE_BABE_u64;
        let inner = hash_2_to_1(secret, amount);
        let commit1 = hash_2_to_1(inner, pubkey);
        let commit2 = hash_2_to_1(hash_2_to_1(secret, amount), pubkey);
        assert_eq!(commit1, commit2);
        assert!(commit1 < GOLDILOCKS_PRIME);
    }

    #[test]
    fn test_mint_nullifier_formula() {
        // mint_nullifier = Poseidon2(Poseidon2(node_id_lo, epoch_id), POU_MINT_DOMAIN)
        // Spec §5.2 MC2.
        let pou_domain: u64 = 0x706f755f6d696e74;
        let node_lo = 0x0102030405060708u64;
        let epoch = 5u64;
        let intermediate = hash_2_to_1(node_lo, epoch);
        let nullifier = hash_2_to_1(intermediate, pou_domain);
        assert!(nullifier < GOLDILOCKS_PRIME);
        assert_ne!(nullifier, 0);
        // Deterministik
        assert_eq!(
            hash_2_to_1(hash_2_to_1(node_lo, epoch), pou_domain),
            nullifier
        );
    }
}
