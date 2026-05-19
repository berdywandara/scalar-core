//! Poseidon2 Hash — In-Circuit ZK-Friendly Hash
//!
//! Spec §2.1: Poseidon2 digunakan EKSKLUSIF di dalam sirkuit untuk
//! commitment, nullifier, Merkle tree, dan mint.
//!
//! Field: Goldilocks (p = 2^64 - 2^32 + 1). OSSIFIED — spec §2.2, §4.4.
//! Parameters: width=4 (t=4), d=7 (S-box exponent), RF=8, RP=22.
//! Constraint per operasi: ~200–400. OSSIFIED — spec §2.1.
//!
//! Round constants: dihasilkan dari Grain LFSR sesuai Poseidon2 paper §B.
//! MDS matrix M_E: circ(5,7,1,3) untuk full rounds.
//! Internal matrix M_I: diagonal + all-ones untuk partial rounds.
//!
//! Referensi: https://eprint.iacr.org/2023/323
//! Parameter reference: https://github.com/HorizenLabs/poseidon2

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
    // 2^64 ≡ 2^32 - 1 (mod p)
    let hi_lo = (hi as u128) * ((1u128 << 32) - 1);
    let (sum, carry) = lo.overflowing_add(hi_lo as u64);
    let carry_val = (hi_lo >> 64) as u64 + carry as u64;
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

// ── Poseidon2 Parameters (width=4, Goldilocks) ────────────────────────────────
// OSSIFIED — mengikuti poseidon2_rust_params.sage di repository.
// t=4, alpha=7, R_F=8, R_P=22, field=Goldilocks.

/// State width t=4. Spec §2.1.
const WIDTH: usize = 4;

/// S-box exponent d=7 untuk Goldilocks field.
const SBOX_EXPONENT: u64 = 7;

/// Full rounds RF=8 (4 awal + 4 akhir).
const FULL_ROUNDS: usize = 8;

/// Partial rounds RP=22 untuk width=4 Goldilocks.
const PARTIAL_ROUNDS: usize = 22;

/// Total rounds = RF + RP = 30.
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

// ── Round Constants — dihasilkan oleh Grain LFSR ─────────────────────────────
// Generator: poseidon2_rust_params.sage (repo root).
// Parameters: t=4, R_F=8, R_P=22, alpha=7, field=Goldilocks.
// Verifikasi: 120 values, semua unique, distribusi uniform.

const ROUND_CONSTANTS: [[u64; WIDTH]; TOTAL_ROUNDS] = [
    [
        0x3aaed6e034fef709,
        0x2da65cf597408562,
        0xa7aace2d982bcb6a,
        0xbc121600d772d547,
    ], // round 0
    [
        0x1b114ef06f74865a,
        0x58ab3321665a38c2,
        0xec6e45fef040c842,
        0x9dc72efe8eb36d95,
    ], // round 1
    [
        0x69309d63ad1865c9,
        0x71a7ff71644d8e7e,
        0x05a8d7027238a428,
        0xe2f309a35adf55a3,
    ], // round 2
    [
        0xaab6a20f988e3a49,
        0xb2a1e4506874ebf9,
        0x31aca8878a23c40d,
        0x9a67297d522172c7,
    ], // round 3
    [
        0xd63b2a0d592f9779,
        0x3a610b62597d4252,
        0xc35857316552ee9c,
        0xeb7b4b8efcef4b6a,
    ], // round 4
    [
        0x1849a3e493848923,
        0x6bfaacbb4ff1db98,
        0x3eb14cd17d192d03,
        0x133e95099396da3c,
    ], // round 5
    [
        0xb8735f19f764cf4c,
        0x3a15f2bcac9cf32e,
        0xb5f0c9217f35cf57,
        0x1fd04c544470eafd,
    ], // round 6
    [
        0xc8a2058487ac0285,
        0x5e0be2f9eac6aad5,
        0xee4fc2378b7c35f8,
        0xeb8047e6be838132,
    ], // round 7
    [
        0x05543806b9d76ce9,
        0x7fabcc72309725b2,
        0xc7a3868a71fd4d8f,
        0xd29015c3c417e4bb,
    ], // round 8
    [
        0x56b7c4440cc9e9c8,
        0xd8b1c629e71bb164,
        0xf4c0847ca9341ac4,
        0x1f8546dc97cdba25,
    ], // round 9
    [
        0x3c56b447f4137881,
        0x59b35f9c795255cf,
        0x32e7ca296fe46732,
        0x2cc294ad1a52a94d,
    ], // round 10
    [
        0x1060b200e2725944,
        0x3ee35f5ee6a0f0cd,
        0x71ba8842cf6a016f,
        0x68060a2ffdce977d,
    ], // round 11
    [
        0x2f3e3d3e3b283902,
        0x350bf8d978a3670f,
        0xd0d9c23db3cbd8c5,
        0x16f68724b6900378,
    ], // round 12
    [
        0x7c2bf4809b9782dd,
        0x052af0b40e08c9d0,
        0xd831fb83be48c0af,
        0xe8a94bfb9464613e,
    ], // round 13
    [
        0x2c96a7d0898dbe1b,
        0x38364d93a426bbd5,
        0x2912a5153ed0ba7c,
        0x0af0925d868358f2,
    ], // round 14
    [
        0x362cdcb4d9e7cc6e,
        0x194a6b07ff7ae21d,
        0x28dd53b3bcd5e851,
        0x59fb7afb4bee528c,
    ], // round 15
    [
        0x4bd0360314bc46a0,
        0x076257530c706d7a,
        0x5b790519caf338c1,
        0x454cdca868c6610c,
    ], // round 16
    [
        0x426ca38cca16970d,
        0xc9555fe6efa48f9a,
        0x23f18cd0ca651b3a,
        0x12f6be2551a9ece4,
    ], // round 17
    [
        0x5d19cd85625e6cd4,
        0x033f57ecb7f9988b,
        0x51dbf1d36da0e24f,
        0x3e077397f307b7d4,
    ], // round 18
    [
        0x96024145db4a13da,
        0x2be4ba6bd810a850,
        0xd49cface475c85eb,
        0x54b101b103564356,
    ], // round 19
    [
        0x51daf7526c6d3721,
        0x9e2c63ccadb3e457,
        0x7574671c8831bd72,
        0x593906603a027573,
    ], // round 20
    [
        0xbf978d0d430a1038,
        0x16498e417fbda281,
        0x3324b0966a2b5c61,
        0xb565ea80a19f1465,
    ], // round 21
    [
        0xb1f1e0f1dfe67dc4,
        0x069ee318d5037863,
        0x025015c57735ec6d,
        0x83ca2cb6afc9c0b5,
    ], // round 22
    [
        0x9aca0c65658045da,
        0x32c72b854aa33f6a,
        0x1b86c06c65e563e9,
        0xd3b2e743605233c7,
    ], // round 23
    [
        0xde5453cdb5f6a3c1,
        0x160c94d47b36ba4e,
        0xc572402fa8c73cc1,
        0x59231b2ee92c0409,
    ], // round 24
    [
        0x05b087175e09ee36,
        0xb2e9c18902a18e06,
        0x5846001972ba7da8,
        0x6aebcd9abd529048,
    ], // round 25
    [
        0x2d3a03adc848eab1,
        0x9b779ac00fbb85db,
        0x4ebb1bbd83118149,
        0x263f74ab9d87da4b,
    ], // round 26
    [
        0x8a7fcc51f6fec3c8,
        0x879bdb1cb5d7d9a2,
        0x812d6a0b9d0363e5,
        0xad371d1acf8f155b,
    ], // round 27
    [
        0xb250667f5e91f0ba,
        0x5c54378b048155dd,
        0x0297d13f80000cb3,
        0xf2abfe46670b1961,
    ], // round 28
    [
        0x4880f5bc96111cde,
        0xe89150e848fa6bd6,
        0x6e504d15b09e7e2e,
        0xd02e8fc81d0b1a92,
    ], // round 29
];

// ── MDS Matrix M_E — circ(5,7,1,3) untuk full rounds ─────────────────────────
// Referensi: HorizenLabs poseidon2, Table 2, Goldilocks t=4.

const MATRIX_FULL: [[u64; WIDTH]; WIDTH] = [
    [
        0x0000000000000005,
        0x0000000000000007,
        0x0000000000000001,
        0x0000000000000003,
    ],
    [
        0x0000000000000003,
        0x0000000000000005,
        0x0000000000000007,
        0x0000000000000001,
    ],
    [
        0x0000000000000001,
        0x0000000000000003,
        0x0000000000000005,
        0x0000000000000007,
    ],
    [
        0x0000000000000007,
        0x0000000000000001,
        0x0000000000000003,
        0x0000000000000005,
    ],
];

// ── Internal Matrix M_I diagonal — untuk partial rounds ───────────────────────
// M_I * state[i] = sum(state) + state[i] * diag[i]
// diag[i] = MAT_DIAG4_M_1[i] + 1, disimpan sebagai (diag - 1) untuk efisiensi.
// Referensi: HorizenLabs poseidon2, Goldilocks t=4.

const MAT_DIAG4_M_1: [u64; WIDTH] = [
    0x0000000000000000,
    0x0000000000000001,
    0x0000000000000002,
    0x0000000000000003,
];

// ── Test Vectors — wajib diverifikasi §15.3 ───────────────────────────────────
// Dihasilkan oleh Python generator dengan Grain LFSR yang sama.

/// Test vector: permutation([0,0,0,0]) expected output. Spec §15.3.
pub const TV_ZERO_OUT: [u64; 4] = [
    0x922416154318390c,
    0xf4205842c6a5997e,
    0x386c95c28126300a,
    0xccdb766d10c91fde,
];

/// Test vector: permutation([1,2,0,0]) expected output. Spec §15.3.
pub const TV_KNOWN_OUT: [u64; 4] = [
    0xfd43e87a157f12dc,
    0x98e2aec6a1b34d63,
    0x8f775b59e522eeb1,
    0xbc8772dce7281290,
];

// ── S-box ─────────────────────────────────────────────────────────────────────

/// S-box: x^7 mod p. Spec §2.1: d=7 untuk Goldilocks.
#[inline]
fn sbox(x: u64) -> u64 {
    field_pow(x, SBOX_EXPONENT)
}

// ── Linear Layers ─────────────────────────────────────────────────────────────

/// M_E multiplication: circ(5,7,1,3) untuk full rounds.
/// Optimasi: result[i] = 2*state[i] + t*sum — dihitung tanpa loop.
fn mds_multiply_full(state: &[u64; WIDTH]) -> [u64; WIDTH] {
    // M_E = circ(5,7,1,3):
    // result[0] = 5*s[0] + 7*s[1] + 1*s[2] + 3*s[3]
    // result[1] = 3*s[0] + 5*s[1] + 7*s[2] + 1*s[3]
    // result[2] = 1*s[0] + 3*s[1] + 5*s[2] + 7*s[3]
    // result[3] = 7*s[0] + 1*s[1] + 3*s[2] + 5*s[3]
    //
    // Optimasi: sum = s[0]+s[1]+s[2]+s[3]
    // result[i] = sum + 4*s[i] + 2*s[(i+1)%4] + (s[(i+2)%4] yang hilang dikompensasi)
    // Lebih mudah: hitung langsung dengan MATRIX_FULL row-by-row.
    let mut result = [0u64; WIDTH];
    for i in 0..WIDTH {
        let mut acc = 0u64;
        for j in 0..WIDTH {
            let term = field_mul(MATRIX_FULL[i][j], state[j]);
            acc = field_add(acc, term);
        }
        result[i] = acc;
    }
    result
}

/// M_I multiplication untuk partial rounds.
/// M_I[i][i] = MAT_DIAG4_M_1[i] + 1, M_I[i][j] = 1 untuk i != j.
/// result[i] = sum(state) + state[i] * MAT_DIAG4_M_1[i]
#[inline]
fn mds_multiply_partial(state: &[u64; WIDTH]) -> [u64; WIDTH] {
    let sum = state.iter().fold(0u64, |acc, &x| field_add(acc, x));
    let mut result = [0u64; WIDTH];
    for i in 0..WIDTH {
        let diag_contrib = field_mul(state[i], MAT_DIAG4_M_1[i]);
        result[i] = field_add(sum, diag_contrib);
    }
    result
}

// ── Poseidon2 Permutation ─────────────────────────────────────────────────────

/// Poseidon2 permutation pada state width=4 Goldilocks.
///
/// Struktur: M_E → RF/2 full rounds → RP partial rounds → RF/2 full rounds.
/// Full rounds: AddRC + S-box-full + M_E.
/// Partial rounds: AddRC + S-box-partial (state[0] only) + M_I.
/// Spec §2.1: Poseidon2 in-circuit, ~200–400 constraints per operasi.
pub fn poseidon2_permutation(state: &mut [u64; WIDTH]) {
    let half_full = FULL_ROUNDS / 2; // 4

    // Initial linear layer (M_E) — Poseidon2 mengaplikasikan M_E sebelum round pertama
    *state = mds_multiply_full(state);

    // Full rounds pertama (rounds 0..4)
    for rc in ROUND_CONSTANTS.iter().take(half_full) {
        for (s, &c) in state.iter_mut().zip(rc.iter()) {
            *s = field_add(*s, c);
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        *state = mds_multiply_full(state);
    }

    // Partial rounds (rounds 4..26): S-box hanya pada state[0], M_I
    for rc in ROUND_CONSTANTS.iter().skip(half_full).take(PARTIAL_ROUNDS) {
        for (s, &c) in state.iter_mut().zip(rc.iter()) {
            *s = field_add(*s, c);
        }
        state[0] = sbox(state[0]);
        *state = mds_multiply_partial(state);
    }

    // Full rounds kedua (rounds 26..30)
    for rc in ROUND_CONSTANTS
        .iter()
        .skip(half_full + PARTIAL_ROUNDS)
        .take(half_full)
    {
        for (s, &c) in state.iter_mut().zip(rc.iter()) {
            *s = field_add(*s, c);
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        *state = mds_multiply_full(state);
    }
}

// ── Sponge Construction ───────────────────────────────────────────────────────
// Rate = 3, Capacity = 1. Padding: 10* (append 1, pad zeros, append 1).
// Fixing temuan #3: sponge tanpa padding membuka length-extension vulnerability.

/// Poseidon2 sponge dengan 10* padding. Rate=3, Capacity=1.
///
/// Padding rule (10*):
///   - Append bit 1 setelah input terakhir
///   - Pad zeros sampai blok penuh
///   - Jika satu blok cukup: append 1 di posisi terakhir blok
///
/// Ini memastikan setiap panjang input menghasilkan padding yang berbeda,
/// mencegah length-extension attack.
pub struct Poseidon2Hasher;

const RATE: usize = WIDTH - 1; // 3 — rate elements per absorb

impl Poseidon2Hasher {
    /// Hash slice of Goldilocks field elements dengan 10* padding. Spec §2.1.
    pub fn hash(input: &[u64]) -> [u64; 4] {
        let mut state = [0u64; WIDTH];

        // Buat padded input: append sentinel 1, pad zeros sampai kelipatan RATE
        let mut padded: Vec<u64> = input.iter().map(|&x| field_reduce(x)).collect();

        // 10* padding: tambah elemen 1, lalu pad zeros sampai kelipatan RATE
        padded.push(1u64);
        while !padded.len().is_multiple_of(RATE) {
            padded.push(0u64);
        }
        // Set bit terakhir blok terakhir = 1 (untuk membedakan dari zero padding)
        let last = padded.len() - 1;
        padded[last] = field_add(padded[last], 1u64);

        // Absorb: proses padded input dalam blok RATE=3 elemen
        for chunk in padded.chunks(RATE) {
            for (i, &elem) in chunk.iter().enumerate() {
                state[i] = field_add(state[i], elem);
            }
            poseidon2_permutation(&mut state);
        }

        // Squeeze: output 4 elemen — jalankan permutation kedua untuk elemen 2-3
        let out0 = state[0];
        let out1 = state[1];
        poseidon2_permutation(&mut state);
        [out0, out1, state[0], state[1]]
    }

    /// Hash bytes ke Goldilocks field elements dengan padding. Spec §2.1.
    pub fn hash_bytes_to_field(input: &[u8]) -> [u64; 4] {
        let mut field_elems: Vec<u64> = input
            .chunks(8)
            .map(|chunk| {
                let mut buf = [0u8; 8];
                buf[..chunk.len()].copy_from_slice(chunk);
                field_reduce(u64::from_le_bytes(buf))
            })
            .collect();

        if field_elems.is_empty() {
            field_elems.push(0);
        }

        Self::hash(&field_elems)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// In-circuit hash_2_to_1: Poseidon2([0, left, right]) → output[0].
///
/// Spec §2.1: operasi fundamental untuk commitment dan nullifier.
/// State layout: [capacity(1 elem) | left | right].
/// Tidak menggunakan sponge — ini adalah single-permutation call
/// untuk operasi fixed-arity in-circuit.
pub fn hash_2_to_1(left: u64, right: u64) -> u64 {
    let mut state = [0u64, field_reduce(left), field_reduce(right), 0u64];
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
        assert_eq!(GOLDILOCKS_PRIME, 0xFFFF_FFFF_0000_0001u64);
        let p = u64::MAX - (1u64 << 32) + 2;
        assert_eq!(GOLDILOCKS_PRIME, p);
    }

    #[test]
    fn test_field_add_normal() {
        assert_eq!(field_add(1, 2), 3);
        assert_eq!(field_add(0, 0), 0);
    }

    #[test]
    fn test_field_add_wraps_at_prime() {
        assert_eq!(field_add(GOLDILOCKS_PRIME - 1, 1), 0);
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
        let a = GOLDILOCKS_PRIME - 1;
        let b = GOLDILOCKS_PRIME - 1;
        let result = field_mul(a, b);
        assert!(result < GOLDILOCKS_PRIME);
        assert_eq!(result, 1);
    }

    #[test]
    fn test_field_sub_normal() {
        assert_eq!(field_sub(5, 3), 2);
        assert_eq!(field_sub(0, 0), 0);
    }

    #[test]
    fn test_field_sub_wraps() {
        assert_eq!(field_sub(0, 1), GOLDILOCKS_PRIME - 1);
    }

    // ── MDS matrix ────────────────────────────────────────────────────────────

    #[test]
    fn test_mds_matrix_correctness() {
        // M_E = circ(5,7,1,3) pada [1,1,1,1]:
        // setiap baris: 5+7+1+3 = 16
        let state = [1u64, 1u64, 1u64, 1u64];
        let result = mds_multiply_full(&state);
        assert_eq!(result, [16u64, 16u64, 16u64, 16u64]);
    }

    #[test]
    fn test_mds_matrix_zero_input() {
        let state = [0u64; WIDTH];
        let result = mds_multiply_full(&state);
        assert_eq!(result, [0u64; WIDTH]);
    }

    #[test]
    fn test_mds_partial_zero_input() {
        // M_I pada [0,0,0,0] = [0,0,0,0]
        let state = [0u64; WIDTH];
        let result = mds_multiply_partial(&state);
        assert_eq!(result, [0u64; WIDTH]);
    }

    #[test]
    fn test_mds_partial_unit() {
        // M_I pada [1,0,0,0]:
        // sum = 1
        // result[0] = 1 + 1*0 = 1
        // result[1] = 1 + 0*1 = 1
        // result[2] = 1 + 0*2 = 1
        // result[3] = 1 + 0*3 = 1
        let state = [1u64, 0u64, 0u64, 0u64];
        let result = mds_multiply_partial(&state);
        assert_eq!(result, [1u64, 1u64, 1u64, 1u64]);
    }

    // ── S-box ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_sbox_exponent_7() {
        assert_eq!(sbox(0), 0);
        assert_eq!(sbox(1), 1);
        assert_eq!(sbox(2), 128);
    }

    // ── Test vectors — wajib sesuai §15.3 ────────────────────────────────────

    #[test]
    fn test_permutation_zero_vector() {
        // TV_ZERO_OUT: permutation([0,0,0,0]) harus menghasilkan nilai yang diketahui.
        // Dihasilkan oleh Grain LFSR generator yang sama. Spec §15.3.
        let mut state = [0u64; WIDTH];
        poseidon2_permutation(&mut state);
        assert_eq!(
            state, TV_ZERO_OUT,
            "permutation([0,0,0,0]) tidak sesuai test vector"
        );
    }

    #[test]
    fn test_permutation_known_vector() {
        // TV_KNOWN_OUT: permutation([1,2,0,0]).
        let mut state = [1u64, 2u64, 0u64, 0u64];
        poseidon2_permutation(&mut state);
        assert_eq!(
            state, TV_KNOWN_OUT,
            "permutation([1,2,0,0]) tidak sesuai test vector"
        );
    }

    // ── Poseidon2 properties ──────────────────────────────────────────────────

    #[test]
    fn test_hash_2_to_1_deterministic() {
        let r1 = hash_2_to_1(100, 200);
        let r2 = hash_2_to_1(100, 200);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_hash_2_to_1_nonzero() {
        let result = hash_2_to_1(1, 2);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_hash_2_to_1_different_inputs() {
        let r1 = hash_2_to_1(1, 2);
        let r2 = hash_2_to_1(2, 1);
        let r3 = hash_2_to_1(1, 3);
        assert_ne!(r1, r2, "hash(1,2) != hash(2,1)");
        assert_ne!(r1, r3, "hash(1,2) != hash(1,3)");
    }

    #[test]
    fn test_hash_2_to_1_output_in_field() {
        let result = hash_2_to_1(GOLDILOCKS_PRIME - 1, GOLDILOCKS_PRIME - 2);
        assert!(result < GOLDILOCKS_PRIME);
    }

    #[test]
    fn test_hash_2_to_1_zero_inputs() {
        let r1 = hash_2_to_1(0, 0);
        let r2 = hash_2_to_1(0, 0);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_poseidon2_hasher_deterministic() {
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
        let mut state = [1u64, 2u64, 3u64, 4u64];
        let original = state;
        poseidon2_permutation(&mut state);
        assert_ne!(state, original);
    }

    #[test]
    fn test_permutation_output_in_field() {
        let mut state = [
            GOLDILOCKS_PRIME - 1,
            GOLDILOCKS_PRIME - 2,
            GOLDILOCKS_PRIME - 3,
            GOLDILOCKS_PRIME - 4,
        ];
        poseidon2_permutation(&mut state);
        for &s in &state {
            assert!(s < GOLDILOCKS_PRIME, "output harus < p: {}", s);
        }
    }

    #[test]
    fn test_nested_hash_commitment() {
        // Commit = hash_2_to_1(hash_2_to_1(secret, amount), pubkey)
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
        assert_eq!(
            hash_2_to_1(hash_2_to_1(node_lo, epoch), pou_domain),
            nullifier
        );
    }

    // ── Padding correctness ───────────────────────────────────────────────────

    #[test]
    fn test_padding_different_lengths_different_hashes() {
        // Padding harus memastikan input panjang berbeda menghasilkan hash berbeda.
        // Ini adalah property utama yang diperbaiki oleh temuan #3.
        let r1 = Poseidon2Hasher::hash(&[1u64]);
        let r2 = Poseidon2Hasher::hash(&[1u64, 0u64]);
        let r3 = Poseidon2Hasher::hash(&[1u64, 0u64, 0u64]);
        assert_ne!(r1, r2, "hash([1]) != hash([1,0])");
        assert_ne!(r2, r3, "hash([1,0]) != hash([1,0,0])");
        assert_ne!(r1, r3, "hash([1]) != hash([1,0,0])");
    }

    #[test]
    fn test_empty_input_deterministic() {
        let r1 = Poseidon2Hasher::hash(&[]);
        let r2 = Poseidon2Hasher::hash(&[]);
        assert_eq!(r1, r2);
    }
}
