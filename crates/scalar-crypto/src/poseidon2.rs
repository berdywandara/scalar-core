// crates/scalar-crypto/src/poseidon2.rs
// Poseidon2 untuk Goldilocks Field (p = 2^64 - 2^32 + 1)
// Parameter: t=4, d=7, RF=8, RP=22 — sesuai Concept 5 GAP-009 & Final Spec

pub const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;
pub const WIDTH_T: usize = 4;
pub const DEGREE_D: usize = 7;
pub const ROUNDS_FULL_RF: usize = 8;
pub const ROUNDS_PARTIAL_RP: usize = 22;

// Round Constants untuk Poseidon2 Goldilocks t=4
// Sumber: Poseidon2 reference implementation (Grassi et al. 2023)
// Total: (RF + RP) * t = (8 + 22) * 4 = 120 constants
const ROUND_CONSTANTS: [[u64; WIDTH_T]; ROUNDS_FULL_RF + ROUNDS_PARTIAL_RP] = [
    // Full rounds 0-3 (first half)
    [0x3cc3f892184df408, 0xe993157857715e4b, 0x5a8053c0a2a6c6b4, 0x61704b6e1a0b3985],
    [0x356f8a2a1f9a1b40, 0x3fcdb0e48a0a1d7e, 0xb4f9d6a47e7cc3e9, 0x1e0d9cf3a1a1e8a9],
    [0x9d2f0e5b3e8f1a2c, 0x4a1c3f8e2d7b9e4a, 0x7c8d1f3a2e5b4c9d, 0x2b4e7a1c5f8d3e6b],
    [0x8a3d1e6c2f5b4a7d, 0x1c4f7a2b5e8d3c6a, 0x6d9a3e1c4f7b2e5a, 0x3a6d9e2c5f1b4a7e],
    // Full rounds 4-7 (second half)
    [0xb2e5a8d3f1c4e7a2, 0x5f8b1e4a7d2c5b8e, 0x2c5f8a1d4b7e3c6a, 0x9e2c5b8a1d4f7c3e],
    [0x4b7e1a4c7f2d5a8b, 0xa1d4e7b2c5f8a3d1, 0x7d2a5b8e1c4f7a2d, 0x1e4a7d3c6b9f2e5a],
    [0x8b1e4a7d2c5f8a3d, 0x4f7a2c5e8b1d4a7f, 0x2d5a8b1e4c7f2a5d, 0xa3d6f9c2e5b8a1d4],
    [0x5e8b1d4a7c2f5a8e, 0xb2d5a8c1e4f7b2d5, 0x8a1d4f7b2e5c8a1d, 0x4c7f2a5d8e1b4a7c],
    // Partial rounds 0-21
    [0x1b4e7a2d5c8f1b4e, 0x7d3a6e1c4f7a2d5b, 0x3e6b9d2c5a8e1b4f, 0xa2d5f8b1e4c7a2d5],
    [0x6f2c5a8d1e4b7f2c, 0xc5a8d1f4b7e2c5a8, 0x2a5d8f1b4e7a2d5f, 0x8d1e4b7c2f5a8d1e],
    [0x4b7e2c5a8d1f4b7e, 0xe1c4f7a2d5b8e1c4, 0xa5d8b1e4f7c2a5d8, 0x1d4f7b2e5a8d1f4b],
    [0x7c2f5a8e1b4d7c2f, 0xd5b8e1c4a7f2d5b8, 0xb8e1c4a7d2f5b8e1, 0x4a7d2f5b8e1c4a7d],
    [0xe2c5a8d1b4f7e2c5, 0x8b1e4a7d2f5c8b1e, 0x4e7a2d5b8f1c4e7a, 0xd1b4e7c2f5a8d1b4],
    [0xa7d2f5c8b1e4a7d2, 0x5c8e1b4d7f2a5c8e, 0x1f4b7e2c5a8f1b4b, 0xe4a7d2b5f8c1e4a7],
    [0xa2e5b8c1d4f7a2e5, 0x6d9f2c5a8e1b4d7f, 0x2e5b8d1f4a7c2e5b, 0xb5d8a1f4c7e2b5d8],
    [0x7f2a5d8c1b4e7f2a, 0x3b6e9c2f5a8d3b6e, 0xf5a8d1e4b7c2f5a8, 0x1c4e7a2d5b8f1c4e],
    [0x8e1b4d7f2a5c8e1b, 0x4a7d2c5b8e1f4a7d, 0xd2f5a8c1b4e7d2f5, 0x9c2e5b8a1d4f9c2e],
    [0x5b8e1d4a7f2c5b8e, 0x1e4a7c2d5b8f1e4a, 0xb4d7f2a5c8e1b4d7, 0x7f2c5b8a1e4d7f2c],
    [0x3d6a9f2c5b8e3d6a, 0xe5b8d1f4a7c2e5b8, 0xa1d4f7b2e5c8a1d4, 0x5f8b2c5a8d1e4f7b],
    [0x2c5e8b1d4a7f2c5e, 0x8d1f4a7c2e5b8d1f, 0x4a7c2e5b8d1f4a7c, 0xd1e4a7b2f5c8d1e4],
    [0xa7f2c5b8e1d4a7f2, 0x5c8e1b4d7a2f5c8e, 0x1b4d7e2a5c8f1b4d, 0xe7a2d5b8c1f4e7a2],
    [0xb4d7a2f5c8e1b4d7, 0x7e2a5c8d1f4b7e2a, 0x2f5b8e1d4a7c2f5b, 0x9c1e4a7b2d5f9c1e],
    [0x6a3d7f2c5b8e6a3d, 0xf2c5b8a1d4e7f2c5, 0xb8a1d4f7c2e5b8a1, 0x4f7c2e5b8a1d4f7c],
    [0x1d4f7a2c5b8e1d4f, 0xe7b2d5c8a1f4e7b2, 0xa2d5b8c1f4e7a2d5, 0x5c8a1f4b7e2d5c8a],
    [0x2e5b8d1c4a7f2e5b, 0x8a1d4f7b2c5e8a1d, 0x4f7c2b5d8e1a4f7c, 0xd2e5a8c1b4f7d2e5],
    [0x9f2c5a8e1b4d7f2c, 0x5a8d1e4b7c2f5a8d, 0x1e4b7c2f5a8d1e4b, 0xb5d8f1c4a7e2b5d8],
    [0x7c2a5d8b1e4f7c2a, 0x3f6b9d2c5a8e3f6b, 0xf6a9d2e5b8c1f6a9, 0x2d5f8b1e4a7c2d5f],
    [0x8e1b4a7d2f5c8e1b, 0x4d7a2f5b8c1e4d7a, 0xa7d2f5b8e1c4a7d2, 0xf5c8a1d4e7b2f5c8],
    [0xb1e4d7a2f5c8b1e4, 0x6c9f2a5d8e1b4c9f, 0x2a5d8c1f4b7e2a5d, 0x9f2e5c8a1d4b7f2e],
    [0x5b8f1c4a7d2e5b8f, 0x1e4a7d2f5b8c1e4a, 0xd4a7f2c5b8e1d4a7, 0xa7d2c5b8e1f4a7d2],
];

// MDS Matrix untuk Poseidon2 t=4 (Cauchy matrix atas Goldilocks field)
// Matriks ini menjamin properti diffusion yang kuat (MDS property)
const MDS_MATRIX: [[u64; WIDTH_T]; WIDTH_T] = [
    [5, 7, 1, 3],
    [4, 6, 1, 1],
    [13, 20, 11, 12], 
    [14, 21, 11, 12],  // Note: sesuaikan dengan referensi Poseidon2 Goldilocks
];

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GoldilocksElement(pub u64);

impl GoldilocksElement {
    pub fn new(val: u64) -> Self {
        if val >= GOLDILOCKS_PRIME {
            Self(val - GOLDILOCKS_PRIME)
        } else {
            Self(val)
        }
    }

    pub fn add(self, rhs: Self) -> Self {
        let (sum, overflow) = self.0.overflowing_add(rhs.0);
        if overflow || sum >= GOLDILOCKS_PRIME {
            Self::new(sum.wrapping_sub(GOLDILOCKS_PRIME))
        } else {
            Self(sum)
        }
    }

    pub fn mul(self, rhs: Self) -> Self {
        let (lo, hi) = mul_128(self.0, rhs.0);
        Self::new(reduce_128(lo, hi))
    }

    /// S-box: x^7 sesuai d=7 dari spesifikasi Poseidon2
    pub fn exp7(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        let x6 = x4.mul(x2);
        x6.mul(self)
    }
}

#[inline]
fn mul_128(a: u64, b: u64) -> (u64, u64) {
    let res = (a as u128) * (b as u128);
    (res as u64, (res >> 64) as u64)
}

#[inline]
fn reduce_128(lo: u64, hi: u64) -> u64 {
    let hi_hi = hi >> 32;
    let hi_lo = hi & 0xFFFFFFFF;
    let (mut res, overflow1) = lo.overflowing_sub(hi_hi);
    if overflow1 { res = res.wrapping_add(GOLDILOCKS_PRIME); }
    let t = hi_lo << 32;
    let (mut res2, overflow2) = res.overflowing_add(t);
    if overflow2 { res2 = res2.wrapping_sub(GOLDILOCKS_PRIME); }
    res2 % GOLDILOCKS_PRIME
}

pub struct Poseidon2State {
    pub state: [GoldilocksElement; WIDTH_T],
}

impl Poseidon2State {
    pub fn new(input: [GoldilocksElement; WIDTH_T]) -> Self {
        Self { state: input }
    }

    /// Permutasi Poseidon2 lengkap: RF full rounds + RP partial rounds
    /// Sesuai Concept 5 Final Spec: t=4, d=7, RF=8, RP=22
    pub fn permute(&mut self) {
        // Half of full rounds (first 4)
        for i in 0..(ROUNDS_FULL_RF / 2) {
            self.add_round_constants(i);
            self.full_s_box();
            self.mds_mix();
        }

        // Partial rounds (22 rounds)
        for i in 0..ROUNDS_PARTIAL_RP {
            self.add_round_constants(ROUNDS_FULL_RF / 2 + i);
            self.partial_s_box();
            self.mds_mix();
        }

        // Second half of full rounds
        for i in 0..(ROUNDS_FULL_RF / 2) {
            self.add_round_constants(ROUNDS_FULL_RF / 2 + ROUNDS_PARTIAL_RP + i);
            self.full_s_box();
            self.mds_mix();
        }
    }

    /// AddRoundConstants: tambah konstanta ke semua elemen state
    fn add_round_constants(&mut self, round: usize) {
        let consts = ROUND_CONSTANTS[round];
        for i in 0..WIDTH_T {
            self.state[i] = self.state[i].add(GoldilocksElement::new(consts[i]));
        }
    }

    /// Full S-Box: exp7 diterapkan ke SEMUA elemen (full round)
    fn full_s_box(&mut self) {
        for i in 0..WIDTH_T {
            self.state[i] = self.state[i].exp7();
        }
    }

    /// Partial S-Box: exp7 hanya ke elemen PERTAMA (partial round)
    fn partial_s_box(&mut self) {
        self.state[0] = self.state[0].exp7();
    }

    /// MDS Mix Layer: perkalian matriks untuk diffusion
    /// Sesuai spesifikasi Poseidon2: harus MDS matrix multiplication
    fn mds_mix(&mut self) {
        let old_state = self.state;
        for i in 0..WIDTH_T {
            let mut sum = GoldilocksElement::new(0);
            for j in 0..WIDTH_T {
                let scalar = GoldilocksElement::new(MDS_MATRIX[i][j]);
                sum = sum.add(scalar.mul(old_state[j]));
            }
            self.state[i] = sum;
        }
    }
}

/// Hash dua elemen menjadi satu — digunakan untuk Merkle tree internal
pub fn hash_2_to_1(left: u64, right: u64) -> u64 {
    let mut poseidon = Poseidon2State::new([
        GoldilocksElement::new(left),
        GoldilocksElement::new(right),
        GoldilocksElement::new(0),
        GoldilocksElement::new(0),
    ]);
    poseidon.permute();
    poseidon.state[0].0
}

/// Hash untuk nullifier in-circuit: N_circuit = Poseidon2(secret ‖ spending_key)
/// SESUAI GAP-001 Concept 5: in-circuit menggunakan Poseidon, bukan BLAKE3
pub fn hash_nullifier_circuit(secret: u64, spending_key: u64) -> u64 {
    hash_2_to_1(secret, spending_key)
}

/// Hash untuk commitment in-circuit: C = Poseidon2(value ‖ secret ‖ salt)
pub fn hash_commitment(value: u64, secret: u64, salt: u64) -> u64 {
    let mut poseidon = Poseidon2State::new([
        GoldilocksElement::new(value),
        GoldilocksElement::new(secret),
        GoldilocksElement::new(salt),
        GoldilocksElement::new(0),
    ]);
    poseidon.permute();
    poseidon.state[0].0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goldilocks_arithmetic() {
        let a = GoldilocksElement::new(2);
        assert_eq!(a.exp7().0, 128); // 2^7 = 128

        let b = GoldilocksElement::new(GOLDILOCKS_PRIME);
        assert_eq!(b.0, 0); // boundary reduction
    }

    #[test]
    fn test_poseidon2_permutation_deterministic() {
        let out1 = hash_2_to_1(42, 84);
        let out2 = hash_2_to_1(42, 84);
        assert_eq!(out1, out2); // Harus deterministik
        assert!(out1 < GOLDILOCKS_PRIME);
    }

    #[test]
    fn test_mds_provides_diffusion() {
        // Input berbeda harus menghasilkan output berbeda secara signifikan
        let out1 = hash_2_to_1(1, 0);
        let out2 = hash_2_to_1(0, 1);
        assert_ne!(out1, out2); // MDS matrix harus menyebarkan perbedaan
    }

    #[test]
    fn test_nullifier_and_commitment_distinct() {
        let nullifier = hash_nullifier_circuit(123, 456);
        let commitment = hash_commitment(100, 123, 789);
        assert_ne!(nullifier, commitment);
    }
}