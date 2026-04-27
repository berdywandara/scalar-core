// crates/scalar-crypto/src/poseidon2.rs
// Poseidon2 untuk Goldilocks Field (p = 2^64 - 2^32 + 1)
// Parameter: t=4, d=7, RF=8, RP=22 — sesuai Concept 5 GAP-009 & Final Spec

pub const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;
pub const WIDTH_T: usize = 4;
pub const DEGREE_D: usize = 7;
pub const ROUNDS_FULL_RF: usize = 8;
pub const ROUNDS_PARTIAL_RP: usize = 22;

// --- ROUND CONSTANTS & MATRICES GENERATED EXPLICITLY FOR SCALAR NETWORK ---
pub const ROUND_CONSTANTS: [u64; 120] = [
    0xe82190d0cedb700e, 0x0aabb8eb9345494f, 0xd586a09c4e410c50, 0x88ce908709975136,
    0x8466ca66abda0321, 0x3857e99f3e126bdd, 0xf332f4f3fff1e049, 0x33441aecfd2c6545,
    0xb38f52c83ee7ca7d, 0x298aaec4e6e8cfc3, 0xd9eb07330812935e, 0x87d070c0fe77bd49,
    0x7517d6ed649b38a6, 0x365bab2703a3218b, 0x354160d4cc8b4ed7, 0x40fe49dbc6cd68ba,
    0xc4f6327bc124b0ee, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x58c3b863305ac4ff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x5e0df49eefb8a619, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0c2e6d2b539725cb, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xbb2e44775c85d864, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x065019efce55cbea, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xc51d4489641e12a6, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x6acfddc6b64b31f2, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xa8972a520412604e, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x1864c84e3aacab43, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xc5623fbb936f0216, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xc79da8f34e59f5e1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xe286ce88c32ab2a7, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x506c0ca54056a1f5, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x7154bf6d46e8bcdb, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xc067f50650e2565e, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x644903d979ccd860, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x030aafc50e936e0d, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0xd56001c6383c49bd, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x6eaa8e79299537e0, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x3e121c96ddb80fcb, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x7927dc08b8b23ae4, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x13f9f91342b361c3, 0x2e834b590e16ea71, 0x6bc53d74a3056670, 0xb305d1275930ed04,
    0x82ff6dcbe10e60be, 0xea7e605d9e787cda, 0x8782bd7097e96e4c, 0x08592b28bf061b1a,
    0xb65df388bd64b067, 0xc28a3773844b98d5, 0x01aaed9cb3c650f5, 0x9ff56521040d049a,
    0xd122eb77a6f33f03, 0x4cd06d2959c7175b, 0xbddd5439bfb38b05, 0xadf19baf3eb0c020,
];

pub const MATRIX_FULL: [[u64; 4]; 4] = [
    [0x0000000000000005, 0x0000000000000007, 0x0000000000000001, 0x0000000000000003],
    [0x0000000000000004, 0x0000000000000006, 0x0000000000000001, 0x0000000000000001],
    [0x0000000000000001, 0x0000000000000003, 0x0000000000000005, 0x0000000000000007],
    [0x0000000000000001, 0x0000000000000001, 0x0000000000000004, 0x0000000000000006],
];

pub const MATRIX_PARTIAL: [[u64; 4]; 4] = [
    [0xdf21f047f4146b7b, 0x0000000000000001, 0x0000000000000001, 0x0000000000000001],
    [0x0000000000000001, 0x2005a6ff8efd1d39, 0x0000000000000001, 0x0000000000000001],
    [0x0000000000000001, 0x0000000000000001, 0x636056de7eee6b6c, 0x0000000000000001],
    [0x0000000000000001, 0x0000000000000001, 0x0000000000000001, 0x4d2f4818eb0f40d3],
];

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GoldilocksElement(pub u64);

impl GoldilocksElement {
    pub fn new(val: u64) -> Self {
        Self(val % GOLDILOCKS_PRIME)
    }

    pub fn add(self, rhs: Self) -> Self {
        // Menggunakan u128 untuk mencegah overflow 64-bit yang merusak modulus
        let sum = (self.0 as u128) + (rhs.0 as u128);
        Self((sum % (GOLDILOCKS_PRIME as u128)) as u64)
    }

    pub fn mul(self, rhs: Self) -> Self {
        // Menggunakan u128 exact modulo untuk menjamin presisi kriptografis absolut
        let prod = (self.0 as u128) * (rhs.0 as u128);
        Self((prod % (GOLDILOCKS_PRIME as u128)) as u64)
    }

    /// S-box: x^7 sesuai d=7 dari spesifikasi Poseidon2
    pub fn exp7(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        let x6 = x4.mul(x2);
        x6.mul(self)
    }
}

pub struct Poseidon2State {
    pub state: [GoldilocksElement; WIDTH_T],
}

impl Poseidon2State {
    pub fn new(input: [GoldilocksElement; WIDTH_T]) -> Self {
        Self { state: input }
    }

    /// Permutasi Poseidon2 lengkap: RF full rounds + RP partial rounds
    /// Menggunakan alur MDS Matrix khusus Poseidon2
    pub fn permute(&mut self) {
        let mut rc_counter = 0;

        // 1. Initial matrix mix (Poseidon2 explicit optimization feature)
        self.apply_matrix(&MATRIX_FULL);

        // 2. First half of full rounds
        for _ in 0..(ROUNDS_FULL_RF / 2) {
            for i in 0..WIDTH_T {
                self.state[i] = self.state[i].add(GoldilocksElement::new(ROUND_CONSTANTS[rc_counter]));
                rc_counter += 1;
            }
            for i in 0..WIDTH_T {
                self.state[i] = self.state[i].exp7();
            }
            self.apply_matrix(&MATRIX_FULL);
        }

        // 3. Middle partial rounds
        for _ in 0..ROUNDS_PARTIAL_RP {
            for i in 0..WIDTH_T {
                self.state[i] = self.state[i].add(GoldilocksElement::new(ROUND_CONSTANTS[rc_counter]));
                rc_counter += 1;
            }
            // S-box hanya di elemen pertama
            self.state[0] = self.state[0].exp7();
            self.apply_matrix(&MATRIX_PARTIAL);
        }

        // 4. Second half of full rounds
        for _ in 0..(ROUNDS_FULL_RF / 2) {
            for i in 0..WIDTH_T {
                self.state[i] = self.state[i].add(GoldilocksElement::new(ROUND_CONSTANTS[rc_counter]));
                rc_counter += 1;
            }
            for i in 0..WIDTH_T {
                self.state[i] = self.state[i].exp7();
            }
            self.apply_matrix(&MATRIX_FULL);
        }
    }

    /// Terapkan perkalian matriks linear (mengganti MDS Mix klasik)
    pub fn apply_matrix(&mut self, matrix: &[[u64; WIDTH_T]; WIDTH_T]) {
        let old_state = self.state;
        for i in 0..WIDTH_T {
            let mut sum = GoldilocksElement::new(0);
            for j in 0..WIDTH_T {
                let scalar = GoldilocksElement::new(matrix[i][j]);
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
    fn test_nullifier_and_commitment_distinct() {
        let nullifier = hash_nullifier_circuit(123, 456);
        let commitment = hash_commitment(100, 123, 789);
        assert_ne!(nullifier, commitment);
    }
}

#[cfg(test)]
mod reference_vectors {
    use super::*;

    pub const EXPECTED_ZERO_HASH: [u64; 4] = [
        0xf369ebf05abcd441, 0x0d4b6187b76e50ee, 0x2af4b2aeb3347d25, 0xfec8567ddeb4aebb
    ];

    pub const EXPECTED_KNOWN_HASH: [u64; 4] = [
        0xa0fb1e1ee52225ec, 0x1a28093158f3bd78, 0xb60b8080419957b6, 0x0db01e96201b6655
    ];

    #[test]
    fn test_goldilocks_prime_constant() {
        assert_eq!(
            GOLDILOCKS_PRIME, 0xFFFFFFFF00000001,
            "Kesalahan fatal: Prime modulus bukan Goldilocks Field!"
        );
    }

    #[test]
    fn test_poseidon2_zero_input_vector() {
        let mut poseidon = Poseidon2State::new([
            GoldilocksElement::new(0),
            GoldilocksElement::new(0),
            GoldilocksElement::new(0),
            GoldilocksElement::new(0),
        ]);
        poseidon.permute();
        
        let result = [
            poseidon.state[0].0,
            poseidon.state[1].0,
            poseidon.state[2].0,
            poseidon.state[3].0,
        ];
        
        assert_eq!(
            result, EXPECTED_ZERO_HASH,
            "GAP-T01: Zero hash failed! Implementasi permutasi salah."
        );
    }

    #[test]
    fn test_poseidon2_known_input_vector() {
        let mut poseidon = Poseidon2State::new([
            GoldilocksElement::new(1),
            GoldilocksElement::new(2),
            GoldilocksElement::new(0),
            GoldilocksElement::new(0),
        ]);
        poseidon.permute();
        
        let result = [
            poseidon.state[0].0,
            poseidon.state[1].0,
            poseidon.state[2].0,
            poseidon.state[3].0,
        ];
        
        assert_eq!(
            result, EXPECTED_KNOWN_HASH,
            "GAP-T01: Known hash failed! Implementasi permutasi salah."
        );
    }

    #[test]
    fn test_poseidon2_mds_matrix_consistency() {
        let mut poseidon = Poseidon2State::new([
            GoldilocksElement::new(1),
            GoldilocksElement::new(2),
            GoldilocksElement::new(3),
            GoldilocksElement::new(4),
        ]);
        
        let state_before = poseidon.state;
        poseidon.apply_matrix(&MATRIX_FULL);
        
        assert_ne!(state_before, poseidon.state, "Matriks MDS gagal mentransformasi state (Singular/Identitas)!");
    }
}