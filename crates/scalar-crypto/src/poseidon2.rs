/// Implementasi Poseidon2 dioptimalkan untuk Goldilocks Field.
/// p = 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;

pub const WIDTH_T: usize = 4;
pub const DEGREE_D: usize = 7;
pub const ROUNDS_FULL_RF: usize = 8;
pub const ROUNDS_PARTIAL_RP: usize = 22;

/// Merepresentasikan elemen dalam Goldilocks field
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GoldilocksElement(pub u64);

impl GoldilocksElement {
    pub fn new(val: u64) -> Self {
        // Reduksi modulo PRIME aman
        if val >= GOLDILOCKS_PRIME {
            Self(val - GOLDILOCKS_PRIME)
        } else {
            Self(val)
        }
    }

    /// Operasi perkalian dengan reduksi modulo Goldilocks
    pub fn mul(self, rhs: Self) -> Self {
        let (lo, hi) = mul_128(self.0, rhs.0);
        Self::new(reduce_128(lo, hi))
    }

    /// Operasi eksponensial x^7 untuk S-box Poseidon2 (karena d=7)
    pub fn exp7(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        let x6 = x4.mul(x2);
        x6.mul(self)
    }
}

/// Helper perkalian 64-bit -> 128-bit
#[inline]
fn mul_128(a: u64, b: u64) -> (u64, u64) {
    let res = (a as u128) * (b as u128);
    (res as u64, (res >> 64) as u64)
}

/// Helper reduksi 128-bit ke Goldilocks field (menggunakan trik 2^64 = 2^32 - 1)
#[inline]
fn reduce_128(lo: u64, hi: u64) -> u64 {
    // Implementasi simplifikasi reduksi untuk prototype
    let hi_hi = hi >> 32;
    let hi_lo = hi & 0xFFFFFFFF;

    let (mut res, overflow1) = lo.overflowing_sub(hi_hi);
    if overflow1 {
        res = res.wrapping_add(GOLDILOCKS_PRIME);
    }

    let t = hi_lo << 32;
    let (mut res2, overflow2) = res.overflowing_add(t);
    if overflow2 {
        res2 = res2.wrapping_sub(GOLDILOCKS_PRIME);
    }

    res2 % GOLDILOCKS_PRIME
}

pub struct Poseidon2State {
    pub state: [GoldilocksElement; WIDTH_T],
}

impl Poseidon2State {
    pub fn new(input: [GoldilocksElement; WIDTH_T]) -> Self {
        Self { state: input }
    }

    /// Permutasi Poseidon2 (Kerangka Logika)
    pub fn permute(&mut self) {
        // 1. First Half of Full Rounds
        for _ in 0..(ROUNDS_FULL_RF / 2) {
            self.full_round();
        }

        // 2. Partial Rounds
        for _ in 0..ROUNDS_PARTIAL_RP {
            self.partial_round();
        }

        // 3. Second Half of Full Rounds
        for _ in 0..(ROUNDS_FULL_RF / 2) {
            self.full_round();
        }
    }

    fn full_round(&mut self) {
        // SubWords (S-Box) diterapkan ke semua elemen (x^7)
        for i in 0..WIDTH_T {
            self.state[i] = self.state[i].exp7();
        }
        // Todo: AddRoundConstants & MixLayer (Matriks MDS)
    }

    fn partial_round(&mut self) {
        // SubWords hanya diterapkan ke elemen pertama
        self.state[0] = self.state[0].exp7();
        // Todo: AddRoundConstants & MixLayer
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goldilocks_math() {
        let a = GoldilocksElement::new(2);
        assert_eq!(a.exp7().0, 128); // 2^7 = 128

        // Cek boundary field
        let b = GoldilocksElement::new(GOLDILOCKS_PRIME);
        assert_eq!(b.0, 0);
    }

    #[test]
    fn test_poseidon_permutation_flow() {
        // Verifikasi bahwa state tidak crash saat diputar
        let out = hash_2_to_1(42, 84);
        assert!(out < GOLDILOCKS_PRIME);
    }
}
