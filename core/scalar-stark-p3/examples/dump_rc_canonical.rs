//! Extract canonical Poseidon2 RC dari p3-goldilocks config yang dipakai Scalar.
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_symmetric::Permutation;

fn main() {
    use scalar_stark_p3::config::build_poseidon2_perm;

    // Generate multiple test vectors untuk validasi RC di Python
    let inputs: Vec<[u64; 8]> = vec![
        [0; 8],
        [1, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 1, 1, 1, 1],
        [100, 200, 300, 400, 500, 600, 700, 800],
    ];

    println!("POSEIDON2_TEST_VECTORS = [");
    for inp in &inputs {
        let perm = build_poseidon2_perm();
        let mut state: [Goldilocks; 8] = core::array::from_fn(|i| Goldilocks::new(inp[i]));
        perm.permute_mut(&mut state);
        let out: Vec<u64> = state.iter().map(|x| x.as_canonical_u64()).collect();
        print!("    {{'input': {:?}, 'output': {:?}}},", inp.to_vec(), out);
        println!();
    }
    println!("]");
    println!();
    println!("# Tempel di poseidon2.py untuk validasi RC");
    println!("# Jika RC benar: semua test vector akan match");
}
