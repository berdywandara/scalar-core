//! C5 & C6: Value Conservation & Non-Negativity
//! C5: Sum(Inputs) == Sum(Outputs) + Fee
//! C6: Range Proof (0 <= value < 2^64)

pub fn enforce_value_conservation(inputs: &[u64], outputs: &[u64], fee: u64) -> bool {
    let sum_in: u64 = inputs.iter().sum();
    let sum_out: u64 = outputs.iter().sum();
    sum_in == sum_out + fee
}

pub fn enforce_range_proof(value: u64) -> bool {
    // Memastikan nilai berada di dalam Goldilocks field prime: p = 2^64 - 2^32 + 1
    value < 0xFFFFFFFF00000001
}
