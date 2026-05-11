//! Fuzz: Fee Floor Computation — Spec §9.1
//! Property: fee_floor selalu >= FLOOR_MIN_ABSOLUTE (40 sSCL)
//! Property: fee_floor tidak pernah overflow
#![no_main]
use libfuzzer_sys::fuzz_target;
use scalar_fees::floor::{compute_floor, FLOOR_MIN_ABSOLUTE};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 { return; }
    let num_inputs = (data[0] % 11) as u32; // 0-10
    let num_outputs = (data[1] % 11) as u32; // 0-10
    let complexity_weight = (data[2] as u64) + 1; // 1-256

    if num_inputs == 0 || num_outputs == 0 { return; }

    if let Ok(floor) = compute_floor(num_inputs, num_outputs, complexity_weight) {
        // P1: Floor selalu >= FLOOR_MIN_ABSOLUTE
        assert!(
            floor >= FLOOR_MIN_ABSOLUTE,
            "Floor {} < FLOOR_MIN_ABSOLUTE {} — spec §9.1 violated",
            floor, FLOOR_MIN_ABSOLUTE
        );
        // P2: Floor tidak pernah 0
        assert!(floor > 0, "Floor tidak boleh 0");
    }
});
