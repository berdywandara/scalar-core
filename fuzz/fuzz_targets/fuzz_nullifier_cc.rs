//! Fuzz: Nullifier CC Invariant — Spec §15.4
//! Property: assert_cc_invariant selalu konsisten
//! Property: non-member selalu Ok, member selalu Err
#![no_main]
use libfuzzer_sys::fuzz_target;
use scalar_nullifier::formal::assert_cc_invariant;

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 { return; }

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&data[0..32]);
    let in_active = data[32] & 0x01 != 0;
    let in_checkpoint = data[33] & 0x01 != 0;

    let result = assert_cc_invariant(&nullifier, in_active, in_checkpoint);

    if !in_active && !in_checkpoint {
        // P1: Non-member selalu Ok
        assert!(result.is_ok(), "Non-member harus Ok — spec §15.4");
    } else {
        // P2: Member (active atau checkpoint) selalu Err
        assert!(result.is_err(), "Member harus Err (double-spend) — spec §15.4");
    }

    // P3: Hasil deterministik untuk input yang sama
    let result2 = assert_cc_invariant(&nullifier, in_active, in_checkpoint);
    assert_eq!(
        result.is_ok(), result2.is_ok(),
        "CC invariant harus deterministik — spec §15.4"
    );
});
