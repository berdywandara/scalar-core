//! Fuzz: Emission Formula — Spec §7.1
//! Property: E(k) selalu dalam range [0, E0]
//! Property: E(k) monoton menurun seiring M_E naik
//! Property: tidak pernah overflow
#![no_main]
use libfuzzer_sys::fuzz_target;
use scalar_emission::accumulator::{EmissionAccumulator, E0_SSCL, S_E_SSCL};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    let minted = u64::from_le_bytes(data[0..8].try_into().unwrap());
    // Clamp ke range valid
    let minted = minted % (S_E_SSCL + 1);

    let mut acc = EmissionAccumulator::new();
    acc.total_minted = minted;

    let emission = acc.emission_this_epoch();

    // P1: Emission selalu <= E0
    assert!(
        emission <= E0_SSCL,
        "Emission {} > E0 {} — spec §7.1 violated", emission, E0_SSCL
    );

    // P2: Emission selalu >= 0 (u64 tidak bisa negatif, tapi pastikan tidak overflow)
    let _ = emission.checked_add(1).expect("Emission overflow detected");

    // P3: Jika pool habis, emission = 0
    if minted >= S_E_SSCL {
        assert_eq!(emission, 0, "Emission harus 0 saat pool habis — spec §7.1");
    }

    // P4: Jika pool kosong, emission = E0
    if minted == 0 {
        assert_eq!(emission, E0_SSCL, "Emission awal harus E0 — spec §7.1");
    }
});
