//! Integration Test: Emission Epoch
//! Spec §7 PoU Emission — pre-mainnet mandatory

/// Test 1: E0 = 126,000 SCL/epoch
#[test]
fn test_e0_value() {
    use scalar_emission::accumulator::E0_SSCL;
    assert_eq!(E0_SSCL, 12_600_000_000_000u64, "E0 = 126,000 SCL per spec §7.1");
}

/// Test 2: S_E = 18,900,000 SCL
#[test]
fn test_s_e_value() {
    use scalar_emission::accumulator::S_E_SSCL;
    assert_eq!(S_E_SSCL, 1_890_000_000_000_000u64, "S_E per spec §3.2");
}

/// Test 3: E_TAIL = 1,000 SCL
#[test]
fn test_e_tail_value() {
    use scalar_emission::accumulator::E_TAIL_SSCL;
    assert_eq!(E_TAIL_SSCL, 100_000_000_000u64, "E_TAIL per spec §7.7");
}

/// Test 4: Emission = 0 ketika pool habis
#[test]
fn test_emission_zero_at_cap() {
    use scalar_emission::accumulator::{EmissionAccumulator, S_E_SSCL};
    let mut acc = EmissionAccumulator::new();
    acc.total_minted = S_E_SSCL;
    assert_eq!(acc.emission_this_epoch(), 0, "Emission harus 0 saat pool habis");
}

/// Test 5: Heartbeat per epoch = 4,320
#[test]
fn test_heartbeats_per_epoch() {
    use scalar_emission::liveness::EXPECTED_HEARTBEATS_PER_EPOCH;
    assert_eq!(EXPECTED_HEARTBEATS_PER_EPOCH, 4_320u32, "4320 HB/epoch per spec §7.2");
}

/// Test 6: W_MATURE_EPOCHS = 6
#[test]
fn test_w_mature_epochs() {
    use scalar_emission::liveness::W_MATURE_EPOCHS;
    assert_eq!(W_MATURE_EPOCHS, 6u64, "6 epoch maturity per spec §7.4");
}

/// Test 7: Deferred pool max release = 10% E0
#[test]
fn test_deferred_pool_max_release() {
    use scalar_emission::formal::DEFERRED_POOL_MAX_RELEASE;
    use scalar_emission::accumulator::E0_SSCL;
    assert_eq!(DEFERRED_POOL_MAX_RELEASE, E0_SSCL / 10,
        "Max release = 10% E0 per spec §15.5");
}
