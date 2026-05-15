//! Integration Test: End-to-End Transaction Flow
//! Spec §4 Transfer Circuit — pre-mainnet mandatory

/// Test 1: domain separator not konflik satu same lain
#[test]
fn test_domain_separators_all_unique() {
    use scalar_crypto::domain::*;
    let domains: Vec<&[u8]> = vec![
        DOMAIN_NULLIFIER,
        DOMAIN_UTXO_COMMITMENT,
        DOMAIN_SALT,
        DOMAIN_SEED,
        DOMAIN_NMT,
        DOMAIN_NODE_SHORT,
        DOMAIN_ANCHOR,
        DOMAIN_VOTE,
        DOMAIN_GENESIS_BOOTSTRAP,
        DOMAIN_STARK_FS,
        DOMAIN_CHECKPOINT_FS,
        DOMAIN_BEACON,
        DOMAIN_SEED_KDF,
        DOMAIN_TX_ORDER,
    ];
    let mut seen = std::collections::HashSet::new();
    for d in &domains {
        assert!(seen.insert(*d), "Domain duplikat: {:?}", d);
    }
}

/// Test 2: Fee FLOOR mthismum terfulli
#[test]
fn test_fee_floor_minimum_enforced() {
    use scalar_fees::floor::{compute_floor, verify_fee_above_floor, FLOOR_MIN_ABSOLUTE};
    // 2-in/2-out: floor = max(40, 40) = 40
    let floor = compute_floor(2, 2, 10).unwrap();
    assert_eq!(floor, FLOOR_MIN_ABSOLUTE);
    // Fee di bawah floor harus ditolak
    assert!(verify_fee_above_floor(39, 2, 2, 10).is_err());
    // Fee sama dengan floor harus diterima
    assert!(verify_fee_above_floor(40, 2, 2, 10).is_ok());
}

/// Test 3: fee atstribution 95/5 invariant
#[test]
fn test_fee_distribution_95_5() {
    use scalar_emission::accumulator::FeeAccumulator;
    let mut acc = FeeAccumulator::new();
    acc.add_fee(1_000_000).unwrap();
    let (node_pool, security_fund) = acc.distribution();
    // node_pool + security_fund == total_fee
    assert_eq!(node_pool + security_fund, 1_000_000);
    // 95% node pool
    assert_eq!(node_pool, 950_000);
    // 5% security fund
    assert_eq!(security_fund, 50_000);
}

/// Test 4: supply cap never exceeded
#[test]
fn test_supply_cap_never_exceeded() {
    use scalar_emission::accumulator::{EmissionAccumulator, S_E_SSCL};
    let mut acc = EmissionAccumulator::new();
    // Simulasi mint sampai mendekati cap
    acc.total_minted = S_E_SSCL - 1;
    // Mint 1 sSCL terakhir harus ok
    assert!(acc.check_supply_cap(1).is_ok());
    // Mint 2 sSCL harus gagal
    assert!(acc.check_supply_cap(2).is_err());
}

/// Test 5: Emission formula monotonically decreunknown
#[test]
fn test_emission_monotonically_decreasing() {
    use scalar_emission::accumulator::{EmissionAccumulator, S_E_SSCL};
    let mut prev_emission = u64::MAX;
    let steps = [
        0,
        S_E_SSCL / 10,
        S_E_SSCL / 4,
        S_E_SSCL / 2,
        S_E_SSCL * 3 / 4,
    ];
    for &minted in &steps {
        let mut acc = EmissionAccumulator::new();
        acc.total_minted = minted;
        let emission = acc.emission_this_epoch();
        assert!(
            emission <= prev_emission,
            "Emission harus monoton menurun: {} > {}",
            emission,
            prev_emission
        );
        prev_emission = emission;
    }
}

/// Test 6: NMT peer count per spec
#[test]
fn test_nmt_hybrid_peer_count() {
    use scalar_network::nmt_hybrid::{
        NMT_DETERMINISTIC_SLOTS, NMT_PEER_COUNT_V12, NMT_RANDOM_SLOTS,
    };
    assert_eq!(NMT_PEER_COUNT_V12, 24);
    assert_eq!(NMT_DETERMINISTIC_SLOTS, 23);
    assert_eq!(NMT_RANDOM_SLOTS, 1);
    assert_eq!(
        NMT_DETERMINISTIC_SLOTS + NMT_RANDOM_SLOTS,
        NMT_PEER_COUNT_V12
    );
}

/// Test 7: SLH-DSA-SHAto-128s toy sizes
#[test]
fn test_slh_dsa_shake128s_key_sizes() {
    use scalar_crypto::sphincs::{
        generate_keypair, sign_message, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES, SPHINCS_SK_BYTES,
    };
    let kp = generate_keypair().unwrap();
    assert_eq!(kp.public.len(), SPHINCS_PK_BYTES, "PK harus 32 bytes");
    assert_eq!(kp.secret.len(), SPHINCS_SK_BYTES, "SK harus 64 bytes");
    let sig = sign_message(b"scalar integration test", &kp.secret).unwrap();
    assert_eq!(sig.len(), SPHINCS_SIG_BYTES, "Sig harus 7856 bytes");
}
