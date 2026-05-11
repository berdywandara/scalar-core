//! Integration Test: Nullifier Lifecycle
//! Spec §6 NullifierSet — pre-mainnet mandatory

/// Test 1: Nullifier baru tidak ada di set kosong
#[test]
fn test_new_nullifier_not_in_empty_set() {
    use scalar_nullifier::formal::assert_cc_invariant;
    let nullifier = [0x01u8; 32];
    let result = assert_cc_invariant(&nullifier, false, false);
    assert!(result.is_ok(), "Nullifier baru harus non-member");
}

/// Test 2: Double-spend terdeteksi — nullifier di NS_ACTIVE
#[test]
fn test_double_spend_detected_active() {
    use scalar_nullifier::formal::assert_cc_invariant;
    let nullifier = [0x02u8; 32];
    let result = assert_cc_invariant(&nullifier, true, false);
    assert!(result.is_err(), "Nullifier di NS_ACTIVE harus ditolak");
}

/// Test 3: Double-spend terdeteksi — nullifier di NS_CHECKPOINT
#[test]
fn test_double_spend_detected_checkpoint() {
    use scalar_nullifier::formal::assert_cc_invariant;
    let nullifier = [0x03u8; 32];
    let result = assert_cc_invariant(&nullifier, false, true);
    assert!(result.is_err(), "Nullifier di NS_CHECKPOINT harus ditolak");
}

/// Test 4: Zero-Gap Property — nullifier harus masuk checkpoint sebelum keluar active
#[test]
fn test_zero_gap_property_enforced() {
    use scalar_nullifier::formal::assert_zero_gap_property;
    let nullifier = [0x04u8; 32];
    // Belum masuk checkpoint → gap violation
    assert!(assert_zero_gap_property(&nullifier, false).is_err());
    // Sudah masuk checkpoint → ok
    assert!(assert_zero_gap_property(&nullifier, true).is_ok());
}

/// Test 5: NS_WARM hash functions = 33, NS_COLD = 50
#[test]
fn test_bloom_filter_hash_functions() {
    use scalar_nullifier::bloom::{NS_COLD_HASH_FUNCTIONS, NS_WARM_HASH_FUNCTIONS};
    assert_eq!(NS_WARM_HASH_FUNCTIONS, 33, "NS_WARM k=33 per spec §6.3");
    assert_eq!(NS_COLD_HASH_FUNCTIONS, 50, "NS_COLD k=50 per spec §6.4");
}

/// Test 6: COLD_PROMOTION_EPOCH_THRESHOLD = 12
#[test]
fn test_cold_promotion_threshold() {
    use scalar_nullifier::hierarchical::COLD_PROMOTION_EPOCH_THRESHOLD;
    assert_eq!(COLD_PROMOTION_EPOCH_THRESHOLD, 12u64, "Spec §6.3");
}
