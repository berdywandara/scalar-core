//! Integration Test: Nullifier Lifecycle
//! Spec §6 NullifierSet 2-layer — pre-mainnet mandatory

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
    assert!(assert_zero_gap_property(&nullifier, false).is_err());
    assert!(assert_zero_gap_property(&nullifier, true).is_ok());
}

/// Test 5: NullifierSet 2-layer insert dan is_spent — spec §6.3
#[test]
fn test_nullifier_set_insert_and_is_spent() {
    use scalar_nullifier::NullifierSet;
    let mut ns = NullifierSet::new();
    let nullifier = [0x05u8; 32];
    assert!(!ns.is_spent(&nullifier), "Belum diinsert → tidak spent");
    ns.insert(&nullifier, 1);
    assert!(ns.is_spent(&nullifier), "Setelah insert → spent");
}

/// Test 6: NullifierSet checkpoint Zero-Gap — nullifier tetap ditemukan setelah arsip
#[test]
fn test_nullifier_set_checkpoint_zero_gap() {
    use scalar_nullifier::NullifierSet;
    let mut ns = NullifierSet::new();
    let nullifier = [0x06u8; 32];
    ns.insert(&nullifier, 1); // epoch 1
                              // Checkpoint di epoch 10: epoch 1 → umur=9 > 3 → arsip
    ns.checkpoint(10).unwrap();
    // Zero-Gap: nullifier harus tetap ditemukan di NS_CHECKPOINT
    assert!(
        ns.is_spent(&nullifier),
        "Zero-Gap: nullifier harus tetap is_spent setelah checkpoint"
    );
}

/// Test 7: NS_ACTIVE window = 3 epoch. OSSIFIED — spec §6.1.
#[test]
fn test_ns_active_window_epochs() {
    use scalar_nullifier::NS_ACTIVE_WINDOW_EPOCHS;
    assert_eq!(NS_ACTIVE_WINDOW_EPOCHS, 3u64, "Spec §6.1: 3 epoch terakhir");
}

/// Test 8: Checkpoint interval = 3 epoch. OSSIFIED — spec §6, §17.
#[test]
fn test_checkpoint_interval_epochs() {
    use scalar_nullifier::CHECKPOINT_INTERVAL_EPOCHS;
    assert_eq!(CHECKPOINT_INTERVAL_EPOCHS, 3u64, "Spec §6, §17");
}

/// Test 9: MAX_NULLIFIERS_PER_CHECKPOINT = 200_000. OSSIFIED — spec §6, §17.
#[test]
fn test_max_nullifiers_per_checkpoint() {
    use scalar_nullifier::MAX_NULLIFIERS_PER_CHECKPOINT;
    assert_eq!(MAX_NULLIFIERS_PER_CHECKPOINT, 200_000usize, "Spec §6, §17");
}

/// Test 10: CheckpointProof struct fields sesuai spec §6.2
#[test]
fn test_checkpoint_proof_struct_spec() {
    use scalar_nullifier::CheckpointProof;
    let cp = CheckpointProof::genesis();
    assert_eq!(cp.smt_depth, 32, "SMT depth = 32 — spec §6.2");
    assert_eq!(cp.total_archived_count, 0, "Genesis: 0 archived");
    assert_eq!(cp.archived_smt_root, [0u8; 32], "Genesis: root zero");
}
