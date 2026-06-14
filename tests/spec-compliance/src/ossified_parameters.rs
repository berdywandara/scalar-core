//! Spec Compliance: Ossified Parameters
//! Verifikasi semua parameter OSSIFIED sesuai spec v11.1-FINAL §17

// ── §3.2 Supply ───────────────────────────────────────────────────────────────

#[test]
fn compliance_s_max() {
    assert_eq!(
        scalar_emission::accumulator::S_MAX_SSCL,
        2_100_000_000_000_000u64
    );
}

#[test]
fn compliance_s_e() {
    assert_eq!(
        scalar_emission::accumulator::S_E_SSCL,
        1_890_000_000_000_000u64
    );
}

#[test]
fn compliance_s_r() {
    assert_eq!(
        scalar_emission::accumulator::S_R_SSCL,
        210_000_000_000_000u64
    );
}

#[test]
fn compliance_e0() {
    assert_eq!(scalar_emission::accumulator::E0_SSCL, 12_600_000_000_000u64);
}

#[test]
fn compliance_e_tail() {
    assert_eq!(
        scalar_emission::accumulator::E_TAIL_SSCL,
        100_000_000_000u64
    );
}

// ── §2.4 Crypto Version ───────────────────────────────────────────────────────

#[test]
fn compliance_crypto_version_current() {
    assert_eq!(scalar_crypto::version::CURRENT_VERSION, 0x01u8);
}

#[test]
fn compliance_t_transition_epochs() {}

// ── §2.1 Signature Sizes ──────────────────────────────────────────────────────

#[test]
fn compliance_sphincs_pk_bytes() {
    assert_eq!(scalar_crypto::sphincs::SPHINCS_PK_BYTES, 32usize);
}

#[test]
fn compliance_sphincs_sk_bytes() {
    assert_eq!(scalar_crypto::sphincs::SPHINCS_SK_BYTES, 64usize);
}

#[test]
fn compliance_sphincs_sig_bytes() {
    assert_eq!(scalar_crypto::sphincs::SPHINCS_SIG_BYTES, 7_856usize);
}

// ── §7.2 Heartbeat ────────────────────────────────────────────────────────────

#[test]
fn compliance_heartbeats_per_epoch() {
    assert_eq!(
        scalar_emission::liveness::EXPECTED_HEARTBEATS_PER_EPOCH,
        4_320u32
    );
}

#[test]
fn compliance_w_mature_epochs() {
    // D-027: W_MATURE_EPOCHS is now derived via protocol_params::w_mature_epochs()
    assert_eq!(scalar_emission::protocol_params::w_mature_epochs(), 342u64);
}

// ── §9 Fee Model ──────────────────────────────────────────────────────────────

#[test]
fn compliance_floor_min_absolute() {
    assert_eq!(scalar_fees::floor::FLOOR_MIN_ABSOLUTE, 40u64);
}

#[test]
fn compliance_fee_node_pool_percent() {
    assert_eq!(scalar_fees::distribution::FEE_NODE_POOL_PERCENT, 95u64);
}

#[test]
fn compliance_fee_security_fund_percent() {
    assert_eq!(scalar_fees::distribution::FEE_SECURITY_FUND_PERCENT, 5u64);
}

#[test]
fn compliance_fee_split_sums_100() {
    assert_eq!(
        scalar_fees::distribution::FEE_NODE_POOL_PERCENT
            + scalar_fees::distribution::FEE_SECURITY_FUND_PERCENT,
        100u64
    );
}

// ── §6 NullifierSet ───────────────────────────────────────────────────────────

#[test]
fn compliance_ns_warm_k() {
    assert_eq!(
        scalar_nullifier::smt::MAX_NULLIFIERS_PER_CHECKPOINT,
        200_000usize
    );
}

#[test]
fn compliance_ns_cold_k() {
    assert_eq!(scalar_nullifier::SMT_DEPTH, 32usize);
}

#[test]
fn compliance_cold_promotion_threshold() {
    // TESTNET: CHECKPOINT_INTERVAL_EPOCHS = u64::MAX (ESKALASI-01 resolution).
    // Reverts to 3 after Phase 0 RecursiveVerifierAir is complete.
    // [SCALAR-TECHNICAL §7.3]
    assert_eq!(scalar_nullifier::CHECKPOINT_INTERVAL_EPOCHS, u64::MAX);
}

// ── §12.3 NMT ────────────────────────────────────────────────────────────────

#[test]
fn compliance_nmt_total_peers() {
    assert_eq!(scalar_network::nmt_hybrid::NMT_PEER_COUNT_V12, 24usize);
}

#[test]
fn compliance_nmt_deterministic_slots() {
    assert_eq!(scalar_network::nmt_hybrid::NMT_DETERMINISTIC_SLOTS, 23usize);
}

#[test]
fn compliance_nmt_random_slots() {
    assert_eq!(scalar_network::nmt_hybrid::NMT_RANDOM_SLOTS, 1usize);
}

// ── §11.7 Fork ────────────────────────────────────────────────────────────────

#[test]
fn compliance_fork_commit_threshold() {
    assert_eq!(scalar_network::fork::FORK_COMMIT_THRESHOLD_FP, 750_000u64);
}

#[test]
fn compliance_fork_abort_threshold() {
    assert_eq!(scalar_network::fork::FORK_ABORT_THRESHOLD_FP, 670_000u64);
}

#[test]
fn compliance_emergency_fork_lock_secs() {
    assert_eq!(scalar_network::fork::EMERGENCY_FORK_LOCK_SECS, 172_800u64);
}
