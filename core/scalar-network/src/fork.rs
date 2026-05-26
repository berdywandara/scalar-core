//! Fork Protocol — Spec §11.7
//!
//! STATE MACHINE:
//!   PENDING    → COMMITTED : signal_fraction ≥ 75%
//!   COMMITTED  → CANCELLED : abort_fraction ≥ 67%
//!   COMMITTED  → ACTIVE    : setelah activation_epoch tercapai
//!
//! NORMAL FORK: Lock 90d + Review 30d + Activation epoch+3
//! EMERGENCY FORK: Lock 48 jam, scope crypto primitives only, 51% threshold

use scalar_crypto::sphincs::verify_signature;
use std::collections::HashMap;
use scalar_crypto::domain::DOMAIN_VOTE;

pub const FORK_COMMIT_THRESHOLD_FP: u64 = 750_000;
pub const FORK_ABORT_THRESHOLD_FP: u64 = 670_000;
pub const EMERGENCY_FORK_COMMIT_THRESHOLD_FP: u64 = 510_000;
pub const FORK_LOCK_DAYS: u64 = 90;
pub const FORK_REVIEW_DAYS: u64 = 30;
pub const FORK_ACTIVATION_OFFSET_EPOCHS: u64 = 3;
pub const EMERGENCY_FORK_LOCK_SECS: u64 = 172_800;
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    Commit = 0,
    Abort = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSignalMessage {
    pub node_id: [u8; 32],
    pub epoch_id: u64,
    pub fork_hash: [u8; 32],
    pub signal_type: SignalType,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    /// NodeKey public key untuk verifikasi signature. Spec §11.1.
    pub public_key: Vec<u8>,
}

impl ForkSignalMessage {
    /// Compute canonical vote message untuk signature verification.
    /// Spec §2.3: domain separator b"scalar_vote" (11 byte).
    /// Spec §11.1: vote ditandatangani dengan NodeKey.
    pub fn vote_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(11 + 32 + 8 + 32 + 1);
        msg.extend_from_slice(DOMAIN_VOTE); // spec §2.3
        msg.extend_from_slice(&self.node_id);
        msg.extend_from_slice(&self.epoch_id.to_le_bytes());
        msg.extend_from_slice(&self.fork_hash);
        msg.push(self.signal_type as u8);
        msg
    }

    /// Verifikasi SLH-DSA signature atas vote message. Spec §11.1.
    pub fn verify_sig(&self) -> bool {
        if self.public_key.is_empty() || self.signature.is_empty() {
            return false;
        }
        let msg = self.vote_message();
        verify_signature(&msg, &self.signature, &self.public_key).unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkType {
    Normal,
    Emergency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkState {
    Pending,
    Committed { committed_epoch: u64 },
    Active { activation_epoch: u64 },
    Cancelled,
}

/// Per-node signal dengan governance power. Spec §11.2.
#[derive(Debug, Clone)]
pub struct NodeSignal {
    pub signal_type: SignalType,
    /// Governance power setelah cap Tier C. Spec §11.2, §10.1.
    /// TIER_C_MAX_GOV_POWER = 200_000 fp untuk Tier C nodes.
    pub governance_power_fp: u64,
}

/// Maximum governance power untuk Tier C. OSSIFIED — spec §10.1, §17.
pub const TIER_C_MAX_GOV_POWER: u64 = 200_000;

/// Prefix byte untuk Tier C node_id. OSSIFIED — spec §10.1.
pub const TIER_C_PREFIX: u8 = 0xFE;

#[derive(Debug, Clone)]
pub struct ForkProposal {
    pub fork_hash: [u8; 32],
    pub fork_type: ForkType,
    pub proposed_epoch: u64,
    pub proposed_timestamp: u64,
    pub state: ForkState,
    /// Per-node signals dengan governance power. Spec §11.2.
    pub signals: HashMap<[u8; 32], NodeSignal>,
    /// Total governance power dari semua eligible nodes. Spec §11.2.
    pub total_governance_power_fp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkError {
    ForkNotFound,
    ForkNotPending,
    AlreadyCommitted,
    ForkCancelled,
    ForkActive,
    InvalidEmergencyScope,
    ZeroTotalNodes,
    /// Signature SLH-DSA tidak valid. Spec §11.1.
    InvalidSignature,
}

impl core::fmt::Display for ForkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ForkNotFound => write!(f, "Fork tidak ditemukan"),
            Self::ForkNotPending => write!(f, "Fork tidak dalam state Pending"),
            Self::AlreadyCommitted => write!(f, "Fork sudah committed"),
            Self::ForkCancelled => write!(f, "Fork sudah cancelled"),
            Self::ForkActive => write!(f, "Fork sudah active"),
            Self::InvalidEmergencyScope => {
                write!(f, "Emergency fork hanya untuk crypto primitives")
            }
            Self::ZeroTotalNodes => write!(f, "Total nodes tidak boleh 0"),
            Self::InvalidSignature => write!(f, "Invalid SLH-DSA signature — spec §11.1"),
        }
    }
}

impl ForkProposal {
    pub fn new(
        fork_hash: [u8; 32],
        fork_type: ForkType,
        proposed_epoch: u64,
        proposed_timestamp: u64,
        total_governance_power_fp: u64,
    ) -> Self {
        Self {
            fork_hash,
            fork_type,
            proposed_epoch,
            proposed_timestamp,
            state: ForkState::Pending,
            signals: HashMap::new(),
            total_governance_power_fp,
        }
    }

    pub fn add_signal(
        &mut self,
        msg: &ForkSignalMessage,
        governance_power_fp: u64,
    ) -> Result<(), ForkError> {
        match self.state {
            ForkState::Cancelled => return Err(ForkError::ForkCancelled),
            ForkState::Active { .. } => return Err(ForkError::ForkActive),
            _ => {}
        }
        // Temuan #9: verifikasi SLH-DSA signature sebelum accept vote. Spec §11.1.
        if !msg.verify_sig() {
            return Err(ForkError::InvalidSignature);
        }
        // Temuan #11: cap governance power untuk Tier C. Spec §10.1, §11.2.
        let capped_gp = if msg.node_id[0] == TIER_C_PREFIX {
            governance_power_fp.min(TIER_C_MAX_GOV_POWER)
        } else {
            governance_power_fp
        };
        self.signals.insert(
            msg.node_id,
            NodeSignal {
                signal_type: msg.signal_type,
                governance_power_fp: capped_gp,
            },
        );
        Ok(())
    }

    /// Commit fraction berdasarkan governance power. Spec §11.2, §11.4.
    pub fn commit_fraction_fp(&self) -> u64 {
        if self.total_governance_power_fp == 0 {
            return 0;
        }
        let commit_power: u64 = self
            .signals
            .values()
            .filter(|s| s.signal_type == SignalType::Commit)
            .map(|s| s.governance_power_fp)
            .fold(0u64, |acc, x| acc.saturating_add(x));
        commit_power.saturating_mul(FIXED_POINT_BASIS) / self.total_governance_power_fp
    }

    /// Abort fraction berdasarkan governance power. Spec §11.2, §11.4.
    pub fn abort_fraction_fp(&self) -> u64 {
        if self.total_governance_power_fp == 0 {
            return 0;
        }
        let abort_power: u64 = self
            .signals
            .values()
            .filter(|s| s.signal_type == SignalType::Abort)
            .map(|s| s.governance_power_fp)
            .fold(0u64, |acc, x| acc.saturating_add(x));
        abort_power.saturating_mul(FIXED_POINT_BASIS) / self.total_governance_power_fp
    }

    pub fn evaluate_transition(
        &mut self,
        current_epoch: u64,
        current_timestamp: u64,
    ) -> Result<(), ForkError> {
        if self.total_governance_power_fp == 0 {
            return Err(ForkError::ZeroTotalNodes);
        }
        match self.state {
            ForkState::Pending => {
                let threshold = match self.fork_type {
                    ForkType::Normal => FORK_COMMIT_THRESHOLD_FP,
                    ForkType::Emergency => EMERGENCY_FORK_COMMIT_THRESHOLD_FP,
                };
                if self.commit_fraction_fp() >= threshold {
                    self.state = ForkState::Committed {
                        committed_epoch: current_epoch,
                    };
                }
            }
            ForkState::Committed { committed_epoch } => {
                if self.abort_fraction_fp() >= FORK_ABORT_THRESHOLD_FP {
                    self.state = ForkState::Cancelled;
                    return Ok(());
                }
                match self.fork_type {
                    ForkType::Normal => {
                        let activation_epoch = committed_epoch + FORK_ACTIVATION_OFFSET_EPOCHS;
                        if current_epoch >= activation_epoch {
                            self.state = ForkState::Active { activation_epoch };
                        }
                    }
                    ForkType::Emergency => {
                        if current_timestamp >= self.proposed_timestamp + EMERGENCY_FORK_LOCK_SECS {
                            self.state = ForkState::Active {
                                activation_epoch: current_epoch,
                            };
                        }
                    }
                }
            }
            ForkState::Active { .. } | ForkState::Cancelled => {}
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ForkProposalStore {
    proposals: HashMap<[u8; 32], ForkProposal>,
}

impl ForkProposalStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_proposal(&mut self, proposal: ForkProposal) {
        self.proposals.insert(proposal.fork_hash, proposal);
    }

    pub fn process_signal(
        &mut self,
        msg: &ForkSignalMessage,
        governance_power_fp: u64,
        current_epoch: u64,
        current_timestamp: u64,
    ) -> Result<(), ForkError> {
        let proposal = self
            .proposals
            .get_mut(&msg.fork_hash)
            .ok_or(ForkError::ForkNotFound)?;
        proposal.add_signal(msg, governance_power_fp)?;
        proposal.evaluate_transition(current_epoch, current_timestamp)?;
        Ok(())
    }

    pub fn get(&self, fork_hash: &[u8; 32]) -> Option<&ForkProposal> {
        self.proposals.get(fork_hash)
    }

    pub fn active_count(&self) -> usize {
        self.proposals
            .values()
            .filter(|p| matches!(p.state, ForkState::Pending | ForkState::Committed { .. }))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_crypto::sphincs::{generate_keypair, sign_message, ScalarKeyPair};
    use std::sync::OnceLock;

    /// Shared keypair generated once for all fork tests.
    /// SLH-DSA keygen is ~7s — sharing avoids per-test overhead.
    static SHARED_KP: OnceLock<ScalarKeyPair> = OnceLock::new();

    fn shared_keypair() -> &'static ScalarKeyPair {
        SHARED_KP.get_or_init(|| generate_keypair().expect("keypair generation failed"))
    }

    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }
    fn fork_hash(b: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = b;
        h
    }

    /// Build a signed ForkSignalMessage reusing a shared keypair.
    /// Keypair is generated once per call — use make_signed_signals() for bulk.
    fn signed_signal(nb: u8, fb: u8, st: SignalType) -> ForkSignalMessage {
        let kp = shared_keypair();
        signed_signal_with_kp(nb, fb, st, &kp.public, &kp.secret)
    }

    /// Build a signed ForkSignalMessage with a provided keypair (avoids repeated keygen).
    fn signed_signal_with_kp(
        nb: u8,
        fb: u8,
        st: SignalType,
        public_key: &[u8],
        secret_key: &[u8],
    ) -> ForkSignalMessage {
        let mut msg = ForkSignalMessage {
            node_id: node(nb),
            epoch_id: 10,
            fork_hash: fork_hash(fb),
            signal_type: st,
            timestamp: 1_000_000,
            signature: vec![],
            public_key: public_key.to_vec(),
        };
        let vote_msg = msg.vote_message();
        msg.signature = sign_message(&vote_msg, secret_key).expect("sign failed");
        msg
    }

    /// Generate N signed signals with a pre-generated keypair (avoids extra keygen).
    fn make_signals_with_kp(
        node_range: std::ops::RangeInclusive<u8>,
        fb: u8,
        st: SignalType,
        public_key: &[u8],
        secret_key: &[u8],
    ) -> Vec<ForkSignalMessage> {
        node_range
            .map(|i| signed_signal_with_kp(i, fb, st, public_key, secret_key))
            .collect()
    }

    /// Build an unsigned ForkSignalMessage (for testing signature rejection).
    fn unsigned_signal(nb: u8, fb: u8, st: SignalType) -> ForkSignalMessage {
        ForkSignalMessage {
            node_id: node(nb),
            epoch_id: 10,
            fork_hash: fork_hash(fb),
            signal_type: st,
            timestamp: 1_000_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Total governance power for N nodes each with 1_000_000 fp.
    fn make_proposal(fb: u8, ft: ForkType, total_gp: u64) -> ForkProposal {
        ForkProposal::new(fork_hash(fb), ft, 10, 1_000_000, total_gp)
    }

    #[test]
    fn test_commit_threshold_75_percent() {
        assert_eq!(FORK_COMMIT_THRESHOLD_FP, 750_000u64);
    }
    #[test]
    fn test_abort_threshold_67_percent() {
        assert_eq!(FORK_ABORT_THRESHOLD_FP, 670_000u64);
    }
    #[test]
    fn test_emergency_commit_threshold_51_percent() {
        assert_eq!(EMERGENCY_FORK_COMMIT_THRESHOLD_FP, 510_000u64);
    }
    #[test]
    fn test_emergency_lock_48_hours() {
        assert_eq!(EMERGENCY_FORK_LOCK_SECS, 172_800u64);
    }
    #[test]
    fn test_fork_lock_days_90() {
        assert_eq!(FORK_LOCK_DAYS, 90u64);
    }
    #[test]
    fn test_fork_review_days_30() {
        assert_eq!(FORK_REVIEW_DAYS, 30u64);
    }

    // ── constant tests ────────────────────────────────────────────────────────

    #[test]
    fn test_pending_to_committed_at_75_percent() {
        // 8 nodes each with 1_000_000 gp, total = 8_000_000 → 100% commit → committed.
        // With total_gp = 8_000_000, threshold 75% = 6_000_000.
        let kp = shared_keypair();
        let mut p = make_proposal(1, ForkType::Normal, 8_000_000);
        for msg in make_signals_with_kp(1u8..=8, 1, SignalType::Commit, &kp.public, &kp.secret) {
            p.add_signal(&msg, 1_000_000).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        assert!(matches!(p.state, ForkState::Committed { .. }));
    }

    #[test]
    fn test_stays_pending_below_75_percent() {
        // 2 of 4 nodes commit = 50% < 75% → stays pending.
        let kp = shared_keypair();
        let mut p = make_proposal(1, ForkType::Normal, 4_000_000);
        for msg in make_signals_with_kp(1u8..=2, 1, SignalType::Commit, &kp.public, &kp.secret) {
            p.add_signal(&msg, 1_000_000).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        assert_eq!(p.state, ForkState::Pending);
    }

    #[test]
    fn test_committed_to_active_after_3_epochs() {
        let kp = shared_keypair();
        let mut p = make_proposal(1, ForkType::Normal, 8_000_000);
        for msg in make_signals_with_kp(1u8..=8, 1, SignalType::Commit, &kp.public, &kp.secret) {
            p.add_signal(&msg, 1_000_000).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        p.evaluate_transition(13, 1_000_000).unwrap();
        assert!(matches!(p.state, ForkState::Active { .. }));
    }

    #[test]
    fn test_committed_to_cancelled_at_67_percent_abort() {
        // 8 of 10 commit → committed, then 7 of 10 abort → cancelled.
        let kp = shared_keypair();
        let mut p = make_proposal(1, ForkType::Normal, 10_000_000);
        for msg in make_signals_with_kp(1u8..=8, 1, SignalType::Commit, &kp.public, &kp.secret) {
            p.add_signal(&msg, 1_000_000).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        for msg in make_signals_with_kp(1u8..=7, 1, SignalType::Abort, &kp.public, &kp.secret) {
            p.add_signal(&msg, 1_000_000).unwrap();
        }
        p.evaluate_transition(11, 1_000_000).unwrap();
        assert_eq!(p.state, ForkState::Cancelled);
    }

    #[test]
    fn test_emergency_fork_activates_after_48_hours() {
        // 2 of 2 commit = 100% > 51% → committed, then 48h passes → active.
        let kp = shared_keypair();
        let mut p = make_proposal(2, ForkType::Emergency, 2_000_000);
        for msg in make_signals_with_kp(1u8..=2, 2, SignalType::Commit, &kp.public, &kp.secret) {
            p.add_signal(&msg, 1_000_000).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        p.evaluate_transition(10, 1_172_801).unwrap();
        assert!(matches!(p.state, ForkState::Active { .. }));
    }

    #[test]
    fn test_store_process_signal_updates_state() {
        // 3 nodes commit out of total_gp=4_000_000 → 75% exactly → committed.
        let kp = shared_keypair();
        let mut store = ForkProposalStore::new();
        store.add_proposal(make_proposal(1, ForkType::Normal, 4_000_000));
        for msg in make_signals_with_kp(1u8..=3, 1, SignalType::Commit, &kp.public, &kp.secret) {
            store
                .process_signal(&msg, 1_000_000, 10, 1_000_000)
                .unwrap();
        }
        assert!(matches!(
            store.get(&fork_hash(1)).unwrap().state,
            ForkState::Committed { .. }
        ));
    }

    #[test]
    fn test_store_fork_not_found() {
        let mut store = ForkProposalStore::new();
        let msg = signed_signal(1, 99, SignalType::Commit);
        let err = store
            .process_signal(&msg, 1_000_000, 10, 1_000_000)
            .unwrap_err();
        assert_eq!(err, ForkError::ForkNotFound);
    }

    #[test]
    fn test_no_floating_point() {
        // 8 of 10 nodes commit: 8_000_000 / 10_000_000 = 800_000 fp.
        let kp = shared_keypair();
        let mut p = make_proposal(1, ForkType::Normal, 10_000_000);
        for msg in make_signals_with_kp(1u8..=8, 1, SignalType::Commit, &kp.public, &kp.secret) {
            p.add_signal(&msg, 1_000_000).unwrap();
        }
        assert_eq!(p.commit_fraction_fp(), 800_000);
    }

    // ── Finding #9: signature verification ───────────────────────────────────

    #[test]
    fn test_unsigned_signal_rejected() {
        // add_signal must reject votes without valid SLH-DSA signature. Spec §11.1.
        let mut p = make_proposal(1, ForkType::Normal, 1_000_000);
        let err = p
            .add_signal(&unsigned_signal(1, 1, SignalType::Commit), 1_000_000)
            .unwrap_err();
        assert_eq!(err, ForkError::InvalidSignature);
    }

    // ── Finding #11: Tier C governance power cap ──────────────────────────────

    #[test]
    fn test_tier_c_governance_power_capped() {
        // Tier C node (prefix 0xFE) governance power capped at 200_000. Spec §10.1.
        let kp = shared_keypair();
        let mut tier_c_msg = ForkSignalMessage {
            node_id: {
                let mut id = [0u8; 32];
                id[0] = TIER_C_PREFIX; // 0xFE
                id
            },
            epoch_id: 10,
            fork_hash: fork_hash(1),
            signal_type: SignalType::Commit,
            timestamp: 1_000_000,
            signature: vec![],
            public_key: kp.public.clone(),
        };
        let vote_msg = tier_c_msg.vote_message();
        tier_c_msg.signature = scalar_crypto::sphincs::sign_message(&vote_msg, &kp.secret).unwrap();

        let mut p = make_proposal(1, ForkType::Normal, 1_000_000);
        // Pass 1_000_000 gp but Tier C should be capped at 200_000
        p.add_signal(&tier_c_msg, 1_000_000).unwrap();

        let signal = p.signals.get(&tier_c_msg.node_id).unwrap();
        assert_eq!(
            signal.governance_power_fp, TIER_C_MAX_GOV_POWER,
            "Tier C governance power must be capped at {}",
            TIER_C_MAX_GOV_POWER
        );
    }
}
