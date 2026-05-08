//! Fork Protocol — Spec §11.7
//!
//! STATE MACHINE:
//!   PENDING    → COMMITTED : signal_fraction ≥ 75%
//!   COMMITTED  → CANCELLED : abort_fraction ≥ 67%
//!   COMMITTED  → ACTIVE    : setelah activation_epoch tercapai
//!
//! NORMAL FORK: Lock 90d + Review 30d + Activation epoch+3
//! EMERGENCY FORK: Lock 48 jam, scope crypto primitives only, 51% threshold

use std::collections::HashMap;

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

#[derive(Debug, Clone)]
pub struct ForkProposal {
    pub fork_hash: [u8; 32],
    pub fork_type: ForkType,
    pub proposed_epoch: u64,
    pub proposed_timestamp: u64,
    pub state: ForkState,
    pub signals: HashMap<[u8; 32], SignalType>,
    pub total_nodes: u64,
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
        }
    }
}

impl ForkProposal {
    pub fn new(
        fork_hash: [u8; 32],
        fork_type: ForkType,
        proposed_epoch: u64,
        proposed_timestamp: u64,
        total_nodes: u64,
    ) -> Self {
        Self {
            fork_hash,
            fork_type,
            proposed_epoch,
            proposed_timestamp,
            state: ForkState::Pending,
            signals: HashMap::new(),
            total_nodes,
        }
    }

    pub fn add_signal(&mut self, msg: &ForkSignalMessage) -> Result<(), ForkError> {
        match self.state {
            ForkState::Cancelled => return Err(ForkError::ForkCancelled),
            ForkState::Active { .. } => return Err(ForkError::ForkActive),
            _ => {}
        }
        self.signals.insert(msg.node_id, msg.signal_type);
        Ok(())
    }

    pub fn commit_fraction_fp(&self) -> u64 {
        if self.total_nodes == 0 {
            return 0;
        }
        let commits = self
            .signals
            .values()
            .filter(|&&s| s == SignalType::Commit)
            .count() as u64;
        commits.saturating_mul(FIXED_POINT_BASIS) / self.total_nodes
    }

    pub fn abort_fraction_fp(&self) -> u64 {
        if self.total_nodes == 0 {
            return 0;
        }
        let aborts = self
            .signals
            .values()
            .filter(|&&s| s == SignalType::Abort)
            .count() as u64;
        aborts.saturating_mul(FIXED_POINT_BASIS) / self.total_nodes
    }

    pub fn evaluate_transition(
        &mut self,
        current_epoch: u64,
        current_timestamp: u64,
    ) -> Result<(), ForkError> {
        if self.total_nodes == 0 {
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
        current_epoch: u64,
        current_timestamp: u64,
    ) -> Result<(), ForkError> {
        let proposal = self
            .proposals
            .get_mut(&msg.fork_hash)
            .ok_or(ForkError::ForkNotFound)?;
        proposal.add_signal(msg)?;
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
    fn signal(nb: u8, fb: u8, st: SignalType) -> ForkSignalMessage {
        ForkSignalMessage {
            node_id: node(nb),
            epoch_id: 10,
            fork_hash: fork_hash(fb),
            signal_type: st,
            timestamp: 1_000_000,
            signature: vec![],
        }
    }
    fn make_proposal(fb: u8, ft: ForkType, total: u64) -> ForkProposal {
        ForkProposal::new(fork_hash(fb), ft, 10, 1_000_000, total)
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

    #[test]
    fn test_pending_to_committed_at_75_percent() {
        let mut p = make_proposal(1, ForkType::Normal, 4);
        for i in 1u8..=8 {
            p.add_signal(&signal(i, 1, SignalType::Commit)).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        assert!(matches!(p.state, ForkState::Committed { .. }));
    }

    #[test]
    fn test_stays_pending_below_75_percent() {
        let mut p = make_proposal(1, ForkType::Normal, 4);
        for i in 1u8..=2 {
            p.add_signal(&signal(i, 1, SignalType::Commit)).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        assert_eq!(p.state, ForkState::Pending);
    }

    #[test]
    fn test_committed_to_active_after_3_epochs() {
        let mut p = make_proposal(1, ForkType::Normal, 4);
        for i in 1u8..=8 {
            p.add_signal(&signal(i, 1, SignalType::Commit)).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        p.evaluate_transition(13, 1_000_000).unwrap();
        assert!(matches!(p.state, ForkState::Active { .. }));
    }

    #[test]
    fn test_committed_to_cancelled_at_67_percent_abort() {
        let mut p = make_proposal(1, ForkType::Normal, 10);
        for i in 1u8..=8 {
            p.add_signal(&signal(i, 1, SignalType::Commit)).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        for i in 1u8..=7 {
            p.add_signal(&signal(i, 1, SignalType::Abort)).unwrap();
        }
        p.evaluate_transition(11, 1_000_000).unwrap();
        assert_eq!(p.state, ForkState::Cancelled);
    }

    #[test]
    fn test_emergency_fork_activates_after_48_hours() {
        let mut p = make_proposal(2, ForkType::Emergency, 2);
        for i in 1u8..=2 {
            p.add_signal(&signal(i, 2, SignalType::Commit)).unwrap();
        }
        p.evaluate_transition(10, 1_000_000).unwrap();
        p.evaluate_transition(10, 1_172_801).unwrap();
        assert!(matches!(p.state, ForkState::Active { .. }));
    }

    #[test]
    fn test_store_process_signal_updates_state() {
        let mut store = ForkProposalStore::new();
        store.add_proposal(make_proposal(1, ForkType::Normal, 4));
        for i in 1u8..=3 {
            store
                .process_signal(&signal(i, 1, SignalType::Commit), 10, 1_000_000)
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
        let err = store
            .process_signal(&signal(1, 99, SignalType::Commit), 10, 1_000_000)
            .unwrap_err();
        assert_eq!(err, ForkError::ForkNotFound);
    }

    #[test]
    fn test_no_floating_point() {
        let mut p = make_proposal(1, ForkType::Normal, 10);
        for i in 1u8..=8 {
            p.add_signal(&signal(i, 1, SignalType::Commit)).unwrap();
        }
        assert_eq!(p.commit_fraction_fp(), 800_000);
    }
}
