// File: crates/scalar-emission/src/consensus.rs

use crate::manifest::{EpochRewardManifest, EpochStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusState {
    Open { manifest: EpochRewardManifest },
    Finalized,
}

pub struct ConsensusEngine {
    pub state: ConsensusState,
}

impl ConsensusEngine {
    pub fn new(initial_epoch: u64) -> Self {
        let initial_manifest = EpochRewardManifest::deferred(initial_epoch, 0);
        Self {
            state: ConsensusState::Open {
                manifest: initial_manifest,
            },
        }
    }

    pub fn transition_to_finalized(
        &mut self,
        final_manifest: EpochRewardManifest,
    ) -> Result<(), &'static str> {
        if final_manifest.status != EpochStatus::Finalized {
            return Err("Manifest must be finalized to transition");
        }

        if !final_manifest.verify_arithmetic_invariants() {
            return Err("Manifest invariant verification failed");
        }

        self.state = ConsensusState::Finalized;
        Ok(())
    }
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transition_to_finalized() {
        let mut engine = ConsensusEngine::new(1);
        let mut manifest = EpochRewardManifest::deferred(1, 0);
        manifest.status = EpochStatus::Finalized;

        assert!(engine.transition_to_finalized(manifest).is_ok());
        assert_eq!(engine.state, ConsensusState::Finalized);
    }
}
