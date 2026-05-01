// File: crates/scalar-emission/src/consensus.rs

use crate::manifest::EpochRewardManifest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusState {
    Open { manifest: EpochRewardManifest },
    Finalized,
}

#[derive(Default)]
pub struct ConsensusEngine;

impl ConsensusEngine {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {}
