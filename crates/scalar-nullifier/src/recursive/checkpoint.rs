// File: crates/scalar-nullifier/src/recursive/checkpoint.rs

/// NS_ARCH: STARK Checkpoint layer (Mock/Stub untuk integrasi Hierarchical)
pub struct ArchCheckpoint;

impl ArchCheckpoint {
    pub fn new() -> Self {
        Self
    }
    pub fn contains(&self, _nullifier: &[u8; 32]) -> bool {
        false
    }
}

impl Default for ArchCheckpoint {
    fn default() -> Self {
        Self::new()
    }
}
