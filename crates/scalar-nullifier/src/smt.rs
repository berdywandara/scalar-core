// File: crates/scalar-nullifier/src/smt.rs

pub struct ScalarSMT {
    root: [u8; 32],
}

impl ScalarSMT {
    pub fn new() -> Self {
        Self { root: [0; 32] }
    }

    pub fn contains(&self, _nullifier: &[u8; 32]) -> bool {
        // Mock checking
        false
    }

    pub fn insert(&mut self, _nullifier: &[u8; 32]) {
        // Mock root update
        self.root = [1; 32];
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn non_membership_proof(&self, _nullifier: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        (vec![], self.root)
    }
}

impl Default for ScalarSMT {
    fn default() -> Self {
        Self::new()
    }
}
