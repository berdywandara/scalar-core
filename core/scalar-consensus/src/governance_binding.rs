//! GovernanceBinding — C1-BIND state object (passive).
//!
//! Maps node_id_full -> GovernanceID_pub (SLH-DSA-SHAKE-128s public key, 32 bytes).
//! Stored in committed_manifest as a separate Merkle sub-tree, sorted
//! lexicographically by node_id_full for O(log N) lookup.
//!
//! This is a PASSIVE state object. Governance logic lives in scalar-governance.
//! [SCALAR-TECHNICAL §10.2, SCALAR-PROTOCOL §9.1 C1-BIND, OSSIFIED]

use std::collections::BTreeMap;

/// GovernanceBinding — OSSIFIED struct. Changes require hard fork.
/// [SCALAR-TECHNICAL §10.2, SCALAR-PROTOCOL §9.1 C1-BIND]
///
/// Maps node_id_full (32 bytes) -> GovernanceID_pub (SLH-DSA-SHAKE-128s, 32 bytes).
/// Sub-tree is sorted lexicographically by node_id_full (BTreeMap guarantees this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceBinding {
    /// SLH-DSA-SHAKE-128s public key (32 bytes). Bound permanently to node_id_full.
    /// [SCALAR-SECURITY §1.2: SPHINCS+-SHAKE-128s pubkey = 32 bytes, FIPS 205]
    pub governance_id_pub: [u8; 32],
}

/// GovernanceBindingStore — committed_manifest sub-tree for C1-BIND.
///
/// Sorted lexicographically by node_id_full (BTreeMap). O(log N) lookup.
/// Passive state object — no governance logic here.
/// [SCALAR-TECHNICAL §10.2]
#[derive(Debug, Clone, Default)]
pub struct GovernanceBindingStore {
    /// Inner map: node_id_full -> GovernanceBinding.
    /// BTreeMap ensures lexicographic ordering by node_id_full.
    bindings: BTreeMap<[u8; 32], GovernanceBinding>,
}

impl GovernanceBindingStore {
    /// Create an empty store (genesis state).
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    /// Register a (node_id_full, governance_id_pub) binding.
    ///
    /// Returns Err if node_id_full already has a binding (C1-BIND: permanent).
    /// Re-binding requires a valid rebind_payload signed by the old GovernanceID_priv.
    /// That logic is enforced in scalar-governance, not here.
    /// [SCALAR-PROTOCOL §9.1 C1-BIND]
    pub fn register(
        &mut self,
        node_id_full: [u8; 32],
        governance_id_pub: [u8; 32],
    ) -> Result<(), GovernanceBindingError> {
        if self.bindings.contains_key(&node_id_full) {
            return Err(GovernanceBindingError::AlreadyBound);
        }
        self.bindings
            .insert(node_id_full, GovernanceBinding { governance_id_pub });
        Ok(())
    }

    /// Update an existing binding (rebind). Caller (scalar-governance) is
    /// responsible for verifying the rebind_payload SLH-DSA signature before
    /// calling this. This store only enforces structural invariants.
    /// [SCALAR-PROTOCOL §9.1 C1-BIND rebind]
    pub fn rebind(
        &mut self,
        node_id_full: [u8; 32],
        governance_id_pub_new: [u8; 32],
    ) -> Result<(), GovernanceBindingError> {
        let entry = self
            .bindings
            .get_mut(&node_id_full)
            .ok_or(GovernanceBindingError::NotFound)?;
        entry.governance_id_pub = governance_id_pub_new;
        Ok(())
    }

    /// Look up GovernanceID_pub for a given node_id_full. O(log N).
    pub fn get(&self, node_id_full: &[u8; 32]) -> Option<&GovernanceBinding> {
        self.bindings.get(node_id_full)
    }

    /// Returns true if node_id_full has a registered binding.
    pub fn is_bound(&self, node_id_full: &[u8; 32]) -> bool {
        self.bindings.contains_key(node_id_full)
    }

    /// Number of registered bindings.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Returns true if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Iterate bindings in lexicographic order by node_id_full.
    /// Used for Merkle sub-tree root computation.
    pub fn iter_sorted(&self) -> impl Iterator<Item = (&[u8; 32], &GovernanceBinding)> {
        self.bindings.iter()
    }

    /// Compute Merkle sub-tree root over all bindings, sorted by node_id_full.
    ///
    /// Leaf = BLAKE3(DOMAIN_GOV_BINDING || node_id_full || governance_id_pub).
    /// Root = BLAKE3(DOMAIN_GOV_BINDING || leaf_0 || leaf_1 || ... || leaf_n).
    /// Empty store: root = [0u8; 32].
    /// [SCALAR-TECHNICAL §10.2]
    pub fn merkle_root(&self) -> [u8; 32] {
        use scalar_crypto::blake3::hash as blake3_hash;

        const DOMAIN_GOV_BINDING: &[u8] = b"scalar_gov_binding";

        if self.bindings.is_empty() {
            return [0u8; 32];
        }

        // Compute leaf hashes in sorted order
        let leaves: Vec<[u8; 32]> = self
            .bindings
            .iter()
            .map(|(node_id, binding)| {
                let mut preimage = Vec::with_capacity(DOMAIN_GOV_BINDING.len() + 32 + 32);
                preimage.extend_from_slice(DOMAIN_GOV_BINDING);
                preimage.extend_from_slice(node_id);
                preimage.extend_from_slice(&binding.governance_id_pub);
                blake3_hash(&preimage)
            })
            .collect();

        // Combine all leaves into root
        let mut root_preimage = Vec::with_capacity(DOMAIN_GOV_BINDING.len() + leaves.len() * 32);
        root_preimage.extend_from_slice(DOMAIN_GOV_BINDING);
        for leaf in &leaves {
            root_preimage.extend_from_slice(leaf);
        }
        blake3_hash(&root_preimage)
    }
}

/// Errors from GovernanceBindingStore operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceBindingError {
    #[error("node_id_full already has a binding (C1-BIND: permanent)")]
    AlreadyBound,
    #[error("node_id_full not found in binding store")]
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn gov_pub(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn test_register_and_lookup() {
        let mut store = GovernanceBindingStore::new();
        let nid = node_id(0x01);
        let gpub = gov_pub(0xAA);

        store.register(nid, gpub).unwrap();
        let binding = store.get(&nid).unwrap();
        assert_eq!(binding.governance_id_pub, gpub);
    }

    #[test]
    fn test_double_register_rejected() {
        let mut store = GovernanceBindingStore::new();
        let nid = node_id(0x02);
        store.register(nid, gov_pub(0xBB)).unwrap();
        let err = store.register(nid, gov_pub(0xCC)).unwrap_err();
        assert_eq!(err, GovernanceBindingError::AlreadyBound);
    }

    #[test]
    fn test_rebind_updates_pub() {
        let mut store = GovernanceBindingStore::new();
        let nid = node_id(0x03);
        store.register(nid, gov_pub(0x11)).unwrap();
        store.rebind(nid, gov_pub(0x22)).unwrap();
        assert_eq!(store.get(&nid).unwrap().governance_id_pub, gov_pub(0x22));
    }

    #[test]
    fn test_rebind_unknown_node_rejected() {
        let mut store = GovernanceBindingStore::new();
        let err = store.rebind(node_id(0xFF), gov_pub(0x33)).unwrap_err();
        assert_eq!(err, GovernanceBindingError::NotFound);
    }

    #[test]
    fn test_iter_sorted_lexicographic() {
        let mut store = GovernanceBindingStore::new();
        // Insert in reverse order
        store.register(node_id(0x03), gov_pub(0x03)).unwrap();
        store.register(node_id(0x01), gov_pub(0x01)).unwrap();
        store.register(node_id(0x02), gov_pub(0x02)).unwrap();

        let keys: Vec<_> = store.iter_sorted().map(|(k, _)| k[0]).collect();
        assert_eq!(
            keys,
            vec![0x01, 0x02, 0x03],
            "Must be sorted lexicographically"
        );
    }

    #[test]
    fn test_merkle_root_empty() {
        let store = GovernanceBindingStore::new();
        assert_eq!(store.merkle_root(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let mut store1 = GovernanceBindingStore::new();
        let mut store2 = GovernanceBindingStore::new();

        store1.register(node_id(0x01), gov_pub(0xAA)).unwrap();
        store1.register(node_id(0x02), gov_pub(0xBB)).unwrap();

        // Insert in different order
        store2.register(node_id(0x02), gov_pub(0xBB)).unwrap();
        store2.register(node_id(0x01), gov_pub(0xAA)).unwrap();

        assert_eq!(
            store1.merkle_root(),
            store2.merkle_root(),
            "Merkle root must be deterministic regardless of insertion order"
        );
    }

    #[test]
    fn test_merkle_root_changes_on_rebind() {
        let mut store = GovernanceBindingStore::new();
        store.register(node_id(0x01), gov_pub(0xAA)).unwrap();
        let root_before = store.merkle_root();
        store.rebind(node_id(0x01), gov_pub(0xBB)).unwrap();
        let root_after = store.merkle_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_c1_bind_struct_sizes() {
        // OSSIFIED: both node_id_full and governance_id_pub are [u8;32].
        // node_id_full: BLAKE3 output (32 bytes).
        // governance_id_pub: SLH-DSA-SHAKE-128s pubkey (32 bytes). [SCALAR-SECURITY §1.2]
        assert_eq!(std::mem::size_of::<[u8; 32]>(), 32);
        let binding = GovernanceBinding {
            governance_id_pub: [0u8; 32],
        };
        assert_eq!(binding.governance_id_pub.len(), 32);
    }
}
