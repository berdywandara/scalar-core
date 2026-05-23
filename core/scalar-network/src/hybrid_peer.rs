//! Hybrid Peer Architecture — Research Package §3.3.3, Decision D-007
//!
//! Four-tier peer architecture with different trust levels:
//!
//! Tier 1 — Manifest: committed_manifest(k-1) node list. Maximum trust.
//!   Used for: heartbeat, consensus, state sync, Sub-Epoch consensus.
//!   Sub-Epoch consensus uses EXCLUSIVELY Manifest-tier peers.
//!
//! Tier 2 — NMT: nmt_rank selection (23+1). High trust.
//!   Used for: NMT timestamp, Sub-Epoch consensus validation.
//!
//! Tier 3 — Bootstrap: ~50 hardcoded multijurisdiction nodes. Medium trust.
//!   Used for: entry point for new nodes before manifest inclusion.
//!
//! Tier 4 — Kademlia: DHT discovery. Low trust.
//!   Used for: ONLY for new nodes before entering committed_manifest.
//!   Attack window: max 1 epoch (30 days). After that, node uses Manifest-tier.
//!
//! Critical rule: Sub-Epoch consensus uses EXCLUSIVELY Manifest-tier peers.
//! Kademlia is never used for consensus operations.
//!
//! Research Package §3.3.3: "Attack window Kademlia terbatas hanya pada
//! periode sebelum node masuk ke committed_manifest — maksimal satu epoch."

use std::collections::{HashMap, HashSet};

// ── PeerSource — 4-tier trust ─────────────────────────────────────────────────

/// Peer trust tier. Research Package §3.3.3. OSSIFIED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerTier {
    /// Tier 1: From committed_manifest(k-1). Maximum trust.
    /// Used for all consensus and Sub-Epoch operations.
    Manifest = 1,
    /// Tier 2: From NMT rank selection (23+1). High trust.
    /// Used for NMT timestamp and Sub-Epoch validation.
    NMT = 2,
    /// Tier 3: Hardcoded bootstrap nodes (~50, multijurisdiction). Medium trust.
    /// Entry point for new nodes only.
    Bootstrap = 3,
    /// Tier 4: Kademlia DHT discovery. Low trust.
    /// ONLY for new nodes before manifest inclusion. Never for consensus.
    Kademlia = 4,
}

impl PeerTier {
    /// Returns true if this tier is eligible for consensus operations.
    /// Only Manifest-tier peers may participate in Sub-Epoch consensus.
    /// Research Package §3.3.3.
    pub fn is_consensus_eligible(&self) -> bool {
        matches!(self, PeerTier::Manifest)
    }

    /// Returns true if this tier is eligible for NMT timestamp computation.
    /// Research Package §3.3.3: Manifest and NMT tiers.
    pub fn is_nmt_eligible(&self) -> bool {
        matches!(self, PeerTier::Manifest | PeerTier::NMT)
    }

    /// Returns true if this tier can be used for state sync.
    pub fn is_sync_eligible(&self) -> bool {
        matches!(
            self,
            PeerTier::Manifest | PeerTier::NMT | PeerTier::Bootstrap
        )
    }
}

// ── PeerRecord — peer with tier annotation ────────────────────────────────────

/// Peer record with trust tier. Research Package §3.3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Full 32-byte node ID. Spec §10.2.
    pub node_id: [u8; 32],
    /// Trust tier. Research Package §3.3.3.
    pub tier: PeerTier,
    /// Network address.
    pub addr: String,
    /// SLH-DSA public key for routing message verification.
    pub pubkey: Vec<u8>,
    /// Last seen timestamp (seconds).
    pub last_seen: u64,
    /// NodeScore (0-1_000_000). Spec §12.4.
    pub node_score: u64,
}

impl PeerRecord {
    pub fn new(node_id: [u8; 32], tier: PeerTier, addr: String) -> Self {
        Self {
            node_id,
            tier,
            addr,
            pubkey: Vec::new(),
            last_seen: 0,
            node_score: 0,
        }
    }
}

// ── HybridPeerStore — 4-tier peer management ─────────────────────────────────

/// Hybrid peer store with 4-tier trust management. Research Package §3.3.3.
///
/// Maintains separate sets for each tier.
/// Consensus operations only access Manifest-tier peers.
#[derive(Default)]
pub struct HybridPeerStore {
    peers: HashMap<[u8; 32], PeerRecord>,
}

impl HybridPeerStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a peer record.
    pub fn upsert(&mut self, record: PeerRecord) {
        self.peers.insert(record.node_id, record);
    }

    /// Remove a peer.
    pub fn remove(&mut self, node_id: &[u8; 32]) {
        self.peers.remove(node_id);
    }

    /// Get peers by tier.
    pub fn peers_by_tier(&self, tier: PeerTier) -> Vec<&PeerRecord> {
        self.peers.values().filter(|p| p.tier == tier).collect()
    }

    /// Get all consensus-eligible peers (Manifest-tier only).
    /// Research Package §3.3.3: Sub-Epoch consensus exclusively Manifest-tier.
    pub fn consensus_peers(&self) -> Vec<&PeerRecord> {
        self.peers_by_tier(PeerTier::Manifest)
    }

    /// Get all NMT-eligible peers (Manifest + NMT tiers).
    pub fn nmt_peers(&self) -> Vec<&PeerRecord> {
        self.peers
            .values()
            .filter(|p| p.tier.is_nmt_eligible())
            .collect()
    }

    /// Get all sync-eligible peers.
    pub fn sync_peers(&self) -> Vec<&PeerRecord> {
        self.peers
            .values()
            .filter(|p| p.tier.is_sync_eligible())
            .collect()
    }

    /// Promote a peer from Kademlia/Bootstrap to Manifest tier.
    ///
    /// Called when a node's node_id_full appears in committed_manifest(k).
    /// Research Package §3.3.3: "mekanisme promosi node baru dari
    /// Kademlia-tier ke Manifest-tier".
    pub fn promote_to_manifest(&mut self, node_id: &[u8; 32]) -> bool {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.tier = PeerTier::Manifest;
            return true;
        }
        false
    }

    /// Demote all Manifest peers not in the new manifest to Bootstrap/Kademlia.
    ///
    /// Called when a new committed_manifest is received.
    /// Peers not in the new manifest are demoted to Bootstrap tier.
    pub fn sync_with_manifest(&mut self, manifest_node_ids: &HashSet<[u8; 32]>) {
        for peer in self.peers.values_mut() {
            if peer.tier == PeerTier::Manifest && !manifest_node_ids.contains(&peer.node_id) {
                peer.tier = PeerTier::Bootstrap;
            }
        }
        // Promote peers that are in the manifest
        for node_id in manifest_node_ids {
            if let Some(peer) = self.peers.get_mut(node_id) {
                peer.tier = PeerTier::Manifest;
            }
        }
    }

    /// Total peer count.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Get a peer by node_id.
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&PeerRecord> {
        self.peers.get(node_id)
    }

    /// Count peers per tier.
    pub fn tier_counts(&self) -> HashMap<PeerTier, usize> {
        let mut counts = HashMap::new();
        for peer in self.peers.values() {
            *counts.entry(peer.tier).or_insert(0) += 1;
        }
        counts
    }
}

// ── Bootstrap peer list — Research Package §3.3.3 ────────────────────────────

/// Hardcoded bootstrap peers (~50, multijurisdiction). Research Package §3.3.3.
///
/// Tier 3 — medium trust. Entry point for new nodes only.
/// In production these would be real onion addresses with verified pubkeys.
pub fn default_bootstrap_peers() -> Vec<PeerRecord> {
    let _jurisdictions = ["US", "EU", "SG", "JP", "CH", "IS", "BR", "ZA", "AE", "AU"];
    (0..50u8)
        .map(|i| {
            let mut node_id = [0u8; 32];
            node_id[0] = i;
            node_id[1] = 0xB0; // Bootstrap prefix marker
            PeerRecord {
                node_id,
                tier: PeerTier::Bootstrap,
                addr: format!("scalar-bootstrap-{}.onion:4001", i),
                pubkey: vec![i; 32],
                last_seen: 0,
                node_score: 0,
            }
        })
        .collect()
}

// ── PeerFilter — filter helpers for consensus ─────────────────────────────────

/// Filter a peer list to consensus-eligible peers only.
/// Research Package §3.3.3: Sub-Epoch uses EXCLUSIVELY Manifest-tier.
pub fn filter_consensus_peers(peers: &[PeerRecord]) -> Vec<&PeerRecord> {
    peers
        .iter()
        .filter(|p| p.tier.is_consensus_eligible())
        .collect()
}

/// Filter a peer list to NMT-eligible peers only.
pub fn filter_nmt_peers(peers: &[PeerRecord]) -> Vec<&PeerRecord> {
    peers.iter().filter(|p| p.tier.is_nmt_eligible()).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(id_byte: u8, tier: PeerTier) -> PeerRecord {
        let mut node_id = [0u8; 32];
        node_id[0] = id_byte;
        PeerRecord::new(node_id, tier, format!("node-{}.onion", id_byte))
    }

    fn node_id(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    // ── PeerTier — trust levels ───────────────────────────────────────────────

    #[test]
    fn test_manifest_tier_is_consensus_eligible() {
        // Research Package §3.3.3: Sub-Epoch exclusively Manifest-tier.
        assert!(PeerTier::Manifest.is_consensus_eligible());
        assert!(!PeerTier::NMT.is_consensus_eligible());
        assert!(!PeerTier::Bootstrap.is_consensus_eligible());
        assert!(!PeerTier::Kademlia.is_consensus_eligible());
    }

    #[test]
    fn test_nmt_eligible_tiers() {
        // Research Package §3.3.3: NMT uses Manifest + NMT tiers.
        assert!(PeerTier::Manifest.is_nmt_eligible());
        assert!(PeerTier::NMT.is_nmt_eligible());
        assert!(!PeerTier::Bootstrap.is_nmt_eligible());
        assert!(!PeerTier::Kademlia.is_nmt_eligible());
    }

    #[test]
    fn test_sync_eligible_tiers() {
        assert!(PeerTier::Manifest.is_sync_eligible());
        assert!(PeerTier::NMT.is_sync_eligible());
        assert!(PeerTier::Bootstrap.is_sync_eligible());
        assert!(!PeerTier::Kademlia.is_sync_eligible());
    }

    #[test]
    fn test_tier_ordering() {
        // Manifest has highest trust (lowest ordinal value).
        assert!(PeerTier::Manifest < PeerTier::NMT);
        assert!(PeerTier::NMT < PeerTier::Bootstrap);
        assert!(PeerTier::Bootstrap < PeerTier::Kademlia);
    }

    // ── HybridPeerStore ───────────────────────────────────────────────────────

    #[test]
    fn test_store_upsert_and_get() {
        let mut store = HybridPeerStore::new();
        store.upsert(make_peer(0x01, PeerTier::Manifest));
        assert!(store.get(&node_id(0x01)).is_some());
    }

    #[test]
    fn test_store_remove() {
        let mut store = HybridPeerStore::new();
        store.upsert(make_peer(0x01, PeerTier::Manifest));
        store.remove(&node_id(0x01));
        assert!(store.get(&node_id(0x01)).is_none());
    }

    #[test]
    fn test_consensus_peers_only_manifest() {
        // Research Package §3.3.3: consensus exclusively Manifest-tier.
        let mut store = HybridPeerStore::new();
        store.upsert(make_peer(0x01, PeerTier::Manifest));
        store.upsert(make_peer(0x02, PeerTier::NMT));
        store.upsert(make_peer(0x03, PeerTier::Bootstrap));
        store.upsert(make_peer(0x04, PeerTier::Kademlia));

        let consensus = store.consensus_peers();
        assert_eq!(consensus.len(), 1);
        assert_eq!(consensus[0].node_id[0], 0x01);
    }

    #[test]
    fn test_nmt_peers_manifest_and_nmt() {
        let mut store = HybridPeerStore::new();
        store.upsert(make_peer(0x01, PeerTier::Manifest));
        store.upsert(make_peer(0x02, PeerTier::NMT));
        store.upsert(make_peer(0x03, PeerTier::Bootstrap));
        store.upsert(make_peer(0x04, PeerTier::Kademlia));

        let nmt = store.nmt_peers();
        assert_eq!(nmt.len(), 2);
    }

    #[test]
    fn test_kademlia_not_in_consensus() {
        // Research Package §3.3.3: Kademlia never used for consensus.
        let mut store = HybridPeerStore::new();
        for i in 0..10u8 {
            store.upsert(make_peer(i, PeerTier::Kademlia));
        }
        assert_eq!(store.consensus_peers().len(), 0);
    }

    #[test]
    fn test_promote_to_manifest() {
        // Research Package §3.3.3: node promotion from Kademlia to Manifest.
        let mut store = HybridPeerStore::new();
        store.upsert(make_peer(0x01, PeerTier::Kademlia));
        assert!(!store
            .get(&node_id(0x01))
            .unwrap()
            .tier
            .is_consensus_eligible());

        let promoted = store.promote_to_manifest(&node_id(0x01));
        assert!(promoted);
        assert!(store
            .get(&node_id(0x01))
            .unwrap()
            .tier
            .is_consensus_eligible());
    }

    #[test]
    fn test_promote_nonexistent_returns_false() {
        let mut store = HybridPeerStore::new();
        assert!(!store.promote_to_manifest(&node_id(0xFF)));
    }

    #[test]
    fn test_sync_with_manifest_promotes_and_demotes() {
        // Sync with new manifest: promote included, demote excluded.
        let mut store = HybridPeerStore::new();
        store.upsert(make_peer(0x01, PeerTier::Manifest)); // stays Manifest
        store.upsert(make_peer(0x02, PeerTier::Manifest)); // demoted — not in new manifest
        store.upsert(make_peer(0x03, PeerTier::Kademlia)); // promoted — in new manifest

        let mut new_manifest = HashSet::new();
        new_manifest.insert(node_id(0x01));
        new_manifest.insert(node_id(0x03));

        store.sync_with_manifest(&new_manifest);

        assert_eq!(store.get(&node_id(0x01)).unwrap().tier, PeerTier::Manifest);
        assert_eq!(store.get(&node_id(0x02)).unwrap().tier, PeerTier::Bootstrap);
        assert_eq!(store.get(&node_id(0x03)).unwrap().tier, PeerTier::Manifest);
    }

    #[test]
    fn test_tier_counts() {
        let mut store = HybridPeerStore::new();
        store.upsert(make_peer(0x01, PeerTier::Manifest));
        store.upsert(make_peer(0x02, PeerTier::Manifest));
        store.upsert(make_peer(0x03, PeerTier::NMT));
        store.upsert(make_peer(0x04, PeerTier::Kademlia));

        let counts = store.tier_counts();
        assert_eq!(counts.get(&PeerTier::Manifest).copied().unwrap_or(0), 2);
        assert_eq!(counts.get(&PeerTier::NMT).copied().unwrap_or(0), 1);
        assert_eq!(counts.get(&PeerTier::Kademlia).copied().unwrap_or(0), 1);
    }

    // ── Bootstrap peers ───────────────────────────────────────────────────────

    #[test]
    fn test_default_bootstrap_peers_count() {
        // Research Package §3.3.3: ~50 bootstrap nodes.
        let peers = default_bootstrap_peers();
        assert_eq!(peers.len(), 50);
    }

    #[test]
    fn test_default_bootstrap_peers_tier() {
        let peers = default_bootstrap_peers();
        assert!(peers.iter().all(|p| p.tier == PeerTier::Bootstrap));
    }

    #[test]
    fn test_default_bootstrap_peers_unique_ids() {
        let peers = default_bootstrap_peers();
        let ids: HashSet<[u8; 32]> = peers.iter().map(|p| p.node_id).collect();
        assert_eq!(ids.len(), 50);
    }

    // ── filter helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_filter_consensus_peers() {
        let peers = vec![
            make_peer(0x01, PeerTier::Manifest),
            make_peer(0x02, PeerTier::NMT),
            make_peer(0x03, PeerTier::Kademlia),
        ];
        let filtered = filter_consensus_peers(&peers);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].node_id[0], 0x01);
    }

    #[test]
    fn test_filter_nmt_peers() {
        let peers = vec![
            make_peer(0x01, PeerTier::Manifest),
            make_peer(0x02, PeerTier::NMT),
            make_peer(0x03, PeerTier::Bootstrap),
        ];
        let filtered = filter_nmt_peers(&peers);
        assert_eq!(filtered.len(), 2);
    }

    // ── Critical invariant: Kademlia never in consensus ───────────────────────

    #[test]
    fn test_kademlia_attack_window_bounded() {
        // Research Package §3.3.3: Kademlia attack window max 1 epoch.
        // After sync_with_manifest, Kademlia peers that entered manifest
        // are promoted and no longer depend on Kademlia.
        let mut store = HybridPeerStore::new();

        // New node discovers peers via Kademlia
        for i in 0..5u8 {
            store.upsert(make_peer(i, PeerTier::Kademlia));
        }

        // None are consensus-eligible
        assert_eq!(store.consensus_peers().len(), 0);

        // After epoch, node enters manifest — promoted
        let mut manifest = HashSet::new();
        manifest.insert(node_id(0x00));
        manifest.insert(node_id(0x01));
        store.sync_with_manifest(&manifest);

        // Now manifest peers are consensus-eligible
        assert_eq!(store.consensus_peers().len(), 2);
        // Remaining Kademlia peers still not eligible
        assert_eq!(
            store.peers_by_tier(PeerTier::Bootstrap).len()
                + store.peers_by_tier(PeerTier::Kademlia).len(),
            3
        );
    }
}
