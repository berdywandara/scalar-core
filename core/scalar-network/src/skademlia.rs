//! S/Kademlia — Secure Kademlia DHT — Research Package §3.3, Decision D-007
//!
//! Three improvements over standard Kademlia (Research Package §3.3.2):
//!   1. Node IDs from crypto puzzle (Argon2id) — ALREADY EXISTS via node_id.rs
//!   2. Routing messages signed with SLH-DSA — AVAILABLE via scalar-crypto
//!   3. Disjoint path lookup d=3 — NEW IMPLEMENTATION HERE
//!
//! Parameters (OSSIFIED — Decision D-007):
//!   d = 3  (disjoint lookup paths)
//!   k = 20 (k-bucket size)
//!
//! Eclipse resistance for d=3, k=20 (Research Package §3.3.4):
//!   P(eclipse) ≈ (B/N)^(k×d) — for realistic Sybil budgets: < 2^-30
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.

use blake3::Hasher;
use std::collections::HashSet;
use scalar_crypto::domain::DOMAIN_NODEID;

// ── Constants — OSSIFIED (Decision D-007) ────────────────────────────────────

/// Disjoint lookup paths. OSSIFIED — Research Package §3.3, D-007.
pub const SKADEMLIA_D: usize = 3;

/// K-bucket size. OSSIFIED — Research Package §3.3, D-007.
pub const SKADEMLIA_K: usize = 20;

/// Key space bits (256-bit node IDs).
pub const KEY_BITS: usize = 256;

/// Alpha — parallel lookup factor (standard Kademlia).
pub const ALPHA: usize = 3;

// ── NodeId — 256-bit key ──────────────────────────────────────────────────────

/// 256-bit node identifier. Derived from Argon2id (anti-Sybil). Spec §10.2.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// XOR distance between two node IDs. Kademlia metric.
    pub fn distance(&self, other: &NodeId) -> NodeId {
        let mut d = [0u8; 32];
        for (i, (a, b)) in self.0.iter().zip(other.0.iter()).enumerate() {
            d[i] = a ^ b;
        }
        NodeId(d)
    }

    /// Leading zeros in XOR distance — determines bucket index.
    pub fn leading_zeros(&self) -> usize {
        for (i, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                return i * 8 + byte.leading_zeros() as usize;
            }
        }
        KEY_BITS
    }

    /// Bucket index for routing table (0 = closest, KEY_BITS-1 = farthest).
    pub fn bucket_index(&self, other: &NodeId) -> usize {
        let dist = self.distance(other);
        let lz = dist.leading_zeros();
        if lz >= KEY_BITS {
            0
        } else {
            KEY_BITS - 1 - lz
        }
    }

    /// Generate a random node ID for a given bucket (for bucket refresh).
    pub fn random_for_bucket(local: &NodeId, bucket: usize, seed: &[u8; 32]) -> NodeId {
        let mut h = Hasher::new();
        h.update(DOMAIN_NODEID);
        h.update(&local.0);
        h.update(&(bucket as u64).to_le_bytes());
        h.update(seed);
        NodeId(*h.finalize().as_bytes())
    }
}

// ── NodeInfo — peer record ────────────────────────────────────────────────────

/// Peer record in the routing table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: NodeId,
    /// SLH-DSA public key for routing message verification. Research Package §3.3.2.
    pub pubkey: Vec<u8>,
    /// Network address (multiaddr string).
    pub addr: String,
    /// Last seen timestamp (seconds).
    pub last_seen: u64,
}

// ── KBucket — fixed-size peer bucket ─────────────────────────────────────────

/// K-bucket holding up to SKADEMLIA_K peers. Kademlia §2.4.
#[derive(Debug, Default)]
pub struct KBucket {
    /// Peers sorted by last_seen (most recently seen first).
    peers: Vec<NodeInfo>,
}

impl KBucket {
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }

    /// Insert or update a peer. Returns true if inserted/updated.
    /// If full, the oldest peer is evicted (simplified — production would ping first).
    pub fn insert(&mut self, node: NodeInfo) -> bool {
        // If already present, update last_seen and move to front
        if let Some(pos) = self.peers.iter().position(|p| p.id == node.id) {
            self.peers[pos] = node;
            return true;
        }
        if self.peers.len() >= SKADEMLIA_K {
            // Evict oldest (last element)
            self.peers.pop();
        }
        self.peers.insert(0, node);
        true
    }

    /// Remove a peer by ID.
    pub fn remove(&mut self, id: &NodeId) {
        self.peers.retain(|p| &p.id != id);
    }

    /// Get all peers in this bucket.
    pub fn peers(&self) -> &[NodeInfo] {
        &self.peers
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

// ── RoutingTable — 256-bucket Kademlia table ──────────────────────────────────

/// Kademlia routing table with KEY_BITS buckets.
pub struct RoutingTable {
    pub local_id: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        let buckets = (0..KEY_BITS).map(|_| KBucket::new()).collect();
        Self { local_id, buckets }
    }

    /// Insert a peer into the appropriate bucket.
    pub fn insert(&mut self, node: NodeInfo) -> bool {
        if node.id == self.local_id {
            return false; // Don't add self
        }
        let bucket_idx = self.local_id.bucket_index(&node.id);
        self.buckets[bucket_idx].insert(node)
    }

    /// Remove a peer.
    pub fn remove(&mut self, id: &NodeId) {
        if let Some(bucket_idx) = self.bucket_index_for(id) {
            self.buckets[bucket_idx].remove(id);
        }
    }

    /// Find the k closest peers to a target ID.
    pub fn closest_peers(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        let mut all_peers: Vec<(NodeId, NodeInfo)> = self
            .buckets
            .iter()
            .flat_map(|b| b.peers().iter().cloned())
            .map(|p| (p.id.distance(target), p))
            .collect();

        all_peers.sort_by_key(|(dist, _)| *dist);
        all_peers.into_iter().take(count).map(|(_, p)| p).collect()
    }

    /// Total number of peers in routing table.
    pub fn peer_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    fn bucket_index_for(&self, id: &NodeId) -> Option<usize> {
        if *id == self.local_id {
            return None;
        }
        Some(self.local_id.bucket_index(id))
    }

    /// All peers in routing table.
    pub fn all_peers(&self) -> Vec<NodeInfo> {
        self.buckets
            .iter()
            .flat_map(|b| b.peers().iter().cloned())
            .collect()
    }
}

// ── DisjointLookup — S/Kademlia d=3 ─────────────────────────────────────────

/// State for one disjoint lookup path. Research Package §3.3.2.
#[derive(Debug)]
pub struct LookupPath {
    pub path_id: usize,
    /// Peers queried on this path.
    pub queried: HashSet<NodeId>,
    /// Best peers found so far (closest to target).
    pub candidates: Vec<NodeInfo>,
}

impl LookupPath {
    pub fn new(path_id: usize, seeds: Vec<NodeInfo>) -> Self {
        Self {
            path_id,
            queried: HashSet::new(),
            candidates: seeds,
        }
    }

    /// Select next peers to query (not yet queried, closest first).
    pub fn next_to_query(&self, _target: &NodeId, alpha: usize) -> Vec<NodeInfo> {
        self.candidates
            .iter()
            .filter(|p| !self.queried.contains(&p.id))
            .take(alpha)
            .cloned()
            .collect()
    }

    /// Mark a peer as queried.
    pub fn mark_queried(&mut self, id: &NodeId) {
        self.queried.insert(*id);
    }

    /// Add new candidates, maintaining sorted order by distance to target.
    pub fn add_candidates(&mut self, new_peers: Vec<NodeInfo>, target: &NodeId) {
        for peer in new_peers {
            if !self.queried.contains(&peer.id) && !self.candidates.iter().any(|c| c.id == peer.id)
            {
                self.candidates.push(peer);
            }
        }
        self.candidates.sort_by_key(|p| p.id.distance(target));
        self.candidates.truncate(SKADEMLIA_K);
    }
}

/// S/Kademlia lookup with d=3 disjoint paths. Research Package §3.3, D-007.
///
/// Penyerang harus mengontrol node di semua 3 jalur independen untuk eclipse.
/// Eclipse probability: P ≈ (B/N)^(k*d) — Research Package §3.3.4.
pub struct DisjointLookup {
    pub target: NodeId,
    pub paths: Vec<LookupPath>,
    pub found: Vec<NodeInfo>,
}

impl DisjointLookup {
    /// Initialize d=3 disjoint lookup paths with different seed sets.
    ///
    /// Each path starts with a different subset of the closest known peers,
    /// ensuring path independence. Research Package §3.3.2 Perbaikan 3.
    pub fn new(target: NodeId, routing_table: &RoutingTable) -> Self {
        let all_closest = routing_table.closest_peers(&target, SKADEMLIA_K * SKADEMLIA_D);

        // Partition into d disjoint seed sets
        let mut paths = Vec::with_capacity(SKADEMLIA_D);
        for path_id in 0..SKADEMLIA_D {
            let seeds: Vec<NodeInfo> = all_closest
                .iter()
                .enumerate()
                .filter(|(i, _)| i % SKADEMLIA_D == path_id)
                .map(|(_, p)| p.clone())
                .collect();
            paths.push(LookupPath::new(path_id, seeds));
        }

        Self {
            target,
            paths,
            found: Vec::new(),
        }
    }

    /// Get next peers to query across all paths (alpha per path).
    pub fn next_queries(&self) -> Vec<(usize, Vec<NodeInfo>)> {
        self.paths
            .iter()
            .map(|path| (path.path_id, path.next_to_query(&self.target, ALPHA)))
            .filter(|(_, peers)| !peers.is_empty())
            .collect()
    }

    /// Update a path with query results.
    pub fn update_path(&mut self, path_id: usize, queried: &NodeId, responses: Vec<NodeInfo>) {
        if let Some(path) = self.paths.get_mut(path_id) {
            path.mark_queried(queried);
            path.add_candidates(responses, &self.target);
        }
    }

    /// Collect final results: k closest unique peers across all paths.
    pub fn finalize(&mut self) -> Vec<NodeInfo> {
        let mut all: Vec<NodeInfo> = self
            .paths
            .iter()
            .flat_map(|p| p.candidates.iter().cloned())
            .collect();

        // Deduplicate and sort by distance
        let mut seen = HashSet::new();
        all.retain(|p| seen.insert(p.id));
        all.sort_by_key(|p| p.id.distance(&self.target));
        all.truncate(SKADEMLIA_K);
        self.found = all.clone();
        all
    }

    /// Check if lookup is complete (all paths have no more unqueried candidates).
    pub fn is_complete(&self) -> bool {
        self.paths
            .iter()
            .all(|path| path.next_to_query(&self.target, 1).is_empty())
    }
}

// ── Signed routing message — Research Package §3.3.2 Perbaikan 2 ─────────────

/// Routing message signed with SLH-DSA. Research Package §3.3.2.
///
/// Prevents spoofing and man-in-the-middle attacks.
/// Verification uses scalar_crypto::sphincs::verify_signature.
#[derive(Debug, Clone)]
pub struct SignedRoutingMessage {
    /// Message type identifier.
    pub msg_type: RoutingMsgType,
    /// Sender node ID.
    pub sender_id: NodeId,
    /// Raw message payload.
    pub payload: Vec<u8>,
    /// SLH-DSA signature over (msg_type_byte || sender_id || payload).
    pub signature: Vec<u8>,
    /// Sender's SLH-DSA public key.
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RoutingMsgType {
    FindNode = 0x01,
    FindNodeResponse = 0x02,
    Ping = 0x03,
    Pong = 0x04,
}

impl SignedRoutingMessage {
    /// Canonical bytes for signing: msg_type || sender_id || payload.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.msg_type as u8);
        bytes.extend_from_slice(&self.sender_id.0);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Verify SLH-DSA signature. Research Package §3.3.2 Perbaikan 2.
    pub fn verify(&self) -> bool {
        if self.public_key.is_empty() || self.signature.is_empty() {
            return false;
        }
        let msg = self.canonical_bytes();
        scalar_crypto::sphincs::verify_signature(&msg, &self.signature, &self.public_key)
            .unwrap_or(false)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(seed: u8) -> NodeId {
        NodeId([seed; 32])
    }

    fn make_node(seed: u8) -> NodeInfo {
        NodeInfo {
            id: make_id(seed),
            pubkey: vec![seed; 32],
            addr: format!("node-{}.onion:4001", seed),
            last_seen: seed as u64 * 1000,
        }
    }

    // ── Constants — D-007 ─────────────────────────────────────────────────────

    #[test]
    fn test_skademlia_d_ossified() {
        // D-007: d = 3. Research Package §3.3, D-007.
        assert_eq!(SKADEMLIA_D, 3);
    }

    #[test]
    fn test_skademlia_k_ossified() {
        // D-007: k = 20. Research Package §3.3, D-007.
        assert_eq!(SKADEMLIA_K, 20);
    }

    // ── NodeId — XOR metric ───────────────────────────────────────────────────

    #[test]
    fn test_node_id_distance_self_is_zero() {
        let id = make_id(0x42);
        let dist = id.distance(&id);
        assert_eq!(dist.0, [0u8; 32]);
    }

    #[test]
    fn test_node_id_distance_symmetric() {
        let a = make_id(0x01);
        let b = make_id(0x02);
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn test_node_id_distance_nonzero() {
        let a = make_id(0x01);
        let b = make_id(0xFF);
        let dist = a.distance(&b);
        assert_ne!(dist.0, [0u8; 32]);
    }

    #[test]
    fn test_node_id_leading_zeros_all_zeros() {
        let id = NodeId([0u8; 32]);
        assert_eq!(id.leading_zeros(), KEY_BITS);
    }

    #[test]
    fn test_node_id_leading_zeros_first_bit_set() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80;
        let id = NodeId(bytes);
        assert_eq!(id.leading_zeros(), 0);
    }

    // ── KBucket ───────────────────────────────────────────────────────────────

    #[test]
    fn test_kbucket_insert_and_retrieve() {
        let mut bucket = KBucket::new();
        bucket.insert(make_node(1));
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_kbucket_max_size_k() {
        let mut bucket = KBucket::new();
        for i in 0..(SKADEMLIA_K + 5) as u8 {
            bucket.insert(make_node(i));
        }
        assert_eq!(bucket.len(), SKADEMLIA_K);
    }

    #[test]
    fn test_kbucket_idempotent_insert() {
        let mut bucket = KBucket::new();
        bucket.insert(make_node(1));
        bucket.insert(make_node(1));
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_kbucket_remove() {
        let mut bucket = KBucket::new();
        bucket.insert(make_node(1));
        bucket.remove(&make_id(1));
        assert_eq!(bucket.len(), 0);
    }

    // ── RoutingTable ──────────────────────────────────────────────────────────

    #[test]
    fn test_routing_table_insert() {
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local);
        rt.insert(make_node(0x01));
        assert_eq!(rt.peer_count(), 1);
    }

    #[test]
    fn test_routing_table_no_self_insert() {
        let local = make_id(0x42);
        let mut rt = RoutingTable::new(local);
        let self_node = NodeInfo {
            id: local,
            pubkey: vec![],
            addr: "self".to_string(),
            last_seen: 0,
        };
        rt.insert(self_node);
        assert_eq!(rt.peer_count(), 0);
    }

    #[test]
    fn test_routing_table_closest_peers() {
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local);
        for i in 1u8..=10 {
            rt.insert(make_node(i));
        }
        let target = make_id(0x05);
        let closest = rt.closest_peers(&target, 3);
        assert_eq!(closest.len(), 3);
        // Closest to 0x05 should include 0x05 itself if present, or nearby
        assert!(!closest.is_empty());
    }

    #[test]
    fn test_routing_table_peer_count() {
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local);
        for i in 1u8..=5 {
            rt.insert(make_node(i));
        }
        assert_eq!(rt.peer_count(), 5);
    }

    // ── DisjointLookup — d=3 ─────────────────────────────────────────────────

    #[test]
    fn test_disjoint_lookup_creates_d_paths() {
        // Research Package §3.3: d=3 disjoint paths. D-007.
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local);
        for i in 1u8..=30 {
            rt.insert(make_node(i));
        }
        let target = make_id(0xFF);
        let lookup = DisjointLookup::new(target, &rt);
        assert_eq!(lookup.paths.len(), SKADEMLIA_D);
        assert_eq!(lookup.paths.len(), 3);
    }

    #[test]
    fn test_disjoint_paths_are_disjoint() {
        // Each path has disjoint seed sets. Research Package §3.3.2.
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local);
        for i in 1u8..=30 {
            rt.insert(make_node(i));
        }
        let target = make_id(0xFF);
        let lookup = DisjointLookup::new(target, &rt);

        // Collect all seed IDs per path
        let path_sets: Vec<HashSet<NodeId>> = lookup
            .paths
            .iter()
            .map(|p| p.candidates.iter().map(|n| n.id).collect())
            .collect();

        // Verify disjoint: no ID appears in more than one path's seeds
        for i in 0..SKADEMLIA_D {
            for j in (i + 1)..SKADEMLIA_D {
                let intersection: HashSet<_> = path_sets[i].intersection(&path_sets[j]).collect();
                assert!(
                    intersection.is_empty(),
                    "Paths {i} and {j} share seed nodes — not disjoint"
                );
            }
        }
    }

    #[test]
    fn test_disjoint_lookup_finalize_deduplicates() {
        let local = make_id(0x00);
        let mut rt = RoutingTable::new(local);
        for i in 1u8..=20 {
            rt.insert(make_node(i));
        }
        let target = make_id(0x10);
        let mut lookup = DisjointLookup::new(target, &rt);
        let results = lookup.finalize();
        // Results should be deduplicated
        let ids: HashSet<NodeId> = results.iter().map(|p| p.id).collect();
        assert_eq!(ids.len(), results.len());
    }

    #[test]
    fn test_lookup_path_next_to_query() {
        let seeds = vec![make_node(1), make_node(2), make_node(3)];
        let path = LookupPath::new(0, seeds);
        let target = make_id(0x00);
        let next = path.next_to_query(&target, 2);
        assert_eq!(next.len(), 2);
    }

    #[test]
    fn test_lookup_path_mark_queried() {
        let seeds = vec![make_node(1), make_node(2)];
        let mut path = LookupPath::new(0, seeds);
        let target = make_id(0x00);
        path.mark_queried(&make_id(1));
        let next = path.next_to_query(&target, 10);
        assert!(!next.iter().any(|p| p.id == make_id(1)));
    }

    // ── SignedRoutingMessage ──────────────────────────────────────────────────

    #[test]
    fn test_signed_routing_msg_canonical_bytes() {
        let msg = SignedRoutingMessage {
            msg_type: RoutingMsgType::FindNode,
            sender_id: make_id(0x01),
            payload: vec![0x42; 10],
            signature: vec![],
            public_key: vec![],
        };
        let bytes = msg.canonical_bytes();
        // First byte = msg_type
        assert_eq!(bytes[0], RoutingMsgType::FindNode as u8);
        // Next 32 bytes = sender_id
        assert_eq!(&bytes[1..33], &[0x01u8; 32]);
        // Remaining = payload
        assert_eq!(&bytes[33..], &[0x42u8; 10]);
    }

    #[test]
    fn test_signed_routing_msg_empty_sig_rejected() {
        let msg = SignedRoutingMessage {
            msg_type: RoutingMsgType::Ping,
            sender_id: make_id(0x01),
            payload: vec![],
            signature: vec![],
            public_key: vec![],
        };
        assert!(!msg.verify());
    }

    #[test]
    fn test_routing_msg_type_values() {
        assert_eq!(RoutingMsgType::FindNode as u8, 0x01);
        assert_eq!(RoutingMsgType::FindNodeResponse as u8, 0x02);
        assert_eq!(RoutingMsgType::Ping as u8, 0x03);
        assert_eq!(RoutingMsgType::Pong as u8, 0x04);
    }
}
