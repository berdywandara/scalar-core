//! Anchor Rate Limiting — Rules A-1, A-2, A-3. MAD §8.1, ADR-SEC-008.
//!
//! A-1: Hanya proses anchor dari node dalam committed_manifest(k-1).
//!      Node baru → PENDING_REGISTRATION pool (max 1000/epoch, FIFO eviction).
//!
//! A-2: Rate limit: max 1 anchor per epoch per node.
//!      Max 1 AnchorExt transmission per ANCHOR_RATE_LIMIT_S (3600s).
//!      First offense: IGNORE. Second offense: SPAM_ANCHOR (DROP selama epoch).
//!
//! A-3: Queue capacity limit (FIFO). Max MAX_ANCHOR_QUEUE_SIZE entries.
//!      Queue penuh → DROP new entry.

use std::collections::{HashMap, VecDeque};

// ── CONSTRAINED parameters — MAD §21.2 ────────────────────────────────────────

/// Maximum anchor queue size. CONSTRAINED — MAD §21.2.
pub const MAX_ANCHOR_QUEUE_SIZE: usize = 500;

/// Rate limit: minimum seconds between AnchorExt transmissions. CONSTRAINED — MAD §21.2.
pub const ANCHOR_RATE_LIMIT_S: u64 = 3_600;

/// Maximum pending registrations per epoch (Rule A-1). MAD §8.1.
pub const MAX_PENDING_REGISTRATION: usize = 1_000;

// ── Anchor processing result ──────────────────────────────────────────────────

/// Result of anchor rate limit check. MAD §8.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorDecision {
    /// Accept — process normally.
    Accept,
    /// Ignore — first offense, do not process, do not penalize.
    Ignore { reason: IgnoreReason },
    /// Drop — SPAM_ANCHOR marked, drop for rest of epoch.
    Drop { reason: DropReason },
    /// Queue to PENDING_REGISTRATION — new node, not in manifest.
    PendingRegistration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreReason {
    /// Already received one anchor this epoch (A-2 first offense).
    DuplicateThisEpoch,
    /// Transmission too recent — within ANCHOR_RATE_LIMIT_S (A-2).
    RateLimitTransmission,
    /// Queue at capacity — new entry not accepted (A-3).
    QueueFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// SPAM_ANCHOR: second offense in same epoch (A-2).
    SpamAnchor,
    /// PENDING_REGISTRATION pool full, FIFO evict oldest (A-1).
    PendingPoolFull,
}

// ── Per-node state ────────────────────────────────────────────────────────────

/// Per-node epoch-scoped state (reset each epoch). MAD §8.1 A-2.
#[derive(Debug, Clone)]
struct NodeEpochState {
    anchor_count: u32,
    spam_anchor: bool,
}
impl NodeEpochState {
    fn new() -> Self {
        Self {
            anchor_count: 0,
            spam_anchor: false,
        }
    }
}

/// Per-node transmission state (persists across epochs). MAD §8.1 A-2.
#[derive(Debug, Clone)]
struct NodeTxState {
    last_transmission_s: Option<u64>,
}
impl NodeTxState {
    fn new() -> Self {
        Self {
            last_transmission_s: None,
        }
    }
}

// ── Priority queue entry ──────────────────────────────────────────────────────

/// Entry in the anchor processing queue. MAD §8.1 A-3.
#[derive(Debug, Clone)]
pub struct AnchorQueueEntry {
    /// Node short ID (4 bytes). Spec §7.2.
    pub node_id_short: [u8; 4],
    /// Full node ID (32 bytes).
    pub node_id_full: [u8; 32],
    /// Anchor received timestamp (Unix seconds).
    pub received_at_s: u64,
    /// Epoch ID.
    pub epoch_id: u64,
}

// ── PENDING_REGISTRATION pool ─────────────────────────────────────────────────

/// PENDING_REGISTRATION pool for new nodes (Rule A-1). MAD §8.1.
/// FIFO eviction when full. Max MAX_PENDING_REGISTRATION per epoch.
#[derive(Debug, Default)]
pub struct PendingRegistrationPool {
    /// Ordered queue: front = oldest (FIFO eviction target).
    queue: VecDeque<[u8; 32]>, // node_id_full
    /// Fast lookup: is node_id already pending?
    pending: HashMap<[u8; 32], u64>, // node_id_full → epoch_id
}

impl PendingRegistrationPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add node to pending pool. Returns true if added, false if already present.
    /// If pool full: FIFO evict oldest. MAD §8.1 A-1.
    pub fn add(&mut self, node_id_full: [u8; 32], epoch_id: u64) -> bool {
        if self.pending.contains_key(&node_id_full) {
            return false; // already pending
        }
        // Evict oldest if full
        if self.queue.len() >= MAX_PENDING_REGISTRATION {
            if let Some(oldest) = self.queue.pop_front() {
                self.pending.remove(&oldest);
            }
        }
        self.queue.push_back(node_id_full);
        self.pending.insert(node_id_full, epoch_id);
        true
    }

    /// Check if node is in pending pool.
    pub fn contains(&self, node_id_full: &[u8; 32]) -> bool {
        self.pending.contains_key(node_id_full)
    }

    /// Drain all pending registrations for a given epoch (epoch transition).
    pub fn drain_epoch(&mut self, epoch_id: u64) -> Vec<[u8; 32]> {
        let drained: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, &e)| e == epoch_id)
            .map(|(id, _)| *id)
            .collect();
        for id in &drained {
            self.pending.remove(id);
            self.queue.retain(|q| q != id);
        }
        drained
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

// ── Anchor Rate Limiter ───────────────────────────────────────────────────────

/// Anchor Rate Limiter implementing Rules A-1, A-2, A-3. MAD §8.1, ADR-SEC-008.
pub struct AnchorRateLimiter {
    /// Current epoch.
    current_epoch: u64,
    /// Per-node epoch state — reset each epoch.
    node_epoch: HashMap<[u8; 32], NodeEpochState>,
    /// Per-node transmission state — persists across epochs.
    node_tx: HashMap<[u8; 32], NodeTxState>,
    /// Committed manifest node list for current epoch (Rule A-1).
    /// Set of node_id_full from committed_manifest(k-1).
    manifest_nodes: std::collections::HashSet<[u8; 32]>,
    /// Priority queue for anchor processing (Rule A-3).
    /// Tier C anchors at back, Tier A/B at front.
    anchor_queue: VecDeque<AnchorQueueEntry>,
    /// PENDING_REGISTRATION pool for new nodes (Rule A-1).
    pending_registration: PendingRegistrationPool,
}

impl AnchorRateLimiter {
    /// Create new limiter for genesis epoch.
    pub fn new(initial_epoch: u64) -> Self {
        Self {
            current_epoch: initial_epoch,
            node_epoch: HashMap::new(),
            node_tx: HashMap::new(),
            manifest_nodes: std::collections::HashSet::new(),
            anchor_queue: VecDeque::new(),
            pending_registration: PendingRegistrationPool::new(),
        }
    }

    /// Update manifest node list at epoch transition. MAD §8.1 A-1.
    pub fn update_manifest(&mut self, manifest_node_ids: Vec<[u8; 32]>) {
        self.manifest_nodes = manifest_node_ids.into_iter().collect();
    }

    /// Transition to new epoch: reset per-node state. MAD §8.1 A-2.
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        self.current_epoch = new_epoch;
        self.node_epoch.clear(); // epoch-scoped state reset
                                 // node_tx NOT cleared — transmission rate limit persists
        self.anchor_queue.clear();
        // PENDING_REGISTRATION from previous epoch can be promoted to manifest
        // by the caller (outside scope of rate limiter).
    }

    /// Rule A-1 check: is node in manifest?
    fn is_in_manifest(&self, node_id_full: &[u8; 32]) -> bool {
        self.manifest_nodes.contains(node_id_full)
    }

    /// Rule A-2 check: rate limit per node. Returns decision if rate-limited.
    fn check_a2(&mut self, node_id_full: &[u8; 32], now_s: u64) -> Option<AnchorDecision> {
        // Epoch state (reset per epoch).
        let es = self
            .node_epoch
            .entry(*node_id_full)
            .or_insert_with(NodeEpochState::new);

        // SPAM_ANCHOR: second offense → DROP for rest of epoch.
        if es.spam_anchor {
            return Some(AnchorDecision::Drop {
                reason: DropReason::SpamAnchor,
            });
        }

        // Epoch duplicate check FIRST (A-2: max 1 per epoch).
        if es.anchor_count >= 1 {
            es.spam_anchor = true; // next attempt = DROP
            return Some(AnchorDecision::Ignore {
                reason: IgnoreReason::DuplicateThisEpoch,
            });
        }

        // Transmission rate limit (persists across epochs: max 1 per 3600s).
        let tx = self
            .node_tx
            .entry(*node_id_full)
            .or_insert_with(NodeTxState::new);
        if let Some(last_tx) = tx.last_transmission_s {
            if now_s.saturating_sub(last_tx) < ANCHOR_RATE_LIMIT_S {
                return Some(AnchorDecision::Ignore {
                    reason: IgnoreReason::RateLimitTransmission,
                });
            }
        }

        // Accept: update both states.
        let es = self.node_epoch.get_mut(node_id_full).unwrap();
        es.anchor_count += 1;
        let tx = self.node_tx.get_mut(node_id_full).unwrap();
        tx.last_transmission_s = Some(now_s);
        None
    }

    /// Rule A-3 check: queue capacity management (FIFO). MAD §8.1 A-3.
    fn check_a3(&mut self, entry: AnchorQueueEntry) -> AnchorDecision {
        if self.anchor_queue.len() < MAX_ANCHOR_QUEUE_SIZE {
            // Queue has space: add entry (FIFO). MAD §8.1 A-3.
            self.anchor_queue.push_back(entry);
            AnchorDecision::Accept
        } else {
            // Queue at capacity → ignore new entry. MAD §8.1 A-3.
            AnchorDecision::Ignore {
                reason: IgnoreReason::QueueFull,
            }
        }
    }

    /// Process an incoming anchor. Applies Rules A-1, A-2, A-3. MAD §8.1.
    ///
    /// `node_id_full`: 32-byte full node ID.
    /// `node_id_short`: 4-byte short ID.
    /// `now_s`: current Unix timestamp in seconds.
    /// Returns AnchorDecision for this anchor.
    pub fn process_anchor(
        &mut self,
        node_id_full: [u8; 32],
        node_id_short: [u8; 4],
        now_s: u64,
    ) -> AnchorDecision {
        // Rule A-1: check manifest membership.
        if !self.is_in_manifest(&node_id_full) {
            // New node: route to PENDING_REGISTRATION pool.
            let added = self
                .pending_registration
                .add(node_id_full, self.current_epoch);
            if added {
                return AnchorDecision::PendingRegistration;
            } else {
                // Already pending or pool full.
                return AnchorDecision::Ignore {
                    reason: IgnoreReason::DuplicateThisEpoch,
                };
            }
        }

        // Rule A-2: rate limit check.
        if let Some(decision) = self.check_a2(&node_id_full, now_s) {
            return decision;
        }

        // Rule A-3: priority queue.
        let entry = AnchorQueueEntry {
            node_id_short,
            node_id_full,
            received_at_s: now_s,
            epoch_id: self.current_epoch,
        };
        self.check_a3(entry)
    }

    /// Get next anchor to process from queue (highest priority first).
    pub fn dequeue(&mut self) -> Option<AnchorQueueEntry> {
        self.anchor_queue.pop_front()
    }

    /// Current queue length.
    pub fn queue_len(&self) -> usize {
        self.anchor_queue.len()
    }

    /// Pending registration count.
    pub fn pending_count(&self) -> usize {
        self.pending_registration.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn node_short(b: u8) -> [u8; 4] {
        [b; 4]
    }

    fn limiter_with_manifest(nodes: Vec<[u8; 32]>) -> AnchorRateLimiter {
        let mut l = AnchorRateLimiter::new(1);
        l.update_manifest(nodes);
        l
    }

    // ── Rule A-1 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_a1_manifest_node_accepted() {
        let n = node(0x01);
        let mut l = limiter_with_manifest(vec![n]);
        assert_eq!(
            l.process_anchor(n, node_short(0x01), 0),
            AnchorDecision::Accept
        );
    }

    #[test]
    fn test_a1_non_manifest_node_pending() {
        let n = node(0xFF);
        let mut l = limiter_with_manifest(vec![]);
        assert_eq!(
            l.process_anchor(n, node_short(0xFF), 0),
            AnchorDecision::PendingRegistration
        );
        assert_eq!(l.pending_count(), 1);
    }

    #[test]
    fn test_a1_already_pending_ignored() {
        let n = node(0xFF);
        let mut l = limiter_with_manifest(vec![]);
        l.process_anchor(n, node_short(0xFF), 0);
        // Second attempt: already pending.
        assert_eq!(
            l.process_anchor(n, node_short(0xFF), 0),
            AnchorDecision::Ignore {
                reason: IgnoreReason::DuplicateThisEpoch
            }
        );
    }

    #[test]
    fn test_a1_pending_pool_fifo_eviction() {
        let mut l = limiter_with_manifest(vec![]);
        // Fill pool
        for i in 0..MAX_PENDING_REGISTRATION {
            let n = [
                (i % 256) as u8,
                (i / 256) as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                i as u8,
            ];
            l.pending_registration.add(n, 1);
        }
        assert_eq!(l.pending_count(), MAX_PENDING_REGISTRATION);
        // Add one more: oldest is evicted.
        let new_node = [0xAAu8; 32];
        l.pending_registration.add(new_node, 1);
        assert_eq!(
            l.pending_count(),
            MAX_PENDING_REGISTRATION,
            "Pool stays at max"
        );
        assert!(
            l.pending_registration.contains(&new_node),
            "New node is present"
        );
    }

    // ── Rule A-2 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_a2_second_anchor_same_epoch_ignored() {
        let n = node(0x01);
        let mut l = limiter_with_manifest(vec![n]);
        l.process_anchor(n, node_short(0x01), 0);
        // Second anchor same epoch → IGNORE (first offense).
        assert_eq!(
            l.process_anchor(n, node_short(0x01), 1000),
            AnchorDecision::Ignore {
                reason: IgnoreReason::DuplicateThisEpoch
            }
        );
    }

    #[test]
    fn test_a2_third_anchor_spam_anchor_drop() {
        let n = node(0x01);
        let mut l = limiter_with_manifest(vec![n]);
        l.process_anchor(n, node_short(0x01), 0); // 1st: Accept
        l.process_anchor(n, node_short(0x01), 1000); // 2nd: Ignore (marks spam)
                                                     // 3rd: DROP — SPAM_ANCHOR.
        assert_eq!(
            l.process_anchor(n, node_short(0x01), 2000),
            AnchorDecision::Drop {
                reason: DropReason::SpamAnchor
            }
        );
    }

    #[test]
    fn test_a2_transmission_rate_limit() {
        let n = node(0x01);
        let mut l = limiter_with_manifest(vec![n]);
        l.process_anchor(n, node_short(0x01), 1000);

        // Simulate epoch advance — reset state.
        l.advance_epoch(2);
        l.update_manifest(vec![n]);

        // Too soon (within ANCHOR_RATE_LIMIT_S = 3600s).
        let too_soon = 1000 + ANCHOR_RATE_LIMIT_S - 1;
        assert_eq!(
            l.process_anchor(n, node_short(0x01), too_soon),
            AnchorDecision::Ignore {
                reason: IgnoreReason::RateLimitTransmission
            }
        );

        // After rate limit window.
        let ok_time = 1000 + ANCHOR_RATE_LIMIT_S;
        assert_eq!(
            l.process_anchor(n, node_short(0x01), ok_time),
            AnchorDecision::Accept
        );
    }

    #[test]
    fn test_a2_reset_on_epoch_advance() {
        let n = node(0x01);
        let mut l = limiter_with_manifest(vec![n]);
        l.process_anchor(n, node_short(0x01), 0);

        // New epoch: state reset, but rate limit window may still apply.
        l.advance_epoch(2);
        l.update_manifest(vec![n]);

        // Far enough in time: should accept.
        assert_eq!(
            l.process_anchor(n, node_short(0x01), ANCHOR_RATE_LIMIT_S + 1),
            AnchorDecision::Accept
        );
    }

    // ── Rule A-3 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_a3_queue_full_ignores_new_entry() {
        // Queue at capacity → new entry is ignored (FIFO). MAD §8.1 A-3.
        let mut l = AnchorRateLimiter::new(1);
        for i in 0..MAX_ANCHOR_QUEUE_SIZE {
            let mut n = [0u8; 32];
            n[0] = 0x01;
            n[1] = (i % 256) as u8;
            n[2] = (i / 256) as u8;
            l.manifest_nodes.insert(n);
            l.process_anchor(
                n,
                [0x01, (i % 256) as u8, (i / 256) as u8, 0],
                i as u64 * 4000,
            );
        }
        assert_eq!(l.queue_len(), MAX_ANCHOR_QUEUE_SIZE);

        // Any new anchor when queue full → IGNORE.
        let new_node = node(0xAA);
        l.manifest_nodes.insert(new_node);
        assert_eq!(
            l.process_anchor(
                new_node,
                node_short(0xAA),
                MAX_ANCHOR_QUEUE_SIZE as u64 * 4000
            ),
            AnchorDecision::Ignore {
                reason: IgnoreReason::QueueFull
            }
        );
    }

    #[test]
    fn test_a3_fifo_insertion_order() {
        // A-3 FIFO: entries are dequeued in insertion order. MAD §8.1 A-3.
        let node_a = node(0x01);
        let node_b = node(0x02);

        let mut l = limiter_with_manifest(vec![node_a, node_b]);

        // Insert in order A → B.
        l.process_anchor(node_a, node_short(0x01), 0);
        l.process_anchor(node_b, node_short(0x02), 4000);

        // Dequeue in FIFO order: A first, then B.
        let first = l.dequeue().unwrap();
        assert_eq!(
            first.node_id_full, node_a,
            "First inserted should be first dequeued"
        );
        let second = l.dequeue().unwrap();
        assert_eq!(
            second.node_id_full, node_b,
            "Second inserted should be second dequeued"
        );
    }

    #[test]
    fn test_a3_tier_a_evicts_tier_c_when_queue_full() {
        // After removing Tier C priority: queue full → all entries ignored (FIFO). MAD §8.1 A-3.
        let node_a = node(0x01);
        let node_b = node(0x02);
        let mut l = limiter_with_manifest(vec![node_a, node_b]);

        // Fill queue to capacity with node_a entries across epochs
        for i in 0..MAX_ANCHOR_QUEUE_SIZE {
            let mut n = [0u8; 32];
            n[0] = 0x01;
            n[1] = (i % 256) as u8;
            n[2] = (i / 256) as u8;
            l.manifest_nodes.insert(n);
            l.process_anchor(n, [0x01, (i % 256) as u8, (i / 256) as u8, 0], i as u64 * 4000);
        }
        assert_eq!(l.queue_len(), MAX_ANCHOR_QUEUE_SIZE);

        // Queue full → any new entry is ignored regardless of node identity. MAD §8.1 A-3.
        assert_eq!(
            l.process_anchor(node_b, node_short(0x02), MAX_ANCHOR_QUEUE_SIZE as u64 * 4000),
            AnchorDecision::Ignore { reason: IgnoreReason::QueueFull }
        );
    }
    #[test]
    fn test_anchor_constants() {
        assert_eq!(MAX_ANCHOR_QUEUE_SIZE, 500);
        assert_eq!(ANCHOR_RATE_LIMIT_S, 3_600);
        assert_eq!(MAX_PENDING_REGISTRATION, 1_000);
    }
}
