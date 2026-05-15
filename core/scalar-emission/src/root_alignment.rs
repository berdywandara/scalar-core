//! root Alignment Snapshot Buffer — Spec §7.3
//!
//! root_alignment_score mengukur seberapa sering SMT root node i
//! matches majority root in window snapshot last.
//!
//! Spec §7.3:
//!   root_alignment_score = matched_snapshots / total_snapshots (fp basis 1_000_000)
//! Window = ALIGNMENT_WINDOW_SIZE snapshot last
//! Score 1_000_000 = all snapshot cocok (perfect alignment)
//! Score 0 = none snapshot that cocok (node atvergen)
//!
//! Snapshot taton each heartbeat. Majority root = root that owned
//! ≥50% node in network on when snapshot.
//!
//! used oleh compute_uptime_weight() as komponen 30%.
//! No floating point — all arithmetic integer fixed-point basis 1_000_000.

// ── Constants — spec §7.3 ────────────────────────────────────────────────────

/// Jumlah snapshot that stored for alignment calculation. Spec §7.3.
/// Window = 10 snapshot last.
pub const ALIGNMENT_WINDOW_SIZE: usize = 10;

/// Fixed-point basis for alignment score. Spec §7.3.
pub const ALIGNMENT_FP_BASIS: u64 = 1_000_000;

// ── RootSnapshot — satu snapshot per heartbeat ───────────────────────────────

/// Satu root snapshot from satu heartbeat. Spec §7.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSnapshot {
    /// SMT root node this on when snapshot.
    pub node_root: [u8; 32],
    /// Majority root network on when snapshot (from konsensus).
    pub majority_root: [u8; 32],
    /// seq_num when snapshot taton.
    pub seq_num: u32,
}

impl RootSnapshot {
    /// whether node root matches majority root? Spec §7.3.
    pub fn is_aligned(&self) -> bool {
        self.node_root == self.majority_root
    }
}

// ── RootAlignmentBuffer — spec §7.3 ──────────────────────────────────────────

/// Ring buffer snapshot for root alignment calculation. Spec §7.3.
///
/// store ALIGNMENT_WINDOW_SIZE snapshot last.
/// compute root_alignment_score = matched / total in fp basis 1_000_000.
#[derive(Debug)]
pub struct RootAlignmentBuffer {
    /// Ring buffer — circular, overwrites oldest entry.
    snapshots: [Option<RootSnapshot>; ALIGNMENT_WINDOW_SIZE],
    /// Index for entry next.
    next_idx: usize,
    /// Total snapshot that ever atinsert (for count calculation).
    total_inserted: usize,
}

impl RootAlignmentBuffer {
    pub fn new() -> Self {
        Self {
            snapshots: std::array::from_fn(|_| None),
            next_idx: 0,
            total_inserted: 0,
        }
    }

    /// add snapshot new. Spec §7.3.
    ///
    /// Overwrites entry paling old if buffer full.
    pub fn push(&mut self, snapshot: RootSnapshot) {
        self.snapshots[self.next_idx] = Some(snapshot);
        self.next_idx = (self.next_idx + 1) % ALIGNMENT_WINDOW_SIZE;
        self.total_inserted += 1;
    }

    /// Hitung jumlah snapshot that ada in buffer.
    pub fn count(&self) -> usize {
        self.snapshots.iter().filter(|s| s.is_some()).count()
    }

    /// Hitung jumlah snapshot that cocok (node_root == majority_root). Spec §7.3.
    pub fn matched_count(&self) -> usize {
        self.snapshots
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|s| s.is_aligned())
            .count()
    }

    /// Hitung root_alignment_score in fixed-point basis 1_000_000. Spec §7.3.
    ///
    /// score = matched_snapshots / total_snapshots × 1_000_000
    ///
    /// Returns 0 if none snapshot (node new).
    /// Returns 1_000_000 if all snapshot cocok (perfect alignment).
    pub fn alignment_score_fp(&self) -> u64 {
        let total = self.count() as u64;
        if total == 0 {
            return 0;
        }
        let matched = self.matched_count() as u64;
        // Integer fixed-point: matched / total × 1_000_000
        matched
            .saturating_mul(ALIGNMENT_FP_BASIS)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// tato snapshot latest. Spec §7.3.
    pub fn latest(&self) -> Option<&RootSnapshot> {
        // next_idx - 1 adalah entry terbaru
        let last_idx = self
            .next_idx
            .checked_sub(1)
            .unwrap_or(ALIGNMENT_WINDOW_SIZE - 1);
        self.snapshots[last_idx].as_ref()
    }

    /// check whether buffer full (ALIGNMENT_WINDOW_SIZE snapshot). Spec §7.3.
    pub fn is_full(&self) -> bool {
        self.count() == ALIGNMENT_WINDOW_SIZE
    }
}

impl Default for RootAlignmentBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper: compute majority root dari peer roots ────────────────────────────

/// Compute majority root of slice of (node_id, smt_root) pairs. Spec §7.3.
///
/// Majority root = root that owned ≥50% node.
/// Returns None if none majority (split network).
/// No floating point — all arithmetic integer.
pub fn compute_majority_root(peer_roots: &[([u8; 4], [u8; 32])]) -> Option<[u8; 32]> {
    if peer_roots.is_empty() {
        return None;
    }

    let total = peer_roots.len();
    let threshold = total / 2 + 1; // strictly > 50%

    // Count occurrence per root
    let mut counts: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();
    for (_, root) in peer_roots {
        *counts.entry(*root).or_insert(0) += 1;
    }

    // Find root dengan count >= threshold
    counts
        .into_iter()
        .find(|(_, count)| *count >= threshold)
        .map(|(root, _)| root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_snapshot(node_root: u8, majority_root: u8, seq: u32) -> RootSnapshot {
        RootSnapshot {
            node_root: make_root(node_root),
            majority_root: make_root(majority_root),
            seq_num: seq,
        }
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_alignment_window_size_is_10() {
        // Spec §7.3: window = 10 snapshot.
        assert_eq!(ALIGNMENT_WINDOW_SIZE, 10usize);
    }

    #[test]
    fn test_alignment_fp_basis_is_1_000_000() {
        // Fixed-point basis. Spec §7.3.
        assert_eq!(ALIGNMENT_FP_BASIS, 1_000_000u64);
    }

    // ── RootSnapshot ──────────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_aligned_when_roots_match() {
        // node_root == majority_root → aligned. Spec §7.3.
        let s = RootSnapshot {
            node_root: make_root(0x42),
            majority_root: make_root(0x42),
            seq_num: 1,
        };
        assert!(s.is_aligned());
    }

    #[test]
    fn test_snapshot_not_aligned_when_roots_differ() {
        // node_root ≠ majority_root → not aligned. Spec §7.3.
        let s = RootSnapshot {
            node_root: make_root(0x01),
            majority_root: make_root(0x02),
            seq_num: 1,
        };
        assert!(!s.is_aligned());
    }

    // ── RootAlignmentBuffer ───────────────────────────────────────────────────

    #[test]
    fn test_buffer_empty_score_zero() {
        // Buffer kosong → score = 0. Spec §7.3.
        let buf = RootAlignmentBuffer::new();
        assert_eq!(buf.alignment_score_fp(), 0);
        assert_eq!(buf.count(), 0);
    }

    #[test]
    fn test_buffer_all_aligned_score_1_000_000() {
        // Semua snapshot aligned → score = 1_000_000. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        for i in 0u32..10 {
            buf.push(make_snapshot(0x42, 0x42, i)); // node = majority
        }
        assert_eq!(buf.alignment_score_fp(), 1_000_000);
    }

    #[test]
    fn test_buffer_none_aligned_score_zero() {
        // Tidak ada yang aligned → score = 0. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        for i in 0u32..10 {
            buf.push(make_snapshot(0x01, 0x02, i)); // node ≠ majority
        }
        assert_eq!(buf.alignment_score_fp(), 0);
    }

    #[test]
    fn test_buffer_half_aligned_score_500_000() {
        // 5/10 aligned → score = 500_000. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        for i in 0u32..5 {
            buf.push(make_snapshot(0x42, 0x42, i)); // aligned
        }
        for i in 5u32..10 {
            buf.push(make_snapshot(0x01, 0x02, i)); // not aligned
        }
        assert_eq!(buf.alignment_score_fp(), 500_000);
    }

    #[test]
    fn test_buffer_7_of_10_aligned() {
        // 7/10 aligned → score = 700_000. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        for i in 0u32..7 {
            buf.push(make_snapshot(0x42, 0x42, i));
        }
        for i in 7u32..10 {
            buf.push(make_snapshot(0x01, 0x02, i));
        }
        assert_eq!(buf.alignment_score_fp(), 700_000);
    }

    #[test]
    fn test_buffer_ring_overwrites_oldest() {
        // Buffer penuh → entry lama di-overwrite. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        // Isi 10 snapshot tidak aligned
        for i in 0u32..10 {
            buf.push(make_snapshot(0x01, 0x02, i));
        }
        assert_eq!(buf.alignment_score_fp(), 0);
        // Overwrite semua dengan aligned snapshots
        for i in 10u32..20 {
            buf.push(make_snapshot(0x42, 0x42, i));
        }
        // Sekarang semua 10 slot adalah aligned
        assert_eq!(buf.alignment_score_fp(), 1_000_000);
    }

    #[test]
    fn test_buffer_window_size_limit() {
        // Buffer tidak menyimpan lebih dari ALIGNMENT_WINDOW_SIZE. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        for i in 0u32..20 {
            buf.push(make_snapshot(0x42, 0x42, i));
        }
        assert_eq!(buf.count(), ALIGNMENT_WINDOW_SIZE);
    }

    #[test]
    fn test_buffer_is_full() {
        // is_full() benar setelah ALIGNMENT_WINDOW_SIZE snapshot. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        for i in 0u32..(ALIGNMENT_WINDOW_SIZE as u32) {
            assert!(!buf.is_full());
            buf.push(make_snapshot(0x42, 0x42, i));
        }
        assert!(buf.is_full());
    }

    #[test]
    fn test_buffer_latest_returns_most_recent() {
        // latest() harus return snapshot terakhir yang dipush. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        buf.push(make_snapshot(0x01, 0x01, 1));
        buf.push(make_snapshot(0x42, 0x42, 99));
        let latest = buf.latest().unwrap();
        assert_eq!(latest.seq_num, 99);
    }

    #[test]
    fn test_buffer_partial_fill_score() {
        // Buffer dengan 3 snapshot (2 aligned) → score = 666_666. Spec §7.3.
        let mut buf = RootAlignmentBuffer::new();
        buf.push(make_snapshot(0x42, 0x42, 1));
        buf.push(make_snapshot(0x42, 0x42, 2));
        buf.push(make_snapshot(0x01, 0x02, 3));
        // 2/3 × 1_000_000 = 666_666 (integer division)
        assert_eq!(buf.alignment_score_fp(), 666_666);
    }

    #[test]
    fn test_no_floating_point() {
        // Semua kalkulasi integer — spec global.
        let mut buf = RootAlignmentBuffer::new();
        for i in 0u32..10 {
            buf.push(make_snapshot(if i < 3 { 0x42 } else { 0x01 }, 0x42, i));
        }
        // 3/10 × 1_000_000 = 300_000
        assert_eq!(buf.alignment_score_fp(), 300_000);
    }

    // ── compute_majority_root ─────────────────────────────────────────────────

    #[test]
    fn test_majority_root_clear_majority() {
        // 3/4 sama → majority. Spec §7.3.
        let peers = vec![
            ([0x01u8; 4], make_root(0xAA)),
            ([0x02u8; 4], make_root(0xAA)),
            ([0x03u8; 4], make_root(0xAA)),
            ([0x04u8; 4], make_root(0xBB)),
        ];
        assert_eq!(compute_majority_root(&peers), Some(make_root(0xAA)));
    }

    #[test]
    fn test_majority_root_tie_returns_none() {
        // 2/4 vs 2/4 → no majority. Spec §7.3.
        let peers = vec![
            ([0x01u8; 4], make_root(0xAA)),
            ([0x02u8; 4], make_root(0xAA)),
            ([0x03u8; 4], make_root(0xBB)),
            ([0x04u8; 4], make_root(0xBB)),
        ];
        assert!(compute_majority_root(&peers).is_none());
    }

    #[test]
    fn test_majority_root_empty_returns_none() {
        // Tidak ada peer → None. Spec §7.3.
        assert!(compute_majority_root(&[]).is_none());
    }

    #[test]
    fn test_majority_root_all_same() {
        // Semua sama → majority jelas. Spec §7.3.
        let peers: Vec<([u8; 4], [u8; 32])> =
            (0u8..8).map(|i| ([i, 0, 0, 0], make_root(0x42))).collect();
        assert_eq!(compute_majority_root(&peers), Some(make_root(0x42)));
    }

    #[test]
    fn test_majority_root_single_peer() {
        // 1 peer → majority (1/1 = 100%). Spec §7.3.
        let peers = vec![([0x01u8; 4], make_root(0xFF))];
        assert_eq!(compute_majority_root(&peers), Some(make_root(0xFF)));
    }
}
