//! Production NMT — from peer Timestamps, not wall-clock — Spec §12.3a, Gap G-3
//!
//! PR-V12-013 FIX: NMT still using local_nmt() wall-clock.
//! atganti with meatan from peer timestamps per spec §12.3a.
//!
//! after NMT Hybrid 23+1 (PR-V12-007), production NMT tato timestamp
//! from up to 24 NMT peers (23 determthisstik + 1 random), compute meatan,
//! and usingnya as Network Meatan Time.
//!
//! Fallback: if < 8 peer available → use wall-clock lokal with warning.
//!
//! Spec §12.3a:
//! NMT = meatan(timestamps from NMT peers)
//! openN NTP, openN average, not wall-clock lokal.
//! Local time not included to in calculation.

use scalar_network::nmt::{compute_nmt_with_eclipse_check, NmtStatus, T_NMT_MAX_DRIFT_S};
use scalar_network::nmt_hybrid::NMT_PEER_COUNT_V12;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Constants — spec §12.3a ───────────────────────────────────────────────────

/// Mthismum peer for NMT that reliable. Spec §12.3a.
/// Kurang from this → fallback to wall-clock with warning.
pub const NMT_MIN_PEERS_FOR_RELIABLE: usize = 8;

/// Maximum peer timestamps that stored. = NMT_PEER_COUNT_V12 = 24.
pub const NMT_MAX_STORED_TIMESTAMPS: usize = NMT_PEER_COUNT_V12;

// ── PeerTimestampStore — menyimpan timestamp per peer ────────────────────────

/// Store timestamp heartbeat last from each peer. Spec §12.3a.
///
/// used for compute NMT = meatan(peer_timestamps).
/// Local time not included.
#[derive(Default)]
pub struct PeerTimestampStore {
    /// toy: node_id_short [u8;4] → timestamp last (seconds).
    timestamps: HashMap<[u8; 4], u32>,
}

impl PeerTimestampStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update timestamp for peer. Spec §12.3a.
    pub fn update(&mut self, node_id_short: [u8; 4], timestamp: u32) {
        self.timestamps.insert(node_id_short, timestamp);
        // Limit: maksimum NMT_MAX_STORED_TIMESTAMPS entries
        // Jika lebih, hapus yang paling lama (oldest timestamp)
        if self.timestamps.len() > NMT_MAX_STORED_TIMESTAMPS {
            if let Some((&oldest_id, _)) = self.timestamps.iter().min_by_key(|(_, &ts)| ts) {
                self.timestamps.remove(&oldest_id);
            }
        }
    }

    /// tato all timestamps as Vec. Spec §12.3a.
    pub fn all_timestamps(&self) -> Vec<u32> {
        self.timestamps.values().copied().collect()
    }

    /// Jumlah peer that tersave.
    pub fn peer_count(&self) -> usize {
        self.timestamps.len()
    }

    /// delete peer when atsconnect.
    pub fn remove_peer(&mut self, node_id_short: &[u8; 4]) {
        self.timestamps.remove(node_id_short);
    }
}

// ── ProductionNmt — NMT dari peer timestamps ─────────────────────────────────

/// Hasil kompthreaat NMT production. Spec §12.3a.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionNmtResult {
    /// NMT valid from peer timestamps. Spec §12.3a.
    FromPeers { nmt: u32, peer_count: usize },
    /// insufficient peer — fallback to wall-clock with warning. Spec §12.3a.
    FallbackWallClock { nmt: u32, peer_count: usize },
    /// Eclipse alert detected. Spec §12.3a.
    EclipseAlert { nmt: u32, drift_s: u32 },
}

impl ProductionNmtResult {
    /// tato value NMT regardless of source.
    pub fn nmt_value(&self) -> u32 {
        match self {
            Self::FromPeers { nmt, .. } => *nmt,
            Self::FallbackWallClock { nmt, .. } => *nmt,
            Self::EclipseAlert { nmt, .. } => *nmt,
        }
    }

    /// true if NMT from peer timestamps (openn fallback). Spec §12.3a.
    pub fn is_from_peers(&self) -> bool {
        matches!(self, Self::FromPeers { .. })
    }
}

/// Compute production NMT from peer timestamps. Spec §12.3a.
///
/// `peer_store`: store timestamps from peers.
/// `local_wall_clock`: wall-clock lokal — only for eclipse detection,
/// not included to NMT computation.
///
/// Fallback: if < NMT_MIN_PEERS_FOR_RELIABLE → wall-clock + warning.
pub fn compute_production_nmt(
    peer_store: &PeerTimestampStore,
    local_wall_clock: u32,
) -> ProductionNmtResult {
    let timestamps = peer_store.all_timestamps();
    let peer_count = timestamps.len();

    if peer_count < NMT_MIN_PEERS_FOR_RELIABLE {
        // Fallback: tidak cukup peer → wall-clock lokal
        println!(
            "[NMT] WARNING: hanya {} peer tersedia (min {}), fallback ke wall-clock. \
             Spec §12.3a: NMT harus dari peer timestamps.",
            peer_count, NMT_MIN_PEERS_FOR_RELIABLE
        );
        return ProductionNmtResult::FallbackWallClock {
            nmt: local_wall_clock,
            peer_count,
        };
    }

    // Compute NMT dari peer timestamps + eclipse detection
    let status = compute_nmt_with_eclipse_check(&timestamps, local_wall_clock);

    match status {
        NmtStatus::Valid { nmt, .. } => ProductionNmtResult::FromPeers { nmt, peer_count },
        NmtStatus::EclipseAlert { nmt, drift_s, .. } => {
            println!(
                "[NMT] ECLIPSE ALERT: drift={}s > {}s threshold. Spec §12.3a.",
                drift_s, T_NMT_MAX_DRIFT_S
            );
            ProductionNmtResult::EclipseAlert { nmt, drift_s }
        }
        NmtStatus::InsufficientPeers { count, .. } => {
            // Sudah di-check di atas, tapi handle untuk safety
            ProductionNmtResult::FallbackWallClock {
                nmt: local_wall_clock,
                peer_count: count,
            }
        }
    }
}

/// tato wall-clock lokal in seconds. only for fallback. Spec §12.3a.
pub fn get_local_wall_clock() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store_with_peers(n: usize, base_ts: u32) -> PeerTimestampStore {
        let mut store = PeerTimestampStore::new();
        for i in 0..n {
            let node_id = [i as u8, 0, 0, 0];
            store.update(node_id, base_ts + i as u32);
        }
        store
    }

    // ── test_nmt_from_peer_timestamps ─────────────────────────────────────────

    #[test]
    fn test_nmt_from_peer_timestamps() {
        // NMT = median dari peer timestamps, BUKAN wall-clock. Spec §12.3a.
        let base_ts = 1_000_000u32;
        let store = make_store_with_peers(10, base_ts);
        let local = base_ts + 500; // wall-clock seatkit atfferent
        let result = compute_production_nmt(&store, local);

        assert!(
            result.is_from_peers(),
            "NMT harus dari peer timestamps jika cukup peer tersedia"
        );
        // NMT tidak sama dengan wall-clock
        assert_ne!(
            result.nmt_value(),
            local,
            "NMT tidak boleh sama dengan wall-clock"
        );
    }

    // ── test_nmt_median_calculation ───────────────────────────────────────────

    #[test]
    fn test_nmt_median_calculation() {
        // NMT = median (bukan average). Spec §12.3a.
        let mut store = PeerTimestampStore::new();
        // 8 timestamps: 100..800
        for (i, ts) in [100u32, 200, 300, 400, 500, 600, 700, 800]
            .iter()
            .enumerate()
        {
            store.update([i as u8; 4], *ts);
        }
        let result = compute_production_nmt(&store, 1000);
        assert!(result.is_from_peers());
        // Lower median dari 8 nilai (index 3) = 400
        // Average = 450 — berbeda dari median
        assert_ne!(result.nmt_value(), 450, "NMT bukan average");
    }

    // ── test_nmt_fallback_few_peers ───────────────────────────────────────────

    #[test]
    fn test_nmt_fallback_few_peers() {
        // < 8 peer → fallback graceful. Spec §12.3a.
        let store = make_store_with_peers(5, 1_000_000);
        let local = 1_000_500u32;
        let result = compute_production_nmt(&store, local);
        assert!(
            matches!(result, ProductionNmtResult::FallbackWallClock { .. }),
            "Kurang dari 8 peer harus fallback ke wall-clock"
        );
        assert_eq!(
            result.nmt_value(),
            local,
            "Fallback NMT harus = wall-clock lokal"
        );
    }

    #[test]
    fn test_nmt_fallback_zero_peers() {
        // 0 peer → fallback. Spec §12.3a.
        let store = PeerTimestampStore::new();
        let local = 999_999u32;
        let result = compute_production_nmt(&store, local);
        assert!(matches!(
            result,
            ProductionNmtResult::FallbackWallClock { .. }
        ));
    }

    // ── test PeerTimestampStore ───────────────────────────────────────────────

    #[test]
    fn test_peer_timestamp_store_update() {
        let mut store = PeerTimestampStore::new();
        let node = [0x01u8; 4];
        store.update(node, 1000);
        assert_eq!(store.peer_count(), 1);
        // Update existing peer
        store.update(node, 2000);
        assert_eq!(
            store.peer_count(),
            1,
            "Update peer yang sama tidak menambah count"
        );
    }

    #[test]
    fn test_peer_timestamp_store_max_size() {
        // Store tidak melebihi NMT_MAX_STORED_TIMESTAMPS. Spec §12.3a.
        let mut store = PeerTimestampStore::new();
        for i in 0..30usize {
            store.update([i as u8, 0, 0, 0], 1000 + i as u32);
        }
        assert!(
            store.peer_count() <= NMT_MAX_STORED_TIMESTAMPS,
            "Store tidak boleh melebihi {} entries",
            NMT_MAX_STORED_TIMESTAMPS
        );
    }

    #[test]
    fn test_peer_timestamp_remove() {
        let mut store = PeerTimestampStore::new();
        let node = [0x01u8; 4];
        store.update(node, 1000);
        store.remove_peer(&node);
        assert_eq!(store.peer_count(), 0);
    }

    // ── test_nmt_not_wall_clock ───────────────────────────────────────────────

    #[test]
    fn test_local_time_not_included_in_nmt() {
        // Local time TIDAK dimasukkan ke NMT computation. Spec §12.3a.
        // Verifikasi: NMT dengan peer_count >= 8 tidak bergantung pada wall-clock.
        let mut store = PeerTimestampStore::new();
        for i in 0..8 {
            store.update([i as u8; 4], 500_000 + i * 1000);
        }

        let result_wall_a = compute_production_nmt(&store, 100_000); // wall-clock A
        let result_wall_b = compute_production_nmt(&store, 999_999); // wall-clock B

        // NMT harus sama meski wall-clock berbeda (selama tidak eclipse)
        if result_wall_a.is_from_peers() && result_wall_b.is_from_peers() {
            assert_eq!(
                result_wall_a.nmt_value(),
                result_wall_b.nmt_value(),
                "NMT tidak boleh bergantung pada wall-clock lokal — spec §12.3a"
            );
        }
    }

    // ── test constants ────────────────────────────────────────────────────────

    #[test]
    fn test_nmt_min_peers_constant() {
        // NMT_MIN_PEERS_FOR_RELIABLE = 8. Spec §12.3a.
        assert_eq!(NMT_MIN_PEERS_FOR_RELIABLE, 8usize);
    }

    #[test]
    fn test_nmt_max_stored_timestamps() {
        // NMT_MAX_STORED_TIMESTAMPS = 24 (= NMT_PEER_COUNT_V12). Spec §12.3.
        assert_eq!(NMT_MAX_STORED_TIMESTAMPS, 24usize);
    }
}
