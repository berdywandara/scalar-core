// File: crates/scalar-network/src/dandelion.rs
//
// Dandelion++ Privacy Protocol — Spec §12.7
//
// Pipeline:
//   STEM phase  → single-path forwarding (menyembunyikan origin)
//   FLUFF phase → broadcast ke semua peers (seperti gossip biasa)
//
// Tambahan Timing Defense:
//   - Random delay 0-10 detik sebelum broadcast (CSPRNG)
//   - Message padding ke 4 ukuran standar: 1KB/16KB/64KB/256KB
//   - Proving time normalized 300ms ± 10ms (anti timing side-channel)

use std::collections::HashMap;

// ── Konstanta Spec §12.7 ──────────────────────────────────────────────

/// Probabilitas transisi STEM → FLUFF per hop. Spec §12.7.
/// Setiap node memiliki peluang STEM_TO_FLUFF_PROB untuk beralih ke fluff.
/// Nilai tipikal Dandelion++: ~10% per hop.
pub const STEM_TO_FLUFF_PROB_PERCENT: u64 = 10;

/// Maximum hop STEM sebelum paksa masuk FLUFF. Anti-infinite-stem.
pub const MAX_STEM_HOPS: u64 = 10;

/// Random delay maksimum sebelum broadcast: 10 detik. Spec §12.7.
pub const MAX_BROADCAST_DELAY_SECS: u64 = 10;

/// Ukuran padding standar (bytes). Spec §12.7: 1KB/16KB/64KB/256KB.
pub const PADDING_SIZES: [usize; 4] = [1_024, 16_384, 65_536, 262_144];

/// Proving time target (ms). Spec §12.7: normalized 300ms ± 10ms.
pub const PROVING_TIME_TARGET_MS: u64 = 300;

/// Toleransi proving time (ms). Spec §12.7: ±10ms.
pub const PROVING_TIME_TOLERANCE_MS: u64 = 10;

// ── Phase State ───────────────────────────────────────────────────────

/// Phase propagasi pesan Dandelion++.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DandelionPhase {
    /// STEM: forward ke satu peer saja. Menyembunyikan origin.
    Stem {
        /// Jumlah hop STEM yang sudah ditempuh.
        hops_remaining: u64,
    },
    /// FLUFF: broadcast ke semua peers seperti gossip biasa.
    Fluff,
}

impl DandelionPhase {
    /// Buat STEM phase baru dengan max hop.
    pub fn new_stem() -> Self {
        DandelionPhase::Stem {
            hops_remaining: MAX_STEM_HOPS,
        }
    }

    /// True jika masih dalam STEM phase.
    pub fn is_stem(&self) -> bool {
        matches!(self, DandelionPhase::Stem { .. })
    }

    /// True jika sudah masuk FLUFF phase.
    pub fn is_fluff(&self) -> bool {
        matches!(self, DandelionPhase::Fluff)
    }
}

// ── Message Padding ───────────────────────────────────────────────────

/// Pilih ukuran padding terkecil yang ≥ payload_size. Spec §12.7.
/// Jika payload melebihi ukuran terbesar, gunakan ukuran terbesar.
pub fn select_padding_size(payload_size: usize) -> usize {
    for &size in &PADDING_SIZES {
        if payload_size <= size {
            return size;
        }
    }
    // Payload > 256KB: gunakan ukuran terbesar
    *PADDING_SIZES.last().unwrap()
}

/// Hitung jumlah padding bytes yang harus ditambahkan.
pub fn compute_padding_bytes(payload_size: usize) -> usize {
    let target = select_padding_size(payload_size);
    target.saturating_sub(payload_size)
}

// ── Timing Defense ────────────────────────────────────────────────────

/// Validasi proving time dalam range yang diizinkan spec §12.7.
/// Proving time WAJIB 300ms ± 10ms untuk mencegah timing side-channel.
pub fn is_proving_time_valid(proving_time_ms: u64) -> bool {
    let min = PROVING_TIME_TARGET_MS.saturating_sub(PROVING_TIME_TOLERANCE_MS);
    let max = PROVING_TIME_TARGET_MS + PROVING_TIME_TOLERANCE_MS;
    proving_time_ms >= min && proving_time_ms <= max
}

/// Validasi broadcast delay dalam range 0-10 detik. Spec §12.7.
pub fn is_broadcast_delay_valid(delay_secs: u64) -> bool {
    delay_secs <= MAX_BROADCAST_DELAY_SECS
}

// ── Stem Routing ──────────────────────────────────────────────────────

/// Hasil routing keputusan untuk satu pesan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Teruskan ke satu peer (STEM).
    ForwardStem { next_peer_idx: usize },
    /// Broadcast ke semua peers (FLUFF).
    Broadcast,
}

/// Tentukan routing decision untuk pesan dalam STEM phase.
///
/// Menggunakan deterministic pseudo-random berdasarkan:
/// - tx_id: ID transaksi (sebagai entropy source)
/// - hop_count: hop ke berapa
/// - num_peers: jumlah peers yang tersedia
///
/// Transisi ke FLUFF jika:
/// 1. hops_remaining == 0, atau
/// 2. pseudo-random < STEM_TO_FLUFF_PROB_PERCENT
pub fn decide_stem_routing(
    phase: &DandelionPhase,
    tx_id: u64,
    hop_count: u64,
    num_peers: usize,
) -> RoutingDecision {
    match phase {
        DandelionPhase::Fluff => RoutingDecision::Broadcast,
        DandelionPhase::Stem { hops_remaining } => {
            if *hops_remaining == 0 || num_peers == 0 {
                return RoutingDecision::Broadcast;
            }

            // Pseudo-random untuk transisi STEM→FLUFF
            // Menggunakan simple deterministic hash untuk testability
            // Production: ganti dengan CSPRNG
            let pseudo_rand = simple_hash(tx_id, hop_count) % 100;
            if pseudo_rand < STEM_TO_FLUFF_PROB_PERCENT {
                return RoutingDecision::Broadcast;
            }

            // Pilih peer untuk STEM forwarding (deterministic untuk test)
            let peer_idx = simple_hash(tx_id, hop_count + 1) as usize % num_peers;
            RoutingDecision::ForwardStem {
                next_peer_idx: peer_idx,
            }
        }
    }
}

/// Advance STEM phase: kurangi hops_remaining.
/// Jika hops_remaining sudah 0, transisi ke FLUFF.
pub fn advance_stem_phase(phase: DandelionPhase) -> DandelionPhase {
    match phase {
        DandelionPhase::Stem { hops_remaining } => {
            if hops_remaining == 0 {
                DandelionPhase::Fluff
            } else {
                DandelionPhase::Stem {
                    hops_remaining: hops_remaining - 1,
                }
            }
        }
        DandelionPhase::Fluff => DandelionPhase::Fluff,
    }
}

// ── Stem Path Tracker ─────────────────────────────────────────────────

/// Melacak jalur STEM per transaksi untuk anti-correlation.
/// Spec §12.7: setiap tx harus menggunakan path yang berbeda.
pub struct StemPathTracker {
    /// tx_id → (stem_peer_idx, hop_count)
    paths: HashMap<u64, (usize, u64)>,
}

impl StemPathTracker {
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
        }
    }

    /// Rekam peer yang digunakan untuk STEM forwarding tx ini.
    pub fn record_stem_hop(&mut self, tx_id: u64, peer_idx: usize) {
        let entry = self.paths.entry(tx_id).or_insert((peer_idx, 0));
        entry.1 += 1;
    }

    /// Ambil jumlah hop STEM yang sudah ditempuh tx ini.
    pub fn hop_count(&self, tx_id: u64) -> u64 {
        self.paths.get(&tx_id).map(|(_, hops)| *hops).unwrap_or(0)
    }

    /// Hapus tracking setelah masuk FLUFF (hemat memori).
    pub fn clear_tx(&mut self, tx_id: u64) {
        self.paths.remove(&tx_id);
    }

    /// Jumlah transaksi yang sedang dalam STEM phase.
    pub fn active_stem_count(&self) -> usize {
        self.paths.len()
    }
}

impl Default for StemPathTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper ────────────────────────────────────────────────────────────

/// Simple deterministic hash untuk routing decision (non-crypto, hanya untuk test).
/// Production: gunakan ChaCha20 CSPRNG.
fn simple_hash(a: u64, b: u64) -> u64 {
    // FNV-1a style mix
    let mut h: u64 = 14_695_981_039_346_656_037;
    h ^= a;
    h = h.wrapping_mul(1_099_511_628_211);
    h ^= b;
    h = h.wrapping_mul(1_099_511_628_211);
    h
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Phase ─────────────────────────────────────────────────────────

    #[test]
    fn test_new_stem_phase() {
        let phase = DandelionPhase::new_stem();
        assert!(phase.is_stem());
        assert!(!phase.is_fluff());
        assert_eq!(
            phase,
            DandelionPhase::Stem {
                hops_remaining: MAX_STEM_HOPS
            }
        );
    }

    #[test]
    fn test_fluff_phase() {
        let phase = DandelionPhase::Fluff;
        assert!(phase.is_fluff());
        assert!(!phase.is_stem());
    }

    #[test]
    fn test_advance_stem_decrements_hops() {
        let phase = DandelionPhase::Stem { hops_remaining: 3 };
        let next = advance_stem_phase(phase);
        assert_eq!(next, DandelionPhase::Stem { hops_remaining: 2 });
    }

    #[test]
    fn test_advance_stem_zero_transitions_to_fluff() {
        let phase = DandelionPhase::Stem { hops_remaining: 0 };
        let next = advance_stem_phase(phase);
        assert_eq!(next, DandelionPhase::Fluff);
    }

    #[test]
    fn test_advance_fluff_stays_fluff() {
        let next = advance_stem_phase(DandelionPhase::Fluff);
        assert_eq!(next, DandelionPhase::Fluff);
    }

    // ── Padding ───────────────────────────────────────────────────────

    #[test]
    fn test_padding_small_payload_to_1kb() {
        assert_eq!(select_padding_size(100), 1_024);
    }

    #[test]
    fn test_padding_exact_1kb() {
        assert_eq!(select_padding_size(1_024), 1_024);
    }

    #[test]
    fn test_padding_1kb_plus_1_to_16kb() {
        assert_eq!(select_padding_size(1_025), 16_384);
    }

    #[test]
    fn test_padding_exact_256kb() {
        assert_eq!(select_padding_size(262_144), 262_144);
    }

    #[test]
    fn test_padding_overflow_stays_at_256kb() {
        assert_eq!(select_padding_size(500_000), 262_144);
    }

    #[test]
    fn test_compute_padding_bytes() {
        // 100 byte payload → padded ke 1024 → 924 bytes padding
        assert_eq!(compute_padding_bytes(100), 924);
    }

    #[test]
    fn test_compute_padding_exact_size_no_padding() {
        // Tepat 1024 → tidak ada padding tambahan
        assert_eq!(compute_padding_bytes(1_024), 0);
    }

    // ── Timing ────────────────────────────────────────────────────────

    #[test]
    fn test_proving_time_valid_at_300ms() {
        assert!(is_proving_time_valid(300));
    }

    #[test]
    fn test_proving_time_valid_at_290ms() {
        assert!(is_proving_time_valid(290));
    }

    #[test]
    fn test_proving_time_valid_at_310ms() {
        assert!(is_proving_time_valid(310));
    }

    #[test]
    fn test_proving_time_invalid_at_289ms() {
        assert!(!is_proving_time_valid(289));
    }

    #[test]
    fn test_proving_time_invalid_at_311ms() {
        assert!(!is_proving_time_valid(311));
    }

    #[test]
    fn test_broadcast_delay_valid_zero() {
        assert!(is_broadcast_delay_valid(0));
    }

    #[test]
    fn test_broadcast_delay_valid_10s() {
        assert!(is_broadcast_delay_valid(10));
    }

    #[test]
    fn test_broadcast_delay_invalid_11s() {
        assert!(!is_broadcast_delay_valid(11));
    }

    // ── Routing ───────────────────────────────────────────────────────

    #[test]
    fn test_fluff_phase_always_broadcasts() {
        let decision = decide_stem_routing(&DandelionPhase::Fluff, 42, 0, 5);
        assert_eq!(decision, RoutingDecision::Broadcast);
    }

    #[test]
    fn test_stem_zero_hops_broadcasts() {
        let phase = DandelionPhase::Stem { hops_remaining: 0 };
        let decision = decide_stem_routing(&phase, 42, 5, 5);
        assert_eq!(decision, RoutingDecision::Broadcast);
    }

    #[test]
    fn test_stem_no_peers_broadcasts() {
        let phase = DandelionPhase::new_stem();
        let decision = decide_stem_routing(&phase, 42, 0, 0);
        assert_eq!(decision, RoutingDecision::Broadcast);
    }

    #[test]
    fn test_stem_forward_peer_within_bounds() {
        // Jika tidak transisi ke fluff, peer_idx harus < num_peers
        let phase = DandelionPhase::Stem {
            hops_remaining: MAX_STEM_HOPS,
        };
        let num_peers = 7usize;
        // Coba beberapa tx_id sampai dapat ForwardStem
        let mut got_forward = false;
        for tx_id in 0u64..100 {
            let decision = decide_stem_routing(&phase, tx_id, 0, num_peers);
            if let RoutingDecision::ForwardStem { next_peer_idx } = decision {
                assert!(next_peer_idx < num_peers);
                got_forward = true;
                break;
            }
        }
        assert!(
            got_forward,
            "Harus ada setidaknya satu ForwardStem dalam 100 tx"
        );
    }

    #[test]
    fn test_stem_probabilistic_transition_occurs() {
        // Dengan STEM_TO_FLUFF_PROB_PERCENT=10, dalam 200 percobaan
        // harus ada minimal satu transisi ke Broadcast
        let phase = DandelionPhase::Stem {
            hops_remaining: MAX_STEM_HOPS,
        };
        let mut got_broadcast = false;
        for tx_id in 0u64..200 {
            let decision = decide_stem_routing(&phase, tx_id, 1, 5);
            if decision == RoutingDecision::Broadcast {
                got_broadcast = true;
                break;
            }
        }
        assert!(
            got_broadcast,
            "Harus ada transisi STEM→FLUFF dalam 200 percobaan"
        );
    }

    // ── StemPathTracker ───────────────────────────────────────────────

    #[test]
    fn test_stem_tracker_records_hops() {
        let mut tracker = StemPathTracker::new();
        tracker.record_stem_hop(100, 2);
        tracker.record_stem_hop(100, 2);
        assert_eq!(tracker.hop_count(100), 2);
    }

    #[test]
    fn test_stem_tracker_unknown_tx_zero_hops() {
        let tracker = StemPathTracker::new();
        assert_eq!(tracker.hop_count(999), 0);
    }

    #[test]
    fn test_stem_tracker_clear_tx() {
        let mut tracker = StemPathTracker::new();
        tracker.record_stem_hop(1, 0);
        assert_eq!(tracker.active_stem_count(), 1);
        tracker.clear_tx(1);
        assert_eq!(tracker.active_stem_count(), 0);
    }

    #[test]
    fn test_constants_match_spec() {
        // Spec §12.7
        assert_eq!(MAX_BROADCAST_DELAY_SECS, 10);
        assert_eq!(PROVING_TIME_TARGET_MS, 300);
        assert_eq!(PROVING_TIME_TOLERANCE_MS, 10);
        assert_eq!(PADDING_SIZES, [1_024, 16_384, 65_536, 262_144]);
        assert_eq!(MAX_STEM_HOPS, 10);
    }
}
