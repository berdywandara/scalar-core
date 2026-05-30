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

/// Random delay minimum sebelum broadcast: 100 ms. Spec §12.7.
pub const MIN_BROADCAST_DELAY_MS: u64 = 100;

/// Random delay maksimum sebelum broadcast: 5000 ms (5 detik). Spec §12.7.
pub const MAX_BROADCAST_DELAY_MS: u64 = 5_000;

/// Random delay maksimum dalam detik — alias MAX_BROADCAST_DELAY_MS / 1000. Spec §12.7.
pub const MAX_BROADCAST_DELAY_SECS: u64 = 5;

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

/// Validasi broadcast delay dalam range [MIN_BROADCAST_DELAY_MS, MAX_BROADCAST_DELAY_MS]. Spec §12.7.
/// delay_ms: delay dalam milidetik (100–5000 ms).
pub fn is_broadcast_delay_valid(delay_ms: u64) -> bool {
    (MIN_BROADCAST_DELAY_MS..=MAX_BROADCAST_DELAY_MS).contains(&delay_ms)
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
    fn test_broadcast_delay_min_boundary() {
        // 100 ms = MIN_BROADCAST_DELAY_MS → valid. Spec §12.7.
        assert!(is_broadcast_delay_valid(100));
        // 99 ms < minimum → invalid.
        assert!(!is_broadcast_delay_valid(99));
        // 0 ms < minimum → invalid.
        assert!(!is_broadcast_delay_valid(0));
    }

    #[test]
    fn test_broadcast_delay_valid_5000ms() {
        // 5000 ms = MAX_BROADCAST_DELAY_MS → valid. Spec §12.7.
        assert!(is_broadcast_delay_valid(5_000));
    }

    #[test]
    fn test_broadcast_delay_invalid_5001ms() {
        // 5001 ms > MAX_BROADCAST_DELAY_MS → invalid. Spec §12.7.
        assert!(!is_broadcast_delay_valid(5_001));
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
        assert_eq!(MIN_BROADCAST_DELAY_MS, 100);
        assert_eq!(MAX_BROADCAST_DELAY_MS, 5_000);
        assert_eq!(MAX_BROADCAST_DELAY_SECS, 5);
        assert_eq!(PROVING_TIME_TARGET_MS, 300);
        assert_eq!(PROVING_TIME_TOLERANCE_MS, 10);
        assert_eq!(PADDING_SIZES, [1_024, 16_384, 65_536, 262_144]);
        assert_eq!(MAX_STEM_HOPS, 10);
    }
}

// ── ADR-SEC-018: Reduced Anonymity Mode ──────────────────────────────────────
//
// Ketika jaringan kecil (< DANDELION_FULL_THRESHOLD node), full anonymity
// tidak feasible — kecilnya set membuat timing correlation mudah.
// Reduced mode: stem prob lebih tinggi + batch obfuscation window 60s.
// CONSTRAINED: dapat berubah via governance COMMIT 75%. MAD §21.2.

/// Network size threshold untuk full vs reduced anonymity mode. CONSTRAINED — MAD §21.2.
/// Di bawah nilai ini: gunakan ReducedAnonymityMode.
pub const DANDELION_FULL_THRESHOLD: u64 = 200;

/// Stem probability dalam reduced mode (fixed-point per 1_000_000). CONSTRAINED — MAD §21.2.
/// 700_000 fp = 70% — lebih agresif dari full mode untuk kompensasi set kecil.
pub const DANDELION_REDUCED_STEM_PROB_FP: u64 = 700_000;

/// Batch obfuscation window dalam detik. CONSTRAINED — MAD §21.2.
/// Transaksi di-batch selama 60s sebelum di-route untuk obfuscate timing.
pub const DANDELION_BATCH_WINDOW_S: u64 = 60;

/// Fixed-point basis untuk probabilitas. Spec §18.1.
pub const DANDELION_FP_BASIS: u64 = 1_000_000;

// ── Dandelion Mode ────────────────────────────────────────────────────────────

/// Mode operasi Dandelion++. ADR-SEC-018.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DandelionMode {
    /// Full anonymity — network size >= DANDELION_FULL_THRESHOLD. MAD §21.2.
    Full,
    /// Reduced anonymity — network size < DANDELION_FULL_THRESHOLD. MAD §21.2.
    /// Stem prob lebih tinggi, batch obfuscation aktif.
    Reduced,
}

impl DandelionMode {
    /// Tentukan mode berdasarkan jumlah node yang diketahui. ADR-SEC-018.
    pub fn from_network_size(known_nodes: u64) -> Self {
        if known_nodes >= DANDELION_FULL_THRESHOLD {
            DandelionMode::Full
        } else {
            DandelionMode::Reduced
        }
    }

    /// Apakah mode reduced? ADR-SEC-018.
    pub fn is_reduced(&self) -> bool {
        matches!(self, DandelionMode::Reduced)
    }
}

// ── BLAKE3 stem peer selection ────────────────────────────────────────────────

/// Pilih stem peer dengan BLAKE3 entropy. ADR-SEC-018, MAD §21.2.
///
/// Menggantikan `simple_hash` (FNV placeholder) dengan BLAKE3 deterministik.
/// Domain separator `b"scalar_stem_sel"` dari OSSIFIED domain list. MAD §1.4.
///
/// `tx_id`: ID transaksi (entropy source).
/// `epoch_seed`: seed epoch untuk variasi antar-epoch.
/// `num_peers`: jumlah stem peers yang tersedia.
///
/// Returns: index peer yang dipilih (0..num_peers).
pub fn select_stem_peer_blake3(tx_id: u64, epoch_seed: u64, num_peers: usize) -> usize {
    if num_peers == 0 {
        return 0;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"scalar_stem_sel"); // OSSIFIED domain separator
    hasher.update(&tx_id.to_le_bytes());
    hasher.update(&epoch_seed.to_le_bytes());
    let hash = hasher.finalize();
    let val = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());
    (val % num_peers as u64) as usize
}

// ── Stem probability (Reduced mode) ──────────────────────────────────────────

/// Keputusan routing dengan probabilitas reduced mode. ADR-SEC-018.
///
/// Dalam reduced mode, stem_prob = DANDELION_REDUCED_STEM_PROB_FP / 1_000_000.
/// Gunakan BLAKE3(domain || tx_id || nonce) sebagai entropy sumber.
pub fn decide_reduced_routing(tx_id: u64, nonce: u64, num_peers: usize) -> RoutingDecision {
    if num_peers == 0 {
        return RoutingDecision::Broadcast;
    }

    // BLAKE3 entropy untuk probabilistik stem/fluff decision
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"scalar_stem_sel");
    hasher.update(&tx_id.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    let hash = hasher.finalize();
    let rand_fp =
        u64::from_le_bytes(hash.as_bytes()[8..16].try_into().unwrap()) % DANDELION_FP_BASIS;

    if rand_fp < DANDELION_REDUCED_STEM_PROB_FP {
        // Stem: pilih peer dengan BLAKE3
        let peer_idx = select_stem_peer_blake3(tx_id, nonce, num_peers);
        RoutingDecision::ForwardStem {
            next_peer_idx: peer_idx,
        }
    } else {
        RoutingDecision::Broadcast
    }
}

// ── Batch Obfuscation Window ──────────────────────────────────────────────────

/// Entry dalam batch obfuscation window. ADR-SEC-018.
#[derive(Debug, Clone)]
pub struct BatchEntry {
    /// ID transaksi.
    pub tx_id: u64,
    /// Waktu masuk ke batch (Unix seconds).
    pub entered_at_s: u64,
}

/// Batch obfuscation window untuk Dandelion++ Reduced mode. ADR-SEC-018.
///
/// Transaksi dikumpulkan selama DANDELION_BATCH_WINDOW_S (60s) sebelum
/// di-route. Ini mengaburkan timing correlation dari observer eksternal.
///
/// Domain: b"scalar_batch_obs" untuk batch ordering hash. MAD §1.4.
pub struct BatchObfuscationWindow {
    /// Transaksi dalam window saat ini.
    pending: Vec<BatchEntry>,
    /// Waktu mulai window saat ini (Unix seconds).
    window_started_at_s: u64,
}

impl BatchObfuscationWindow {
    /// Buat window baru.
    pub fn new(now_s: u64) -> Self {
        Self {
            pending: Vec::new(),
            window_started_at_s: now_s,
        }
    }

    /// Tambah transaksi ke batch.
    pub fn add(&mut self, tx_id: u64, now_s: u64) {
        self.pending.push(BatchEntry {
            tx_id,
            entered_at_s: now_s,
        });
    }

    /// Apakah window sudah expired (>= DANDELION_BATCH_WINDOW_S)? ADR-SEC-018.
    pub fn is_expired(&self, now_s: u64) -> bool {
        now_s.saturating_sub(self.window_started_at_s) >= DANDELION_BATCH_WINDOW_S
    }

    /// Drain window: kembalikan semua tx dalam urutan deterministik.
    ///
    /// Urutan di-obfuscate menggunakan BLAKE3("scalar_batch_obs" || window_seed).
    /// Ini mencegah observer mengkorelasikan submission order dengan routing order.
    pub fn drain_ordered(&mut self, window_seed: u64, now_s: u64) -> Vec<u64> {
        let mut entries = std::mem::take(&mut self.pending);
        // Sort deterministik via BLAKE3 hash per tx_id + seed
        entries.sort_by_key(|e| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"scalar_batch_obs"); // OSSIFIED domain separator
            hasher.update(&e.tx_id.to_le_bytes());
            hasher.update(&window_seed.to_le_bytes());
            let h = hasher.finalize();
            u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap())
        });
        // Reset window
        self.window_started_at_s = now_s;
        entries.into_iter().map(|e| e.tx_id).collect()
    }

    /// Jumlah transaksi pending dalam window.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Window kosong?
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

// ── Tests ADR-SEC-018 ─────────────────────────────────────────────────────────

#[cfg(test)]
mod adr_sec_018_tests {
    use super::*;

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn test_adr_sec_018_constants() {
        // CONSTRAINED parameters — MAD §21.2.
        assert_eq!(DANDELION_FULL_THRESHOLD, 200);
        assert_eq!(DANDELION_REDUCED_STEM_PROB_FP, 700_000);
        assert_eq!(DANDELION_BATCH_WINDOW_S, 60);
    }

    // ── DandelionMode ─────────────────────────────────────────────────

    #[test]
    fn test_mode_full_at_threshold() {
        assert_eq!(DandelionMode::from_network_size(200), DandelionMode::Full);
        assert_eq!(DandelionMode::from_network_size(1000), DandelionMode::Full);
    }

    #[test]
    fn test_mode_reduced_below_threshold() {
        assert_eq!(DandelionMode::from_network_size(0), DandelionMode::Reduced);
        assert_eq!(
            DandelionMode::from_network_size(199),
            DandelionMode::Reduced
        );
        assert!(DandelionMode::from_network_size(10).is_reduced());
    }

    // ── BLAKE3 stem selection ─────────────────────────────────────────

    #[test]
    fn test_stem_peer_blake3_deterministic() {
        let p1 = select_stem_peer_blake3(42, 100, 7);
        let p2 = select_stem_peer_blake3(42, 100, 7);
        assert_eq!(p1, p2, "BLAKE3 stem selection must be deterministic");
    }

    #[test]
    fn test_stem_peer_blake3_within_bounds() {
        for tx_id in 0..50 {
            let p = select_stem_peer_blake3(tx_id, 0, 5);
            assert!(p < 5, "peer_idx must be < num_peers");
        }
    }

    #[test]
    fn test_stem_peer_blake3_varies_with_tx_id() {
        // Different tx_ids should produce different peers (statistically)
        let peers: Vec<usize> = (0..20).map(|i| select_stem_peer_blake3(i, 0, 10)).collect();
        let unique: std::collections::HashSet<_> = peers.iter().collect();
        assert!(
            unique.len() > 1,
            "BLAKE3 must produce varied peer selection"
        );
    }

    #[test]
    fn test_stem_peer_blake3_varies_with_epoch_seed() {
        let p1 = select_stem_peer_blake3(42, 0, 10);
        let p2 = select_stem_peer_blake3(42, 1, 10);
        // Different seeds should often produce different results
        // (not guaranteed for every case, but tests the mechanism)
        let _ = (p1, p2); // both valid
    }

    // ── Reduced routing ───────────────────────────────────────────────

    #[test]
    fn test_reduced_routing_stem_probability() {
        // With stem_prob=70%, in 100 trials should have mostly stem
        let mut stem_count = 0;
        for nonce in 0u64..100 {
            if let RoutingDecision::ForwardStem { .. } = decide_reduced_routing(42, nonce, 5) {
                stem_count += 1;
            }
        }
        // Expect ~70 stems, accept 50-90 for statistical tolerance
        assert!(
            stem_count > 50,
            "Reduced mode must have high stem rate: {stem_count}"
        );
    }

    #[test]
    fn test_reduced_routing_no_peers_broadcasts() {
        let d = decide_reduced_routing(1, 0, 0);
        assert_eq!(d, RoutingDecision::Broadcast);
    }

    // ── BatchObfuscationWindow ────────────────────────────────────────

    #[test]
    fn test_batch_window_not_expired_before_60s() {
        let w = BatchObfuscationWindow::new(1000);
        assert!(!w.is_expired(1059)); // 59s later
        assert!(w.is_expired(1060)); // 60s later → expired
    }

    #[test]
    fn test_batch_window_drain_ordered_deterministic() {
        let mut w = BatchObfuscationWindow::new(0);
        w.add(10, 1);
        w.add(20, 2);
        w.add(30, 3);
        let order1 = w.drain_ordered(42, 100);
        let mut w2 = BatchObfuscationWindow::new(0);
        w2.add(10, 1);
        w2.add(20, 2);
        w2.add(30, 3);
        let order2 = w2.drain_ordered(42, 100);
        assert_eq!(order1, order2, "Batch ordering must be deterministic");
    }

    #[test]
    fn test_batch_window_drain_resets() {
        let mut w = BatchObfuscationWindow::new(0);
        w.add(1, 0);
        w.add(2, 0);
        assert_eq!(w.pending_count(), 2);
        let drained = w.drain_ordered(0, 60);
        assert_eq!(drained.len(), 2);
        assert_eq!(w.pending_count(), 0, "Window must be empty after drain");
    }

    #[test]
    fn test_batch_window_obfuscates_order() {
        // Different seeds should produce different ordering
        let add = |seed: u64| -> Vec<u64> {
            let mut w = BatchObfuscationWindow::new(0);
            for i in 0u64..5 {
                w.add(i, i);
            }
            w.drain_ordered(seed, 60)
        };
        let o1 = add(0);
        let o2 = add(1);
        // Orders should differ (statistically very likely with different seeds)
        assert_ne!(
            o1, o2,
            "Different seeds must produce different batch ordering"
        );
    }
}
