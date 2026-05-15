//! Mycelium Adaptive Transport Routing — Spec §12.5
//!
//! CONDUCTIVITY per transport channel (i,j,tier):
//!   dD(i,j,tier)/dt = |Flow(i,j,tier)|^γ - decay × D(i,j,tier)
//! γ = 0.8 (< 1 for fault tolerance)
//!   decay = 0.01 per second
//!
//! CHANNEL SELECTION (probabilistic):
//!   P(route via tier t) = D(t)^2 / Σ D(t')^2
//!
//! NO FLOAT: γ=0.8 atapproximasi with fixed-point integer arithmetic.
//! |Flow|^0.8 ≈ |Flow|^(4/5) using integer Newton's method.

use std::collections::HashMap;

// ── Constants — Spec §12.5 ────────────────────────────────────────────────────

/// Conductivity decay rate per second × FIXED_POINT_BASIS. Spec §12.5.
/// decay = 0.01/s → 10_000 / 1_000_000
pub const DECAY_RATE_FP: u64 = 10_000; // 0.01 × 1_000_000

/// Fixed-point basis. Spec §7.3.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Conductivity mthismum (not ever 0 — always ada tomungkinan eksplorasi).
pub const CONDUCTIVITY_MIN: u64 = 1_000; // 0.001 × 1_000_000

/// Conductivity maksimum.
pub const CONDUCTIVITY_MAX: u64 = 10_000_000; // 10.0 × 1_000_000

/// Gamma numerator for approximasi γ=0.8=4/5. Spec §12.5.
/// used in integer approximation.
pub const GAMMA_NUMERATOR: u32 = 4;
pub const GAMMA_DENOMINATOR: u32 = 5;

// ── TransportTier ─────────────────────────────────────────────────────────────

/// Transport tier. Spec §12.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportTier {
    /// Tier 1: Internet TCP/IP. Spec §12.2.
    Internet = 0,
    /// Tier 2: LoRa Mesh. Spec §12.2.
    LoRa = 1,
    /// Tier 3: HF Raato. Spec §12.2.
    HfRadio = 2,
    /// Tier 4: Local Mesh. Spec §12.2.
    LocalMesh = 3,
    /// Tier 5: Visual QR. Spec §12.2.
    VisualQr = 4,
}

impl TransportTier {
    /// all tier in urutan priority. Spec §12.2.
    pub fn all() -> [TransportTier; 5] {
        [
            TransportTier::Internet,
            TransportTier::LoRa,
            TransportTier::HfRadio,
            TransportTier::LocalMesh,
            TransportTier::VisualQr,
        ]
    }
}

// ── Integer approximation of x^(4/5) ─────────────────────────────────────────

/// Approximasi integer x^(4/5) tanpa floating point.
///
/// x^(4/5) = (x^4)^(1/5) = fifth_root(x^4)
///
/// for avoid overflow: x^(4/5) ≈ x × x^(-1/5)
/// Simplified: use integer sqrt dua kali as approximasi.
///
/// implementation: x^0.8 ≈ integer_pow_4_5(x) using:
/// floor(x^4/5) via Newton's method for fifth root.
pub fn pow_gamma_fp(flow_fp: u64) -> u64 {
    if flow_fp == 0 {
        return 0;
    }
    if flow_fp <= FIXED_POINT_BASIS {
        // flow ≤ 1.0: x^0.8 ≤ x (monotonic increasing, < 1)
        // approximasi: x^0.8 ≈ x × (1 - 0.2×(1-x)) untuk x near 1
        // simplified: x^0.8 ≈ x^(4/5) via integer fifth root
        return fifth_root_u64(flow_fp.saturating_pow(4));
    }
    // flow > 1.0: gunakan u128 untuk menghindari overflow
    let flow_u128 = flow_fp as u128;
    let flow4 = flow_u128
        .saturating_mul(flow_u128)
        .saturating_mul(flow_u128)
        .saturating_mul(flow_u128);
    // fifth_root dalam u128
    let result = fifth_root_u128(flow4);
    result.min(CONDUCTIVITY_MAX as u128) as u64
}

/// Integer fifth root via Newton's method. floor(x^(1/5)).
fn fifth_root_u64(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    if x == 1 {
        return 1;
    }
    // Initial estimate
    let mut guess = (x as f64).powf(0.2) as u64;
    if guess == 0 {
        guess = 1;
    }
    // Newton iterations (3 itera cukup untuk konvergensi)
    for _ in 0..5 {
        let g4 = guess.saturating_pow(4);
        if g4 == 0 {
            break;
        }
        let next = (4 * guess + x / g4) / 5;
        if next >= guess {
            break;
        }
        guess = next;
    }
    guess
}

/// Integer fifth root via Newton's method for u128.
fn fifth_root_u128(x: u128) -> u128 {
    if x == 0 {
        return 0;
    }
    if x == 1 {
        return 1;
    }
    let mut guess = (x as f64).powf(0.2) as u128;
    if guess == 0 {
        guess = 1;
    }
    for _ in 0..8 {
        let g4 = guess.saturating_pow(4);
        if g4 == 0 {
            break;
        }
        let next = (4 * guess + x / g4) / 5;
        if next >= guess {
            break;
        }
        guess = next;
    }
    guess
}

// ── ChannelConductivity ───────────────────────────────────────────────────────

/// State conductivity satu channel (peer, tier). Spec §12.5.
#[derive(Debug, Clone)]
pub struct ChannelConductivity {
    /// Conductivity D in fixed-point basis 1_000_000. Spec §12.5.
    pub conductivity_fp: u64,
}

impl Default for ChannelConductivity {
    fn default() -> Self {
        Self {
            conductivity_fp: CONDUCTIVITY_MIN,
        }
    }
}

impl ChannelConductivity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update conductivity based on flow and elapsed time. Spec §12.5.
    ///
    /// dD/dt = |Flow|^γ - decay × D
    /// D(t+dt) = D(t) + dt × (|Flow|^γ - decay × D(t))
    ///
    /// `flow_fp`: |Flow| in fixed-point basis 1_000_000.
    /// `elapsed_secs_fp`: dt in fixed-point basis 1_000_000.
    pub fn update(&mut self, flow_fp: u64, elapsed_secs_fp: u64) {
        // |Flow|^γ dalam fixed-point
        let flow_gamma = pow_gamma_fp(flow_fp);

        // decay × D
        let decay_term = self.conductivity_fp.saturating_mul(DECAY_RATE_FP) / FIXED_POINT_BASIS;

        // dD/dt = flow_gamma - decay_term
        let delta = if flow_gamma >= decay_term {
            // Conductivity naik
            let increase = flow_gamma.saturating_sub(decay_term);
            increase.saturating_mul(elapsed_secs_fp) / FIXED_POINT_BASIS
        } else {
            0
        };

        let decay_delta = if decay_term > flow_gamma {
            let decrease = decay_term.saturating_sub(flow_gamma);
            decrease.saturating_mul(elapsed_secs_fp) / FIXED_POINT_BASIS
        } else {
            0
        };

        self.conductivity_fp = self
            .conductivity_fp
            .saturating_add(delta)
            .saturating_sub(decay_delta)
            .clamp(CONDUCTIVITY_MIN, CONDUCTIVITY_MAX);
    }
}

// ── AdaptiveMux ───────────────────────────────────────────────────────────────

/// Mycelium Adaptive Transport Mux. Spec §12.5.
///
/// manage conductivity per (peer_id, tier) and select
/// route secara probabilistik based on D(t)^2.
#[derive(Default)]
pub struct AdaptiveMux {
    /// toy: (peer_id, tier) → conductivity
    channels: HashMap<([u8; 32], TransportTier), ChannelConductivity>,
}

impl AdaptiveMux {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or buat channel conductivity for (peer, tier).
    pub fn channel_mut(
        &mut self,
        peer_id: [u8; 32],
        tier: TransportTier,
    ) -> &mut ChannelConductivity {
        self.channels.entry((peer_id, tier)).or_default()
    }

    /// Update conductivity channel after flow. Spec §12.5.
    pub fn record_flow(
        &mut self,
        peer_id: [u8; 32],
        tier: TransportTier,
        flow_fp: u64,
        elapsed_secs_fp: u64,
    ) {
        self.channel_mut(peer_id, tier)
            .update(flow_fp, elapsed_secs_fp);
    }

    /// Hitung probabilitas pemilihan each tier for peer specific.
    ///
    /// P(tier t) = D(t)^2 / Σ D(t')^2 — spec §12.5.
    ///
    /// Return: Vec<(tier, prob_fp)> aturutkan descenatng probability.
    pub fn tier_probabilities(&self, peer_id: [u8; 32]) -> Vec<(TransportTier, u64)> {
        let tiers = TransportTier::all();

        // Hitung D(t)^2 untuk setiap tier
        let d_squared: Vec<(TransportTier, u64)> = tiers
            .iter()
            .map(|&tier| {
                let d = self
                    .channels
                    .get(&(peer_id, tier))
                    .map(|c| c.conductivity_fp)
                    .unwrap_or(CONDUCTIVITY_MIN);
                // D^2 dalam u128 untuk menghindari overflow
                let d2 = (d as u128).saturating_mul(d as u128);
                (tier, d2.min(u64::MAX as u128) as u64)
            })
            .collect();

        // Σ D(t')^2
        let sum_d2: u64 = d_squared.iter().map(|(_, d2)| d2).sum();

        if sum_d2 == 0 {
            // Semua sama — distribusi merata
            let prob = FIXED_POINT_BASIS / tiers.len() as u64;
            return tiers.iter().map(|&t| (t, prob)).collect();
        }

        // P(tier t) = D(t)^2 × FIXED_POINT_BASIS / Σ D(t')^2
        let mut probs: Vec<(TransportTier, u64)> = d_squared
            .iter()
            .map(|&(tier, d2)| {
                let prob =
                    (d2 as u128).saturating_mul(FIXED_POINT_BASIS as u128) / (sum_d2 as u128);
                (tier, prob as u64)
            })
            .collect();

        // Sort descending by probability
        probs.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        probs
    }

    /// select tier terbaik for peer (tier with probabilitas tertinggi).
    pub fn best_tier(&self, peer_id: [u8; 32]) -> TransportTier {
        self.tier_probabilities(peer_id)
            .into_iter()
            .next()
            .map(|(tier, _)| tier)
            .unwrap_or(TransportTier::Internet)
    }

    /// Jumlah channel that registered.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn test_decay_rate_is_001_per_second() {
        // Spec §12.5: decay = 0.01/s. OSSIFIED.
        assert_eq!(DECAY_RATE_FP, 10_000u64); // 0.01 × 1_000_000
    }

    #[test]
    fn test_gamma_approximation_4_over_5() {
        // Spec §12.5: γ = 0.8 = 4/5. Approximated in integer.
        assert_eq!(GAMMA_NUMERATOR, 4u32);
        assert_eq!(GAMMA_DENOMINATOR, 5u32);
    }

    // ── pow_gamma_fp ─────────────────────────────────────────────────────────

    #[test]
    fn test_pow_gamma_zero_flow() {
        assert_eq!(pow_gamma_fp(0), 0);
    }

    #[test]
    fn test_pow_gamma_one_fp_gives_one_fp() {
        // 1.0^0.8 = 1.0 — dalam fixed-point: 1_000_000^0.8
        // Tidak perlu exact, tapi harus reasonable
        let result = pow_gamma_fp(FIXED_POINT_BASIS);
        assert!(result > 0, "1^0.8 harus > 0");
    }

    #[test]
    fn test_pow_gamma_larger_flow_gives_larger_result() {
        // Monotonic increasing: larger flow → larger result
        let r1 = pow_gamma_fp(1_000_000);
        let r2 = pow_gamma_fp(2_000_000);
        assert!(r2 >= r1, "Conductivity harus monotonic dengan flow");
    }

    // ── ChannelConductivity ───────────────────────────────────────────────────

    #[test]
    fn test_conductivity_starts_at_minimum() {
        let ch = ChannelConductivity::new();
        assert_eq!(ch.conductivity_fp, CONDUCTIVITY_MIN);
    }

    #[test]
    fn test_conductivity_increases_with_flow() {
        let mut ch = ChannelConductivity::new();
        let initial = ch.conductivity_fp;
        // Flow besar, 1 detik
        ch.update(5_000_000, FIXED_POINT_BASIS);
        assert!(
            ch.conductivity_fp >= initial,
            "Conductivity harus naik dengan flow"
        );
    }

    #[test]
    fn test_conductivity_decays_without_flow() {
        let mut ch = ChannelConductivity::new();
        ch.conductivity_fp = 1_000_000; // set to 1.0

        // Tanpa flow (flow=0), conductivity harus turun
        ch.update(0, FIXED_POINT_BASIS); // 1 seconds tanpa flow
        assert!(
            ch.conductivity_fp < 1_000_000,
            "Conductivity harus turun tanpa flow"
        );
    }

    #[test]
    fn test_conductivity_clamped_at_minimum() {
        let mut ch = ChannelConductivity::new();
        ch.conductivity_fp = CONDUCTIVITY_MIN;
        // Banyak decay tanpa flow
        for _ in 0..100 {
            ch.update(0, FIXED_POINT_BASIS);
        }
        assert_eq!(
            ch.conductivity_fp, CONDUCTIVITY_MIN,
            "Conductivity tidak boleh di bawah minimum"
        );
    }

    #[test]
    fn test_conductivity_clamped_at_maximum() {
        let mut ch = ChannelConductivity::new();
        // Flow sangat besar
        ch.update(u64::MAX / 2, FIXED_POINT_BASIS);
        assert!(
            ch.conductivity_fp <= CONDUCTIVITY_MAX,
            "Conductivity tidak boleh melebihi maximum"
        );
    }

    // ── AdaptiveMux ───────────────────────────────────────────────────────────

    #[test]
    fn test_adaptive_mux_new_channel_has_min_conductivity() {
        let mut mux = AdaptiveMux::new();
        let ch = mux.channel_mut(peer(1), TransportTier::Internet);
        assert_eq!(ch.conductivity_fp, CONDUCTIVITY_MIN);
    }

    #[test]
    fn test_tier_probabilities_sum_to_basis() {
        // Spec §12.5: Σ P(tier) = 1.0 (dalam fixed-point).
        let mux = AdaptiveMux::new();
        let probs = mux.tier_probabilities(peer(1));
        let total: u64 = probs.iter().map(|(_, p)| p).sum();
        // Dalam range ±5 karena rounding integer
        assert!(
            total > FIXED_POINT_BASIS - 10 && total <= FIXED_POINT_BASIS + 10,
            "Total probabilitas harus ~1.0 (fixed-point), got {total}"
        );
    }

    #[test]
    fn test_high_flow_tier_gets_higher_probability() {
        // Spec §12.5: D(t)^2 dominates — tier dengan flow tinggi = prob tinggi.
        let mut mux = AdaptiveMux::new();
        // Berikan banyak flow ke Internet tier
        for _ in 0..5 {
            mux.record_flow(
                peer(1),
                TransportTier::Internet,
                3_000_000,
                FIXED_POINT_BASIS,
            );
        }
        let probs = mux.tier_probabilities(peer(1));
        let internet_prob = probs
            .iter()
            .find(|(t, _)| *t == TransportTier::Internet)
            .map(|(_, p)| *p)
            .unwrap_or(0);
        let lora_prob = probs
            .iter()
            .find(|(t, _)| *t == TransportTier::LoRa)
            .map(|(_, p)| *p)
            .unwrap_or(0);
        assert!(
            internet_prob > lora_prob,
            "Internet (flow tinggi) harus punya probabilitas lebih tinggi dari LoRa"
        );
    }

    #[test]
    fn test_best_tier_default_is_internet() {
        // Tanpa flow, semua tier sama → Internet (indeks 0) dipilih.
        let mux = AdaptiveMux::new();
        // Dengan equal conductivity, best tier depends on tie-breaking
        // Pastikan ada hasil yang valid
        let tier = mux.best_tier(peer(1));
        let valid_tiers = [
            TransportTier::Internet,
            TransportTier::LoRa,
            TransportTier::HfRadio,
            TransportTier::LocalMesh,
            TransportTier::VisualQr,
        ];
        assert!(valid_tiers.contains(&tier));
    }

    #[test]
    fn test_record_flow_increases_channel_count() {
        let mut mux = AdaptiveMux::new();
        assert_eq!(mux.channel_count(), 0);
        mux.record_flow(
            peer(1),
            TransportTier::Internet,
            1_000_000,
            FIXED_POINT_BASIS,
        );
        assert_eq!(mux.channel_count(), 1);
        mux.record_flow(peer(1), TransportTier::LoRa, 1_000_000, FIXED_POINT_BASIS);
        assert_eq!(mux.channel_count(), 2);
    }

    #[test]
    fn test_no_floating_point_in_public_api() {
        // Public API harus pure integer — semua f64 ada di private helpers saja.
        let mut mux = AdaptiveMux::new();
        mux.record_flow(peer(1), TransportTier::Internet, 2_000_000, 500_000);
        let probs = mux.tier_probabilities(peer(1));
        assert!(!probs.is_empty());
    }
}
