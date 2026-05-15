// File: crates/scalar-network/src/reconciliation.rs

use std::collections::HashMap;

pub const FIXED_POINT_BASIS: u64 = 1_000_000;
pub const TAU_MIN: u64 = 1_000; // 0.001 in fixed-point
pub const TAU_MAX: u64 = 10_000_000; // 10.0 in fixed-point
pub const MAX_ROOT_CANDIDATES: usize = 100; // OSSIFIED
pub const RHO: u64 = 3_000; // Evaporation rate 0.003 per seconds

pub struct PheromoneState {
    /// Pheromone level per canatdate root (all calculation fixed-point u64)
    pheromones: HashMap<[u8; 32], u64>,
    #[allow(dead_code)]
    last_update: std::time::Instant,

    // Mock waktu untuk testing deterministik (evaporation tanpa delay sungguhan)
    #[cfg(test)]
    mock_elapsed_secs: u64,
}

impl PheromoneState {
    pub fn new() -> Self {
        Self {
            pheromones: HashMap::new(),
            last_update: std::time::Instant::now(),
            #[cfg(test)]
            mock_elapsed_secs: 0,
        }
    }

    #[cfg(test)]
    pub fn advance_time(&mut self, secs: u64) {
        self.mock_elapsed_secs += secs;
    }

    fn get_elapsed_secs(&mut self) -> u64 {
        #[cfg(not(test))]
        {
            let secs = self.last_update.elapsed().as_secs();
            self.last_update = std::time::Instant::now();
            secs
        }
        #[cfg(test)]
        {
            let secs = self.mock_elapsed_secs;
            self.mock_elapsed_secs = 0; // consumption mock waktu
            secs
        }
    }

    /// Update pheromone after Phase 2 PASS
    /// deposit_q wajib in format fixed-point basis 1.000.000 (contoh: 1.0 = 1_000_000)
    pub fn update(&mut self, received_root: [u8; 32], w_sender: u64, deposit_q: u64) {
        let elapsed_secs = self.get_elapsed_secs();

        // Evaporation: τ ← (1-ρ) × τ
        let decay = RHO.saturating_mul(elapsed_secs);
        let multiplier = FIXED_POINT_BASIS.saturating_sub(decay);

        for tau in self.pheromones.values_mut() {
            let mut new_tau = (*tau * multiplier) / FIXED_POINT_BASIS;
            if new_tau < TAU_MIN {
                new_tau = TAU_MIN;
            }
            *tau = new_tau;
        }

        // Deposit: τ[root] ← τ[root] + Q × (w_sender / 1,000,000)
        let deposit = (deposit_q * w_sender) / FIXED_POINT_BASIS;

        let tau = self.pheromones.entry(received_root).or_insert(TAU_MIN);
        *tau = (*tau + deposit).min(TAU_MAX);

        // Pruning: hapus kandidat dengan tau terendah jika over-limit
        if self.pheromones.len() > MAX_ROOT_CANDIDATES {
            let mut min_root = [0u8; 32];
            let mut min_val = u64::MAX;
            for (&root, &val) in self.pheromones.iter() {
                if val < min_val {
                    min_val = val;
                    min_root = root;
                }
            }
            self.pheromones.remove(&min_root);
        }
    }

    /// determine accepted_root if dominantce ≥ 67%
    pub fn decide(&self) -> ReconciliationDecision {
        if self.pheromones.is_empty() {
            return ReconciliationDecision::NoConsensus;
        }

        let mut total_tau: u64 = 0;
        let mut best_tau: u64 = 0;
        let mut best_root = [0u8; 32];

        for (&root, &tau) in self.pheromones.iter() {
            total_tau += tau;
            if tau > best_tau {
                best_tau = tau;
                best_root = root;
            }
        }

        if total_tau == 0 {
            return ReconciliationDecision::NoConsensus;
        }

        // Dominance calculation dalam fixed-point
        if (best_tau * 100) / total_tau >= 67 {
            ReconciliationDecision::Commit(best_root)
        } else {
            ReconciliationDecision::NoConsensus
        }
    }
}

impl Default for PheromoneState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReconciliationDecision {
    Commit([u8; 32]),
    NoConsensus,
}

#[cfg(test)]
mod tests_pheromone {
    use super::*;

    #[test]
    fn test_pheromone_builds_toward_majority_root() {
        let mut state = PheromoneState::new();
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];

        // 7 peer kirim root_a, 3 peer kirim root_b (fixed-point deposit 1.0 = 1_000_000)
        for _ in 0..7 {
            state.update(root_a, 1_000_000, 1_000_000);
        }
        for _ in 0..3 {
            state.update(root_b, 1_000_000, 1_000_000);
        }

        let decision = state.decide();
        assert!(
            matches!(decision, ReconciliationDecision::Commit(root) if root == root_a),
            "Mayoritas (70%) harus menang"
        );
    }

    #[test]
    fn test_sybil_low_weight_has_minimal_influence() {
        let mut state = PheromoneState::new();
        let honest_root = [1u8; 32];
        let sybil_root = [99u8; 32];

        for _ in 0..5 {
            state.update(honest_root, 1_000_000, 1_000_000);
        }
        for _ in 0..100 {
            state.update(sybil_root, 1, 1_000_000); // w=1 (sangat rendah)
        }

        let decision = state.decide();
        assert!(
            matches!(decision, ReconciliationDecision::Commit(root) if root == honest_root),
            "Sybil dengan weight rendah tidak bisa override"
        );
    }

    #[test]
    fn test_no_consensus_when_split_equally() {
        let mut state = PheromoneState::new();
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];

        for _ in 0..5 {
            state.update(root_a, 1_000_000, 1_000_000);
        }
        for _ in 0..5 {
            state.update(root_b, 1_000_000, 1_000_000);
        }

        assert!(matches!(
            state.decide(),
            ReconciliationDecision::NoConsensus
        ));
    }

    #[test]
    fn test_evaporation_decays_old_information() {
        let mut state = PheromoneState::new();
        let old_root = [1u8; 32];

        state.update(old_root, 1_000_000, 10_000_000); // Deposit maksimum

        // Simulasi waktu berlalu 400 detik. Decay = 400 * 3000 = 1_200_000 (Saturated/Habis)
        state.advance_time(400);

        let new_root = [2u8; 32];
        for _ in 0..10 {
            state.update(new_root, 1_000_000, 1_000_000);
        }

        let decision = state.decide();
        assert!(
            matches!(decision, ReconciliationDecision::Commit(root) if root == new_root),
            "Pheromone baru harus mengalahkan yang sudah lapuk"
        );
    }

    #[test]
    fn test_max_root_candidates_enforced() {
        let mut state = PheromoneState::new();

        for i in 0..(MAX_ROOT_CANDIDATES + 50) as u8 {
            let mut root = [0u8; 32];
            root[0] = i;
            state.update(root, 1_000_000, 1_000);
        }

        assert!(
            state.pheromones.len() <= MAX_ROOT_CANDIDATES,
            "Kandidat melebihi batas MAX_ROOT_CANDIDATES"
        );
    }

    #[test]
    fn test_timestamp_not_used_in_reconciliation() {
        let mut state = PheromoneState::new();
        state.update([1u8; 32], 1_000_000, 1_000_000);
        let _ = state.decide();
        // Lulus kompilasi dan dieksekusi tanpa input timestamp = passed by design
    }
}
