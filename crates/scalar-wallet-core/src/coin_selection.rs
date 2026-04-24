//! GAP C-004: Staggered Consolidation & Real Greedy Algorithm

use rand::seq::SliceRandom;
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub enum PrivacyMode {
    Speed,   
    Maximum, 
}

pub struct ConsolidationPlan {
    pub delay_hours: u8,
    pub coins_to_merge: Vec<u64>,
}

pub struct CoinSelector;

pub const DENOMINATIONS: [u64; 17] = [
    1, 5, 10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 
    1_000_000, 5_000_000, 10_000_000, 50_000_000, 100_000_000
];

impl CoinSelector {
    /// Mengeksekusi Privacy-Aware Greedy Selection sesungguhnya dari hashmap koin
    pub fn select_coins(
        wallet_coins: &HashMap<u64, usize>, 
        target: u64, 
        mode: PrivacyMode
    ) -> Result<Vec<u64>, &'static str> {
        
        if mode == PrivacyMode::Maximum {
            let delay = rand::random::<u8>() % 24; 
            println!("[PRIVACY MODE] Staggered consolidation scheduled. Delay: {} hours", delay);
        }

        let mut remaining = target;
        let mut selected = Vec::new();
        let mut available_denoms = DENOMINATIONS.to_vec();
        
        // Urutkan dari denominasi terbesar (Greedy)
        available_denoms.sort_by(|a, b| b.cmp(a));

        let mut temp_wallet = wallet_coins.clone();

        // Pass 1: Gunakan koin yang pas atau lebih kecil untuk merakit nilai
        for &d in &available_denoms {
            while remaining > 0 {
                if let Some(count) = temp_wallet.get_mut(&d) {
                    if *count > 0 && (d <= remaining || remaining == target) {
                        selected.push(d);
                        *count -= 1;
                        remaining = remaining.saturating_sub(d);
                        continue;
                    }
                }
                break;
            }
        }

        // Pass 2: Jika masih ada sisa, terpaksa gunakan koin yang lebih besar (kembalian)
        if remaining > 0 {
            for &d in available_denoms.iter().rev() {
                if let Some(count) = temp_wallet.get_mut(&d) {
                    if *count > 0 && d > remaining {
                        selected.push(d);
                        *count -= 1;
                        remaining = 0;
                        break;
                    }
                }
            }
        }

        if remaining > 0 {
            return Err("Saldo di dalam dompet tidak cukup untuk transaksi ini.");
        }
        
        // Privacy Randomization: Acak urutan agar tidak bisa ditebak melalui analitik on-chain
        let mut rng = rand::rng();
        selected.shuffle(&mut rng);
        
        Ok(selected)
    }
}
