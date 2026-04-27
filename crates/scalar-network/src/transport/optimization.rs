//! Modul Optimasi Transmisi & Regulasi Spektrum Radio

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy)]
pub enum LoraRegion {
    EU868, // Terkena regulasi Duty Cycle 1%
    US915, // Tanpa batas Duty Cycle
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum OptimizedPayload {
    FullCompressed(Vec<u8>), // Internet atau US915 LoRa
    ReferenceOnly([u8; 32]), // EU868 LoRa (Hanya SMT Root / Nullifier)
}

impl OptimizedPayload {
    /// Mengatur pengiriman berdasarkan jenis radio dan regulasi regional
    pub fn prepare_lora_transmission(raw_proof: &[u8], region: LoraRegion) -> Self {
        match region {
            LoraRegion::EU868 => {
                // Di Eropa, tidak boleh kirim file 50KB via LoRa (Melanggar Duty Cycle)
                let mut hash = [0u8; 32];
                let len = std::cmp::min(raw_proof.len(), 32);
                hash[..len].copy_from_slice(&raw_proof[..len]);
                Self::ReferenceOnly(hash)
            }
            LoraRegion::US915 => {
                // Di region bebas, kirim full proof dengan kompresi biner (Zlib simulasi)
                Self::FullCompressed(raw_proof.to_vec())
            }
        }
    }
}
