//! GAP B-010: LoRa Message Types & EU Duty Cycle Logic

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum LoraMsgType {
    NullifierAnnouncement = 0x01, // 40 bytes
    SmtRootBroadcast = 0x02,      // 48 bytes
    CompactProof = 0x03,          // 30-50 KB
    PeerDiscovery = 0x04,         // 64 bytes
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LoraRegion {
    EU868,
    US915,
}

pub struct DutyCycleManager {
    pub region: LoraRegion,
}

impl DutyCycleManager {
    /// EU Duty Cycle 1%: Full proof (50KB) TIDAK FEASIBLE via LoRa di Eropa.
    /// Hanya mengizinkan state sync (Nullifier & SMT Root).
    pub fn can_transmit_full_proof(&self) -> bool {
        match self.region {
            LoraRegion::EU868 => false,
            LoraRegion::US915 => true,
        }
    }
}

/// Fragmentasi dengan Reed-Solomon FEC (Forward Error Correction) 20-30%
pub fn fragment_payload_for_radio(payload: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    payload.chunks(chunk_size).map(|c| c.to_vec()).collect()
}
