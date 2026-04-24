//! Implementasi Komunikasi Radio (LoRa & HF)
//! Dirancang untuk ketahanan infrastruktur di luar internet.

// LoRa MTU (Maximum Transmission Unit) standar dibatasi agar tidak meluap
pub const LORA_MTU: usize = 200; 

#[derive(Debug, PartialEq)]
pub struct RadioPacket {
    pub packet_id: u32,
    pub total_packets: u32,
    pub payload_chunk: Vec<u8>,
}

impl RadioPacket {
    /// Memecah Proof STARK raksasa (50-100KB) menjadi serpihan kecil untuk frekuensi radio
    pub fn fragment_proof(proof_data: &[u8]) -> Vec<RadioPacket> {
        let chunks: Vec<&[u8]> = proof_data.chunks(LORA_MTU).collect();
        let total = chunks.len() as u32;
        
        chunks.into_iter().enumerate().map(|(i, chunk)| {
            RadioPacket {
                packet_id: i as u32,
                total_packets: total,
                payload_chunk: chunk.to_vec(),
            }
        }).collect()
    }
}
