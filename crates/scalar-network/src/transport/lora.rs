//! LoRa & HF Radio Transport Protocol
//! Mengimplementasikan mitigasi backdoor ISP (New Concept 2)

const LORA_MTU_BYTES: usize = 200; // Maximum Transmission Unit radio LoRa

/// Memecah SPHINCS+ Signature raksasa (29.8 KB) menjadi paket-paket kecil radio
pub fn fragment_payload_for_radio(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let end = std::cmp::min(offset + LORA_MTU_BYTES, payload.len());

        // Buat header sederhana: [Urutan Paket (4 bytes)] + [Data]
        // Di implementasi nyata, kita gunakan FEC (Forward Error Correction)
        let mut fragment = Vec::with_capacity(LORA_MTU_BYTES + 4);
        fragment.extend_from_slice(&(offset as u32).to_be_bytes());
        fragment.extend_from_slice(&payload[offset..end]);

        fragments.push(fragment);
        offset = end;
    }

    fragments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_signature_fragmentation() {
        // Simulasi SPHINCS+ Signature 29.8 KB
        let dummy_signature = vec![0u8; 29800];

        let fragments = fragment_payload_for_radio(&dummy_signature);

        // 29800 / 200 = 149 paket yang akan dikirim via gelombang radio
        assert_eq!(
            fragments.len(),
            149,
            "Bukti ZK gagal difragmentasi untuk LoRa!"
        );
        assert!(fragments[0].len() <= LORA_MTU_BYTES + 4);
    }
}
