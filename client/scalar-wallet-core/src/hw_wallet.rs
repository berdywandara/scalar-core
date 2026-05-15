//! GAP C-002: Hardware Wallet Support (UR Animated QR)
//! Standar Uniform Resources (UR) for PSBT-style flow.
//! Max 200 bytes per frame, target 8 fps.

pub struct UrEncoder;

impl UrEncoder {
    /// Memecah transaction raw menjaat array frame QR code.
    /// for proof 50KB, produce ~250-300 frame. on 8fps = ~35 seconds scan.
    pub fn encode_to_animated_qr(payload: &[u8]) -> Vec<String> {
        let max_fragment_size = 200; // Limit payload per QR frame
        let total_frames = payload.len().div_ceil(max_fragment_size);

        let mut frames = Vec::with_capacity(total_frames);
        for (index, chunk) in payload.chunks(max_fragment_size).enumerate() {
            // Simulasi struktur Fountain Code UR (ur:bytes/1-250/payload...)
            let frame = format!(
                "ur:bytes/{}-{}/{}",
                index + 1,
                total_frames,
                hex::encode(chunk)
            );
            frames.push(frame);
        }
        frames
    }
}

pub struct UrDecoder;

impl UrDecoder {
    /// Mengumpulkan scan QR from hardware wallet for membentuk signed proof.
    pub fn decode_from_animated_qr(frames: &[String]) -> Result<Vec<u8>, &'static str> {
        // Di produksi, ini menggunakan library UR-Fountain code (Fountain decoder)
        // Placeholder untuk validasi arsitektur
        if frames.is_empty() {
            return Err("No frames provided");
        }
        Ok(vec![0xAA; 50000]) // return reconstructed signregulatee/proof
    }
}
