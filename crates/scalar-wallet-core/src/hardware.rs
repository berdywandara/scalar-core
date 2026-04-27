//! Model Hardware Trust (Concept 2, Hal 46)
//! Mendefinisikan postur keamanan perangkat lunak/keras yang digunakan pengguna.

/// Spektrum Kepercayaan Perangkat Keras (Level 0 hingga 4)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HardwareTrustLevel {
    /// Smartphone standar pengguna awam (Rentan terhadap eksploitasi OS)
    Level0StandardDevice,

    /// Smartphone/OS yang dikeraskan (Contoh: GrapheneOS, Linux Phone)
    Level1HardenedOs,

    /// Kunci privat berada di Hardware Wallet terpisah.
    /// Perangkat utama hanya bertindak sebagai Watch-Only/Broadcaster.
    Level2HardwareWallet,

    /// Setup Air-Gapped murni. Transmisi via QR animasi atau USB/SD Card.
    /// Tidak ada kontak dengan jaringan listrik atau internet publik.
    Level3AirGapped,

    /// Multi-signature tingkat institusional dengan distribusi geografis
    /// dan hardware open-source (RISC-V).
    Level4InstitutionalMultiSig,
}

/// Trait untuk memisahkan logika Kriptografi dari logika Jaringan
pub trait TransactionSigner {
    /// Menandatangani payload (menggunakan SPHINCS+ di implementasi nyata)
    fn sign_transaction(&self, payload: &[u8]) -> Result<Vec<u8>, &'static str>;

    /// Mendeklarasikan level keamanan dari signer ini
    fn trust_level(&self) -> HardwareTrustLevel;
}

/// Contoh implementasi untuk Level 3 (Air-Gapped QR Signer)
pub struct AirGappedQRSigner {
    pub device_id: String,
}

impl TransactionSigner for AirGappedQRSigner {
    fn sign_transaction(&self, _payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Di dunia nyata, ini akan membaca payload dari kamera (QR Code),
        // memproses tanda tangan secara offline, lalu menampilkan QR Code balasan.
        Err("Harus diproses melalui antarmuka kamera/layar secara fisik")
    }

    fn trust_level(&self) -> HardwareTrustLevel {
        HardwareTrustLevel::Level3AirGapped
    }
}
