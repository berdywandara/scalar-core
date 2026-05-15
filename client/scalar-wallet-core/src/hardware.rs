//! Model Hardware Trust (Concept 2, Hal 46)
//! Mendefthissikan postur security device soft/hard used user.

/// Spektrum trust device hard (Level 0 hingga 4)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HardwareTrustLevel {
    /// Smartphone standar user awam (vulnerable terhadap eksploitasi OS)
    Level0StandardDevice,

    /// Smartphone/OS that athardkan (Contoh: GrapheneOS, Linux Phone)
    Level1HardenedOs,

    /// private toy berexists in Hardware Wallet separate.
    /// device utama only bertindak as Watch-Only/Broadcaster.
    Level2HardwareWallet,

    /// Setup Air-Gapped pure. Transmfill via QR animasi or USB/SD Card.
    /// none kontak with network listrik or internet publik.
    Level3AirGapped,

    /// Multi-signregulatee tingkat institusional with atstribution geografis
    /// and hardware open-source (RISC-V).
    Level4InstitutionalMultiSig,
}

/// trait for separate logika cryptography from logika network
pub trait TransactionSigner {
    /// Menandahandle payload (using SPHINCS+ at implementation nyata)
    fn sign_transaction(&self, payload: &[u8]) -> Result<Vec<u8>, &'static str>;

    /// declare level security from signer this
    fn trust_level(&self) -> HardwareTrustLevel;
}

/// Contoh implementation for Level 3 (Air-Gapped QR Signer)
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
