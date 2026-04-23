use crate::CryptoError;

// Konstanta ukuran untuk profil ML-KEM-768
pub const PUBLIC_KEY_BYTES: usize = 1184;
pub const SECRET_KEY_BYTES: usize = 2400;
pub const CIPHERTEXT_BYTES: usize = 1088;
pub const SHARED_SECRET_BYTES: usize = 32;

pub struct KemKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

pub fn generate_keypair() -> KemKeyPair {
    unimplemented!("Menunggu stabilisasi API ml-kem");
}

pub fn encapsulate(_public_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    unimplemented!("Menunggu stabilisasi API");
}

pub fn decapsulate(_ciphertext: &[u8], _secret_key_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    unimplemented!("Menunggu stabilisasi API");
}
