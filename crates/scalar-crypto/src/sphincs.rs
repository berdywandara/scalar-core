use crate::CryptoError;
use pqcrypto_sphincsplus::sphincsshake256128ssimple::*;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

pub const PUBLIC_KEY_BYTES: usize = public_key_bytes();
pub const SECRET_KEY_BYTES: usize = secret_key_bytes();
pub const SIGNATURE_BYTES: usize = signature_bytes();

pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

pub fn generate_keypair() -> KeyPair {
    let (pk, sk) = keypair();
    KeyPair {
        public: pk,
        secret: sk,
    }
}

pub fn sign(message: &[u8], secret_key: &SecretKey) -> DetachedSignature {
    detached_sign(message, secret_key)
}

pub fn verify(
    signature: &DetachedSignature,
    message: &[u8],
    public_key: &PublicKey,
) -> Result<(), CryptoError> {
    verify_detached_signature(signature, message, public_key)
        .map_err(|_| CryptoError::InvalidSignature)
}
