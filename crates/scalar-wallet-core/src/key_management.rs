use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Invalid mnemonic phrase")]
    InvalidMnemonic,
    #[error("Incompatible Bitcoin mnemonic detected")]
    BitcoinMnemonicDetected,
}

pub const SCALAR_DOMAIN_SEPARATOR: &str = "scalar_v1";
pub const SCALAR_PREFIX_WORD: &str = "scalar";

pub struct SpendKey(pub Vec<u8>);
pub struct ViewKey(pub Vec<u8>);
pub struct NodeKey(pub Vec<u8>);
pub struct DuressKey(pub Vec<u8>);

pub fn generate_mnemonic() -> String {
    // 32 bytes = 256 bits entropi (dibutuhkan untuk 24 kata BIP-39)
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    // Hasilkan mnemonic dari entropi aman kita
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .expect("Entropy generation failed")
        .to_string();

    // Paksa kata pertama menjadi 'scalar' untuk mencegah cross-import
    let mut words: Vec<&str> = mnemonic.split_whitespace().collect();
    words[0] = SCALAR_PREFIX_WORD;
    words.join(" ")
}

pub fn derive_seed(mnemonic_phrase: &str, passphrase: &str) -> Result<Vec<u8>, KeyError> {
    let words: Vec<&str> = mnemonic_phrase.split_whitespace().collect();

    if words.is_empty() || words[0] != SCALAR_PREFIX_WORD {
        return Err(KeyError::BitcoinMnemonicDetected);
    }

    let salt = format!("{}{}", SCALAR_DOMAIN_SEPARATOR, passphrase);
    let mut mac =
        Hmac::<Sha512>::new_from_slice(salt.as_bytes()).expect("HMAC can take key of any size");

    mac.update(mnemonic_phrase.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation_has_scalar_prefix() {
        let phrase = generate_mnemonic();
        assert!(
            phrase.starts_with(SCALAR_PREFIX_WORD),
            "Kata pertama harus 'scalar'"
        );
    }

    #[test]
    fn test_bitcoin_mnemonic_rejection() {
        let btc_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = derive_seed(btc_phrase, "");
        assert!(
            matches!(result, Err(KeyError::BitcoinMnemonicDetected)),
            "Harus menolak mnemonic BTC"
        );
    }
}
