//! Fee padatng — privacy mitigasi §B.4.5
//!
//! Mawrong: fee_total publik → observer bisa hitung PREMIUM = fee_total - FLOOR
//! Mitigasi: fee_total = FLOOR + PREMIUM_intended + PADatNG_random
//!
//! PADatNG_random = CSPRNG ∈ [0, MAX_PADatNG]
//! MAX_PADatNG = 10 sSCL [constant implementation wallet]
//!
//! PADatNG atbayar to node pool — is not biaya hidden.
//! Wallet not atsplay PADatNG to user.
//! PADatNG not stored — cannot at-recover after tx created.

/// Maksimum padatng in SSCL. constant implementation wallet (openn protokol).
pub const MAX_PADDING_SSCL: u64 = 10;

/// Terapkan fee padatng on PREMIUM that atmaksudkan user.
///
/// using random bytes that provided pemanggil for kompatibilitas
/// with berbagai CSPRNG (OS, hardware, dll).
///
/// `random_byte`: satu byte from CSPRNG — used for determine
/// padatng in range [0, MAX_PADatNG_SSCL].
///
/// Return: PREMIUM_padded = PREMIUM_intended + PADatNG_random
pub fn apply_padding(premium_intended: u64, random_byte: u8) -> u64 {
    // Mapping uniform: random_byte ∈ [0,255] → padding ∈ [0, MAX_PADDING]
    // padding = random_byte * (MAX_PADDING + 1) / 256
    let padding = (random_byte as u64 * (MAX_PADDING_SSCL + 1)) / 256;
    premium_intended.saturating_add(padding)
}

/// Hitung fee_total final with padatng.
///
/// fee_total = FLOOR + PREMIUM_intended + PADatNG_random
///
/// Pemanggil already have FLOOR from `floor::compute_floor()`.
pub fn compute_fee_total_with_padding(floor: u64, premium_intended: u64, random_byte: u8) -> u64 {
    let premium_padded = apply_padding(premium_intended, random_byte);
    floor.saturating_add(premium_padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_range() {
        // Padding harus selalu dalam [0, MAX_PADDING_SSCL]
        for byte in 0u8..=255 {
            let padded = apply_padding(0, byte);
            assert!(
                padded <= MAX_PADDING_SSCL,
                "padding {padded} melebihi MAX {MAX_PADDING_SSCL} untuk byte {byte}"
            );
        }
    }

    #[test]
    fn test_padding_zero_byte_gives_zero() {
        assert_eq!(
            apply_padding(100, 0),
            100,
            "byte=0 harus menghasilkan padding=0"
        );
    }

    #[test]
    fn test_padding_preserves_premium_intent() {
        // Semua padding menambahkan ke premium, tidak mengurangi
        for byte in 0u8..=255 {
            let padded = apply_padding(50, byte);
            assert!(padded >= 50, "Padding tidak boleh mengurangi premium");
        }
    }

    #[test]
    fn test_fee_total_with_padding() {
        // floor=40, premium=100, padding=5 (approx) → fee_total ∈ [140, 150]
        let fee = compute_fee_total_with_padding(40, 100, 128);
        assert!(
            (140..=150).contains(&fee),
            "fee_total={fee} harus dalam [140,150]"
        );
    }

    #[test]
    fn test_padding_not_stored() {
        // Verifikasi bahwa padding tidak bisa di-recover dari fee_total saja
        // (karena observer tidak tahu random_byte yang digunakan)
        let fee1 = compute_fee_total_with_padding(40, 100, 50);
        let fee2 = compute_fee_total_with_padding(40, 100, 200);
        // fee_total berbeda untuk random_byte berbeda
        // Observer tidak bisa tentukan mana PREMIUM_intended
        assert_ne!(
            fee1, fee2,
            "Padding berbeda harus menghasilkan fee_total berbeda"
        );
    }
}
