//! Fee padding — privacy mitigasi §B.4.5
//!
//! Masalah: fee_total publik → observer bisa hitung PREMIUM = fee_total - FLOOR
//! Mitigasi: fee_total = FLOOR + PREMIUM_intended + PADDING_random
//!
//! PADDING_random = CSPRNG ∈ [0, MAX_PADDING]
//! MAX_PADDING = 10 sSCL [konstanta implementasi wallet]
//!
//! PADDING dibayar ke node pool — bukan biaya tersembunyi.
//! Wallet TIDAK menampilkan PADDING ke user.
//! PADDING tidak disimpan — tidak bisa di-recover setelah tx dibuat.

/// Maksimum padding dalam sSCL. Konstanta implementasi wallet (bukan protokol).
pub const MAX_PADDING_SSCL: u64 = 10;

/// Terapkan fee padding pada PREMIUM yang dimaksudkan user.
///
/// Menggunakan random bytes yang disediakan pemanggil untuk kompatibilitas
/// dengan berbagai CSPRNG (OS, hardware, dll).
///
/// `random_byte`: satu byte dari CSPRNG — digunakan untuk menentukan
/// padding dalam range [0, MAX_PADDING_SSCL].
///
/// Return: PREMIUM_padded = PREMIUM_intended + PADDING_random
pub fn apply_padding(premium_intended: u64, random_byte: u8) -> u64 {
    // Mapping uniform: random_byte ∈ [0,255] → padding ∈ [0, MAX_PADDING]
    // padding = random_byte * (MAX_PADDING + 1) / 256
    let padding = (random_byte as u64 * (MAX_PADDING_SSCL + 1)) / 256;
    premium_intended.saturating_add(padding)
}

/// Hitung fee_total final dengan padding.
///
/// fee_total = FLOOR + PREMIUM_intended + PADDING_random
///
/// Pemanggil sudah memiliki FLOOR dari `floor::compute_floor()`.
pub fn compute_fee_total_with_padding(
    floor:             u64,
    premium_intended:  u64,
    random_byte:       u8,
) -> u64 {
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
        assert_eq!(apply_padding(100, 0), 100, "byte=0 harus menghasilkan padding=0");
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
        assert!(fee >= 140 && fee <= 150, "fee_total={fee} harus dalam [140,150]");
    }

    #[test]
    fn test_padding_not_stored() {
        // Verifikasi bahwa padding tidak bisa di-recover dari fee_total saja
        // (karena observer tidak tahu random_byte yang digunakan)
        let fee1 = compute_fee_total_with_padding(40, 100, 50);
        let fee2 = compute_fee_total_with_padding(40, 100, 200);
        // fee_total berbeda untuk random_byte berbeda
        // Observer tidak bisa tentukan mana PREMIUM_intended
        assert_ne!(fee1, fee2, "Padding berbeda harus menghasilkan fee_total berbeda");
    }
}
