//! Foreign Function Interface (FFI) untuk Scalar Network
//! Jembatan komunikasi antara UI Mobile (Flutter) dan Core Node (Rust).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Fungsi yang akan dipanggil oleh Flutter untuk memverifikasi kata pertama ("scalar")
/// Sesuai dengan protokol pencegahan cross-import yang kita buat di UI sebelumnya.
///
/// # Safety
/// Caller (Flutter) HARUS memastikan:
/// - `phrase_ptr` bukan NULL
/// - `phrase_ptr` menunjuk ke string C yang valid dan null-terminated
/// - String tetap valid selama fungsi ini berjalan
#[no_mangle]
pub unsafe extern "C" fn scalar_verify_domain_separator(
    phrase_ptr: *const c_char,
) -> bool {
    // Pastikan pointer tidak kosong (null)
    if phrase_ptr.is_null() {
        return false;
    }

    // Konversi string C (dari Flutter) menjadi string Rust
    let c_str = CStr::from_ptr(phrase_ptr); // tidak perlu unsafe lagi
    let phrase_str = match c_str.to_str() {
        Ok(s) => s.trim().to_lowercase(),
        Err(_) => return false,
    };

    // Ambil kata pertama
    let first_word = phrase_str.split_whitespace().next().unwrap_or("");

    // Verifikasi matematis domain separator Scalar Network
    first_word == "scalar"
}

/// Fungsi simulasi pembuatan alamat dompet dari Rust
/// Tidak menerima raw pointer — tidak perlu unsafe
#[no_mangle]
pub extern "C" fn scalar_generate_address() -> *mut c_char {
    // Di dunia nyata, ini akan memanggil SPHINCS+ dari scalar-crypto
    let address = "scl1_postquantum_address_stub_9x8c7";

    // Konversi string Rust menjadi string C agar bisa dibaca Flutter
    let c_string = CString::new(address).unwrap();
    c_string.into_raw()
}

/// Fungsi untuk membebaskan memori string yang dialokasikan di Rust.
/// Wajib dipanggil oleh Flutter setelah selesai membaca string
/// untuk mencegah Memory Leak!
///
/// # Safety
/// Caller (Flutter) HARUS memastikan:
/// - `s` adalah pointer yang sebelumnya dikembalikan oleh fungsi Scalar FFI
/// - `s` belum pernah di-free sebelumnya (tidak double-free)
/// - Setelah fungsi ini dipanggil, `s` tidak boleh digunakan lagi
#[no_mangle]
pub unsafe extern "C" fn scalar_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // Drop CString → otomatis bebaskan memori
    // tidak perlu unsafe block lagi karena fungsi sudah unsafe
    let _ = CString::from_raw(s);
}