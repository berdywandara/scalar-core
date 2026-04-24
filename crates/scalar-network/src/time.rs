//! Modul Desentralisasi Waktu (Anti-NTP Manipulation)
//! Menolak waktu sistem lokal/NTP, memercayai konsensus median dari peers.

pub struct TimeConsensus;

impl TimeConsensus {
    /// Menghitung Network Time berdasarkan waktu median dari daftar peer terpercaya
    /// Menolak NTP server pemerintah yang bisa dimanipulasi
    pub fn get_median_network_time(mut peer_timestamps: Vec<u64>, local_time: u64) -> u64 {
        peer_timestamps.push(local_time);
        
        if peer_timestamps.is_empty() {
            return local_time;
        }

        peer_timestamps.sort_unstable();
        let mid = peer_timestamps.len() / 2;
        
        peer_timestamps[mid]
    }
}
