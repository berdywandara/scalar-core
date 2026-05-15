//! module decentralization Waktu (Anti-NTP Manipulation)
//! reject waktu sistem lokal/NTP, memercayai konsensus meatan from peers.

pub struct TimeConsensus;

impl TimeConsensus {
    /// compute Network Time based on waktu meatan from daftar peer terpercaya
    /// reject NTP server pemerintah that can atmanipulasi
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
