/// Pesan sinkronisasi delta untuk efisiensi bandwidth (tidak perlu broadcast full state)
pub struct DeltaSyncMessage {
    pub start_root: [u8; 32],
    pub end_root: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
}
