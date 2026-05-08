//! Konfigurasi Jaringan Statis (Concept 2, Hal 1)
//! Menghilangkan ketergantungan pada DNS untuk mencegah penyensoran.

pub const BOOTSTRAP_NODES: &[&str] = &[
    // Alamat IP Statis dari Genesis Peers (Contoh IP publik fiktif)
    "/ip4/157.245.120.30/tcp/4001/p2p/12D3KooWSm9n9Y8c7b6a5d4e3f2g1h",
    "/ip4/167.172.5.45/tcp/4001/p2p/12D3KooWJp8m7l6k5j4i3h2g1f0e9d8c7b",
];
