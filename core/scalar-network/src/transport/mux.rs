//! GAP B-007: Transport Mux & Adaptive Selection

#[derive(Debug, PartialEq)]
pub enum Priority {
    Normal,
    Emergency,
}

#[derive(Debug, PartialEq)]
pub enum TransportType {
    Internet,
    Tor,
    LoRa,
    HfRadio,
    Local,
}

pub struct TransportMux;

impl TransportMux {
    /// Decision Tree: Otomatis memilih transport berdasarkan prioritas & kondisi sensor
    pub fn select_and_send(
        _payload: &[u8],
        priority: Priority,
        internet_ok: bool,
        censored: bool,
    ) -> Vec<TransportType> {
        match priority {
            Priority::Emergency => {
                // Semua transport paralel (Maximum redundancy)
                vec![
                    TransportType::Internet,
                    TransportType::Tor,
                    TransportType::LoRa,
                    TransportType::HfRadio,
                ]
            }
            Priority::Normal => {
                if internet_ok && !censored {
                    vec![TransportType::Internet, TransportType::Tor]
                } else if internet_ok && censored {
                    // Fallback anti-censor (Tor bridge / LoRa)
                    vec![TransportType::Tor, TransportType::LoRa]
                } else {
                    // No internet (LoRa -> HF -> Local)
                    vec![
                        TransportType::LoRa,
                        TransportType::HfRadio,
                        TransportType::Local,
                    ]
                }
            }
        }
    }
}
