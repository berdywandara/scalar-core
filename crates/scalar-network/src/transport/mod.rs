pub mod lora;

pub enum CommunicationLayer {
    Internet, // Primary Transport
    LoRaMesh, // Backup Transport
    HFRadio,  // Emergency Transport
}
