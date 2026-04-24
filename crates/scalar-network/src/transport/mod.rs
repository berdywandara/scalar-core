pub mod lora;
pub mod optimization;
pub mod radio;
pub mod internet;
pub mod mux;

pub enum CommunicationLayer {
    Internet,
    LoRaMesh,
    HFRadio,
    Adjacent, // Bluetooth/WiFi Direct
}
