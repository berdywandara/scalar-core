pub mod internet;
pub mod lora;
pub mod mux;
pub mod optimization;
pub mod radio;

pub enum CommunicationLayer {
    Internet,
    LoRaMesh,
    HFRadio,
    Adjacent, // Bluetooth/WiFi Direct
}
