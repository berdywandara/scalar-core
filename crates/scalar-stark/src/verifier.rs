use crate::air::TransferCircuitPublicInput;

pub fn verify_proof(
    _proof: &[u8],
    pub_inputs: TransferCircuitPublicInput,
) -> Result<(), &'static str> {
    if pub_inputs.crypto_version != 0x01 {
        return Err("Invalid crypto version (C9 failure)");
    }
    if pub_inputs.entry_timestamp == 0 {
        return Err("Invalid entry timestamp (C10 failure)");
    }
    Ok(())
}
