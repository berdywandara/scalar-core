use crate::StarkError;
use winterfell::ProofOptions;

pub struct ScalarProver {
    #[allow(dead_code)]
    options: ProofOptions,
}

impl ScalarProver {
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(
                32, // number of queries
                8,  // blowup factor
                0,  // grinding factor
                winterfell::FieldExtension::None,
                8,  // FRI folding factor
                31, // FRI max remainder length
            ),
        }
    }
}

pub fn generate_proof() -> Result<Vec<u8>, StarkError> {
    Ok(vec![])
}
