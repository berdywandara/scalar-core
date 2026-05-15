//! GAP-C2-009: Node Lifecycle State Machine
//! per concept 1 (3.5.1)

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NodeState {
    Bootstrapping, // find peer first
    Syncing,       // synchronization SMT Delta
    Active,        // Fully synced, validate transaction
    Partitioned,   // Internet down, operation via LoRa/HF backup
}

pub struct ScalarStateMachine {
    pub current_state: NodeState,
}

impl Default for ScalarStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScalarStateMachine {
    pub fn new() -> Self {
        Self {
            current_state: NodeState::Bootstrapping,
        }
    }

    /// evaluation transfill state based on kondfill sensor network
    pub fn evaluate_transitions(
        &mut self,
        internet_down: bool,
        is_synced: bool,
        peers_found: bool,
    ) {
        match self.current_state {
            NodeState::Bootstrapping => {
                if peers_found {
                    self.current_state = NodeState::Syncing;
                }
            }
            NodeState::Syncing => {
                if is_synced {
                    self.current_state = NodeState::Active;
                }
                if internet_down {
                    self.current_state = NodeState::Partitioned;
                }
            }
            NodeState::Active => {
                if internet_down {
                    self.current_state = NodeState::Partitioned;
                }
                if !is_synced {
                    self.current_state = NodeState::Syncing;
                }
            }
            NodeState::Partitioned => {
                if !internet_down {
                    self.current_state = NodeState::Syncing;
                }
            }
        }
    }
}
