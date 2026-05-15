//! GAP A-008: Node Lifecycle State Machine
//! Transfill: BOOTSTRAPPING -> SYNCING -> ACTIVE -> PARTITIONED

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NodeState {
    Bootstrapping, // verification genesis SMT root
    Syncing,       // Request delta SMT and rekoniliasi
    Active,        // operation full, verification STARK proof and gossip
    Partitioned,   // Internet down, antre transaction secara lokal
}

pub struct NodeStateMachine {
    pub current_state: NodeState,
    pub is_internet_available: bool,
    pub is_smt_synced: bool,
}

impl Default for NodeStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeStateMachine {
    pub fn new() -> Self {
        Self {
            current_state: NodeState::Bootstrapping,
            is_internet_available: true,
            is_smt_synced: false,
        }
    }

    pub fn update_network_sensor(&mut self, internet_status: bool, sync_status: bool) {
        self.is_internet_available = internet_status;
        self.is_smt_synced = sync_status;
        self.evaluate_transitions();
    }

    fn evaluate_transitions(&mut self) {
        match self.current_state {
            NodeState::Bootstrapping => {
                if self.is_internet_available {
                    self.current_state = NodeState::Syncing;
                }
            }
            NodeState::Syncing => {
                if self.is_smt_synced {
                    self.current_state = NodeState::Active;
                }
                if !self.is_internet_available {
                    self.current_state = NodeState::Partitioned;
                }
            }
            NodeState::Active => {
                if !self.is_internet_available {
                    self.current_state = NodeState::Partitioned;
                }
                if !self.is_smt_synced {
                    self.current_state = NodeState::Syncing;
                }
            }
            NodeState::Partitioned => {
                if self.is_internet_available {
                    self.current_state = NodeState::Syncing;
                }
            }
        }
    }
}
