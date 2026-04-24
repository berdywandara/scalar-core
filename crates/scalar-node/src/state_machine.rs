//! GAP A-008: Node Lifecycle State Machine
//! Transisi: BOOTSTRAPPING -> SYNCING -> ACTIVE -> PARTITIONED

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NodeState {
    Bootstrapping, // Verifikasi genesis SMT root
    Syncing,       // Request delta SMT dan rekoniliasi
    Active,        // Operasi penuh, verifikasi STARK proof dan gossip
    Partitioned,   // Internet down, antre transaksi secara lokal
}

pub struct NodeStateMachine {
    pub current_state: NodeState,
    pub is_internet_available: bool,
    pub is_smt_synced: bool,
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
                if self.is_internet_available { self.current_state = NodeState::Syncing; }
            },
            NodeState::Syncing => {
                if self.is_smt_synced { self.current_state = NodeState::Active; }
                if !self.is_internet_available { self.current_state = NodeState::Partitioned; }
            },
            NodeState::Active => {
                if !self.is_internet_available { self.current_state = NodeState::Partitioned; }
                if !self.is_smt_synced { self.current_state = NodeState::Syncing; }
            },
            NodeState::Partitioned => {
                if self.is_internet_available { self.current_state = NodeState::Syncing; }
            },
        }
    }
}
