#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PoolState {
    PoolStateIdle = 0,
    PoolStateQueue = 1,
    PoolStateAcceptingEntries = 2,
    PoolStateSigning = 3,
    PoolStateError = 4,
}

impl PoolState {
    pub fn value(&self) -> i32 {
        *self as i32
    }

    pub fn from_value(value: i32) -> Self {
        match value {
            0 => PoolState::PoolStateIdle,
            1 => PoolState::PoolStateQueue,
            2 => PoolState::PoolStateAcceptingEntries,
            3 => PoolState::PoolStateSigning,
            4 => PoolState::PoolStateError,
            _ => PoolState::PoolStateIdle, // Default case
        }
    }

    pub fn pool_state_min() -> Self {
        PoolState::PoolStateIdle
    }

    pub fn pool_state_max() -> Self {
        PoolState::PoolStateError
    }
}
