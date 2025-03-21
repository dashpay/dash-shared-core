#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[ferment_macro::export]
pub enum PoolState {
    Idle = 0,
    Queue = 1,
    AcceptingEntries = 2,
    Signing = 3,
    Error = 4,
}

#[ferment_macro::export]
impl PoolState {
    pub fn value(&self) -> i32 {
        *self as i32
    }

    pub fn from_value(value: i32) -> PoolState {
        match value {
            0 => PoolState::Idle,
            1 => PoolState::Queue,
            2 => PoolState::AcceptingEntries,
            3 => PoolState::Signing,
            4 => PoolState::Error,
            _ => PoolState::Idle, // Default case
        }
    }

    pub fn pool_state_min() -> PoolState {
        PoolState::Idle
    }

    pub fn pool_state_max() -> PoolState {
        PoolState::Error
    }
}
