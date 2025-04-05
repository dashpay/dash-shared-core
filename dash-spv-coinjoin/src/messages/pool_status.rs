#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[ferment_macro::export]
pub enum PoolStatus {
    Warmup = 0x0001,
    Idle = 0x0002,
    Connecting = 0x0003,
    Connected = 0x0004,
    Mixing = 0x0005,
    Complete = 0x0106,
    Finished = 0x1007,
    Timeout = 0x0107,
    ConnectionTimeout = 0x0108,
    // Errors
    ErrNoInputs = 0x2100,
    ErrMasternodeNotFound = 0x2101,
    ErrNoMasternodesDetected = 0x2102,
    ErrWalletLocked = 0x3103,
    ErrNotEnoughFunds = 0x3104,
    // Warnings
    WarnNoMixingQueues = 0x4200,
    WarnNoCompatibleMasternode = 0x4201
}

impl PoolStatus {
    const STOP: i32 = 0x1000;
    const ERROR: i32 = 0x2000;
    const WARNING: i32 = 0x4000;
    const COMPLETED: i32 = 0x0100;
}
#[ferment_macro::export]
impl PoolStatus {
    pub fn value(&self) -> i32 {
        *self as i32
    }

    pub fn from_index(index: i32) -> PoolStatus {
        match index {
            0x0001 => PoolStatus::Warmup,
            0x0002 => PoolStatus::Idle,
            0x0003 => PoolStatus::Connecting,
            0x0004 => PoolStatus::Connected,
            0x0005 => PoolStatus::Mixing,
            0x0106 => PoolStatus::Complete,
            0x1007 => PoolStatus::Finished,
            0x0107 => PoolStatus::Timeout,
            0x0108 => PoolStatus::ConnectionTimeout,
            0x2100 => PoolStatus::ErrNoInputs,
            0x2101 => PoolStatus::ErrMasternodeNotFound,
            0x2102 => PoolStatus::ErrNoMasternodesDetected,
            0x3103 => PoolStatus::ErrWalletLocked,
            0x3104 => PoolStatus::ErrNotEnoughFunds,
            0x4200 => PoolStatus::WarnNoMixingQueues,
            0x4201 => PoolStatus::WarnNoCompatibleMasternode,
            _ => panic!("Invalid index {}", index),
        }
    }
    pub fn is_error(&self) -> bool {
        (self.value() & Self::ERROR) != 0
    }

    pub fn is_warning(&self) -> bool {
        (self.value() & Self::WARNING) != 0
    }
    pub fn is_err_not_enough_funds(&self) -> bool {
        matches!(self, Self::ErrNotEnoughFunds)
    }

    pub fn should_stop(&self) -> bool {
        (self.value() & Self::STOP) != 0 ||
            self == &PoolStatus::ErrNoInputs ||
            self == &PoolStatus::ErrNotEnoughFunds
    }

    pub fn session_completed(&self) -> bool {
        (self.value() & Self::COMPLETED) != 0
    }

}