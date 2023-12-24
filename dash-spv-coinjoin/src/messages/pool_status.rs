#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
    WarnNoMixingQueues = 0x2200,
    WarnNoCompatibleMasternode = 0x2201,
}

impl PoolStatus {
    const STOP: i32 = 0x1000;
    const ERROR: i32 = 0x2000;
    const WARNING: i32 = 0x4000;
    const COMPLETED: i32 = 0x0100;

    pub fn value(&self) -> i32 {
        *self as i32
    }

    pub fn is_error(&self) -> bool {
        (self.value() & Self::ERROR) != 0
    }

    pub fn is_warning(&self) -> bool {
        (self.value() & Self::WARNING) != 0
    }

    pub fn should_stop(&self) -> bool {
        (self.value() & Self::STOP) != 0
    }

    pub fn session_completed(&self) -> bool {
        (self.value() & Self::COMPLETED) != 0
    }
}
