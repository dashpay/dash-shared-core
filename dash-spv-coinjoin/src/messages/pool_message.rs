#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PoolMessage {
    ErrAlreadyHave = 0,
    ErrDenom = 1,
    ErrEntriesFull = 2,
    ErrExistingTx = 3,
    ErrFees = 4,
    ErrInvalidCollateral = 5,
    ErrInvalidInput = 6,
    ErrInvalidScript = 7,
    ErrInvalidTx = 8,
    ErrMaximum = 9,
    ErrMnList = 10,
    ErrMode = 11,
    ErrQueueFull = 14,
    ErrRecent = 15,
    ErrSession = 16,
    ErrMissingTx = 17,
    ErrVersion = 18,
    MsgNoErr = 19,
    MsgSuccess = 20,
    MsgEntriesAdded = 21,
    ErrSizeMismatch = 22,

    // extra values for DashSync Reporting
    ErrTimeout = 23,
    ErrConnectionTimeout = 24,
}

impl PoolMessage {
    pub fn value(&self) -> i32 {
        *self as i32
    }

    pub fn from_value(value: i32) -> Self {
        match value {
            0 => PoolMessage::ErrAlreadyHave,
            1 => PoolMessage::ErrDenom,
            2 => PoolMessage::ErrEntriesFull,
            3 => PoolMessage::ErrExistingTx,
            4 => PoolMessage::ErrFees,
            5 => PoolMessage::ErrInvalidCollateral,
            6 => PoolMessage::ErrInvalidInput,
            7 => PoolMessage::ErrInvalidScript,
            8 => PoolMessage::ErrInvalidTx,
            9 => PoolMessage::ErrMaximum,
            10 => PoolMessage::ErrMnList,
            11 => PoolMessage::ErrMode,
            14 => PoolMessage::ErrQueueFull,
            15 => PoolMessage::ErrRecent,
            16 => PoolMessage::ErrSession,
            17 => PoolMessage::ErrMissingTx,
            18 => PoolMessage::ErrVersion,
            19 => PoolMessage::MsgNoErr,
            20 => PoolMessage::MsgSuccess,
            21 => PoolMessage::MsgEntriesAdded,
            22 => PoolMessage::ErrSizeMismatch,
            23 => PoolMessage::ErrTimeout,
            24 => PoolMessage::ErrConnectionTimeout,
            _ => PoolMessage::MsgNoErr, // Default case
        }
    }

    pub fn msg_pool_min() -> Self {
        PoolMessage::ErrAlreadyHave
    }

    pub fn msg_pool_max() -> Self {
        PoolMessage::ErrSizeMismatch
    }
}
