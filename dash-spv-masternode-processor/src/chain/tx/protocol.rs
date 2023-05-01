// block height indicating transaction is unconfirmed
pub const TX_UNCONFIRMED: i32 = i32::MAX;

pub static SIGHASH_ALL: u32 = 1;
pub static TX_VERSION: u32 = 0x00000001;
pub static SPECIAL_TX_VERSION: u32 = 0x00000003;
pub static TX_LOCKTIME: u32 = 0x00000000;
pub static TXIN_SEQUENCE: u32 = u32::MAX;
// a lockTime below this value is a block height, otherwise a timestamp
pub const TX_MAX_LOCK_HEIGHT: u32 = 500000000;

pub const MAX_ECDSA_SIGNATURE_SIZE: usize = 75;
