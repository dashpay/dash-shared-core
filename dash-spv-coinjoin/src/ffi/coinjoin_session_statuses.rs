use crate::messages::PoolStatus;

#[repr(C)]
pub struct CoinJoinSessionStatuses {
    pub statuses: *const PoolStatus,
    pub length: usize,
}
