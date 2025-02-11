use dash_spv_masternode_processor::ffi::ByteArray;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CoinJoinKeys {
    pub items: *mut *mut ByteArray,
    pub item_count: usize,
}