use dash_spv_masternode_processor::ffi::ByteArray;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Recipient {
    pub script_pub_key: ByteArray,
    pub amount: u64,
    pub subtract_fee_from_amount: bool
}
