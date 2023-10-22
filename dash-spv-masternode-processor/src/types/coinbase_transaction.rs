use crate::ffi::unboxer::unbox_any;
use crate::types::transaction::Transaction;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CoinbaseTransaction {
    pub base: *mut Transaction,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: *mut [u8; 32],
    pub merkle_root_llmq_list: *mut [u8; 32],
    pub best_cl_height_diff: u32,
    pub best_cl_signature: *mut [u8; 96],
    pub credit_pool_balance: i64,
}

impl Drop for CoinbaseTransaction {
    fn drop(&mut self) {
        unsafe {
            unbox_any(self.base);
            if !self.merkle_root_mn_list.is_null() {
                unbox_any(self.merkle_root_mn_list);
            }
            if !self.merkle_root_llmq_list.is_null() {
                unbox_any(self.merkle_root_llmq_list);
            }
            if !self.best_cl_signature.is_null() {
                unbox_any(self.best_cl_signature);
            }
        }
    }
}