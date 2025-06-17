use crate::entities::special_transaction::SpecialTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinbaseTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub best_cl_height_diff: i32,
    pub best_cl_signature: Vec<u8>,
    pub credit_pool_balance: i64,
    pub height: i32,
    pub merkle_root_llmq_list: Vec<u8>,
    pub merkle_root_mn_list: Vec<u8>,
}
