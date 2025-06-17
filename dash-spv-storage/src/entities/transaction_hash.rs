use crate::entities::chain::ChainEntity;
use crate::entities::transaction::TransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct TransactionHashEntity {
    pub block_height: u32,
    pub timestamp: f64,
    pub tx_hash: [u8; 32],

    pub chain: Option<ChainEntity>,
    pub transaction: Option<Box<TransactionEntity>>,
}