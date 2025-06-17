use crate::entities::account::AccountEntity;
use crate::entities::address::AddressEntity;
use crate::entities::asset_lock_transaction::AssetLockTransactionEntity;
use crate::entities::transaction::TransactionEntity;
use crate::entities::transaction_input::TransactionInputEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct TransactionOutputEntity {
    pub address: String,
    pub n: i32,
    pub script: Vec<u8>,
    pub shapeshift_outbound_address: String,
    pub tx_hash: Vec<u8>,
    pub value: i64,

    pub account: Option<AccountEntity>,
    pub assetlock: Option<AssetLockTransactionEntity>,
    pub local_address: Option<AddressEntity>,
    pub spent_in_input: Option<Box<TransactionInputEntity>>,
    pub transaction: Option<TransactionEntity>,
}
