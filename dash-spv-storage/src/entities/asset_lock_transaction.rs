use crate::entities::special_transaction::SpecialTransactionEntity;
use crate::entities::transaction_output::TransactionOutputEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct AssetLockTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub credit_outputs: Vec<TransactionOutputEntity>,
    // pub registration_funding_transaction: Option<AssetLockTransactionEntity>,
    // pub topup_funding_transactions: Vec<AssetLockTransactionEntity>,
}