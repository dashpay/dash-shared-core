use crate::entities::address::AddressEntity;
use crate::entities::transaction::TransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct SpecialTransactionEntity {
    pub base: TransactionEntity,
    pub special_transaction_version: i16,
    pub addresses: Vec<AddressEntity>,
}
