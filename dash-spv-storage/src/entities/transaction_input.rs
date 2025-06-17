use crate::entities::address::AddressEntity;
use crate::entities::transaction::TransactionEntity;
use crate::entities::transaction_output::TransactionOutputEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct TransactionInputEntity {
    pub n: i32,
    pub sequence: i32,
    pub signature: Vec<u8>,
    pub tx_hash: Vec<u8>,

    pub local_address: Option<AddressEntity>,
    pub prev_output: Option<TransactionOutputEntity>,
    pub transaction: Option<TransactionEntity>,
}
