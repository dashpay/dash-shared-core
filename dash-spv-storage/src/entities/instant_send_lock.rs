use crate::entities::transaction::TransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct InstantSendLockEntity {
    pub cycle_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub valid_signature: bool,
    pub version: i16,
    pub transaction: Option<Box<TransactionEntity>>,
}
