use crate::entities::special_transaction::SpecialTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct AssetUnlockTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub fee: i32,
    pub index: i64,
    pub quorum_hash: Vec<u8>,
    pub quorum_signature: Vec<u8>,
    pub requested_height: i32,
}
