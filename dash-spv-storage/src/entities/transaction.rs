use crate::entities::instant_send_lock::InstantSendLockEntity;
use crate::entities::shapeshift::ShapeshiftEntity;
use crate::entities::transaction_hash::TransactionHashEntity;
use crate::entities::transaction_input::TransactionInputEntity;
use crate::entities::transaction_output::TransactionOutputEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct TransactionEntity {
    pub lock_time: i32,

    pub associated_shapeshift: Option<ShapeshiftEntity>,
    pub inputs: Vec<TransactionInputEntity>,
    pub instant_send_lock: Option<InstantSendLockEntity>,
    pub outputs: Vec<TransactionOutputEntity>,
    pub transaction_hash: Option<TransactionHashEntity>,
}
