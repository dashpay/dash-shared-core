use dash_spv_masternode_processor::tx::TransactionOutput;
use crate::models::tx_outpoint::TxOutPoint;

#[derive(Clone, Debug)]
pub struct InputCoin {
    pub tx_outpoint: TxOutPoint,
    pub output: TransactionOutput,
    pub effective_value: u64
}