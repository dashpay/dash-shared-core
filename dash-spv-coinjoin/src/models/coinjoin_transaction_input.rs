use dash_spv_masternode_processor::tx::TransactionInput;

use super::tx_outpoint::TxOutPoint;

// Holds a mixing input
#[derive(Debug, Clone)]
pub struct CoinJoinTransactionInput {
    pub txin: TransactionInput,
    pub rounds: i32
}

impl CoinJoinTransactionInput {
    pub fn new(txin: TransactionInput, rounds: i32) -> Self {
        CoinJoinTransactionInput {
            txin,
            rounds
        }
    }

    pub fn outpoint(&self) -> TxOutPoint {
        return TxOutPoint::new(self.txin.input_hash, self.txin.index);
    }
}

