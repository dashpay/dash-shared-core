use dashcore::{OutPoint, TxIn};
// use dash_spv_masternode_processor::tx::TransactionInput;

// use super::tx_outpoint::TxOutPoint;

// Holds a mixing input
#[derive(Debug, Clone)]
pub struct CoinJoinTransactionInput {
    pub txin: TxIn,
    pub rounds: i32
}

impl CoinJoinTransactionInput {
    pub fn new(txin: TxIn, rounds: i32) -> Self {
        CoinJoinTransactionInput {
            txin,
            rounds
        }
    }

    pub fn outpoint(&self) -> OutPoint {
        self.txin.previous_output
        // return TxOutPoint::new(self.txin.input_hash, self.txin.index);
    }
}

