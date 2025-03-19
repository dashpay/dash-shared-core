use dashcore::blockdata::transaction::outpoint::OutPoint;
use dashcore::blockdata::transaction::txin::TxIn;

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

