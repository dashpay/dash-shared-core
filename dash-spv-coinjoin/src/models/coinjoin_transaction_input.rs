use dash_spv_masternode_processor::tx::TransactionInput;

use super::tx_outpoint::TxOutPoint;

//  Holds a mixing input
#[derive(Debug, Clone)]
pub struct CoinJoinTransactionInput {
    pub txin: TransactionInput,
    // memory only
    prev_pub_key: Option<Vec<u8>>,
    // flag to indicate if signed
    has_sig: bool,
    pub rounds: i32
}

impl CoinJoinTransactionInput {
    pub fn new(txin: TransactionInput, prev_pub_key: Option<Vec<u8>>, rounds: i32) -> Self {
        CoinJoinTransactionInput {
            txin,
            prev_pub_key,
            has_sig: false,
            rounds
        }
    }

    pub fn outpoint(&self) -> TxOutPoint {
        return TxOutPoint::new(self.txin.input_hash, self.txin.index);
    }
}

