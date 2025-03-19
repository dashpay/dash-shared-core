use dashcore::blockdata::transaction::OutPoint;
use dashcore::blockdata::transaction::txout::TxOut;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct InputCoin {
    pub tx_outpoint: OutPoint,
    pub output: TxOut,
    pub effective_value: u64
}