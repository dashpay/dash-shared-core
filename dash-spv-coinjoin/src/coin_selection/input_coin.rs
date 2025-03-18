use dashcore::{OutPoint, TxOut};

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct InputCoin {
    pub tx_outpoint: OutPoint,
    pub output: TxOut,
    pub effective_value: u64
}