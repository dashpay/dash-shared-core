use crate::models::tx_outpoint as tx_outpoint;

#[repr(C)]
pub struct TxOutPoint {
    pub hash: [u8; 32],
    pub index: u32,
}

impl From<tx_outpoint::TxOutPoint> for TxOutPoint {
    fn from(outpoint: tx_outpoint::TxOutPoint) -> Self {
        TxOutPoint {
            hash: outpoint.hash.0,
            index: outpoint.index,
        }
    }
}
