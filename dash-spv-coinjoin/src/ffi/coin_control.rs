use crate::models::coin_control::CoinType;

use super::tx_outpoint::TxOutPoint;

#[repr(C)]
pub struct CoinControl {
    pub coin_type: CoinType,
    pub min_depth: i32,
    pub max_depth: i32,
    pub avoid_address_reuse: bool,
    pub allow_other_inputs: bool,
    pub set_selected: *mut *mut TxOutPoint,
    pub set_selected_size: usize,
}
