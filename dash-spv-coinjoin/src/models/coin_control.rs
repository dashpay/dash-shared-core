use std::collections::HashSet;
use crate::ffi::coin_control as ffi;

use crate::constants::REFERENCE_DEFAULT_MIN_TX_FEE;
use super::{tx_destination::TxDestination, tx_outpoint::TxOutPoint};

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum CoinType {
    AllCoins = 0,
    OnlyFullyMixed = 1,
    OnlyReadyToMix = 2,
    OnlyNonDenominated = 3,
    OnlyMasternodeCollateral = 4,
    OnlyCoinJoinCollateral = 5,
}

// CoinControl comes from Dash Core.  Not all functions fields and functions are supported within the Wallet class
pub struct CoinControl {
    pub dest_change: TxDestination,
    pub allow_other_inputs: bool,
    require_all_inputs: bool,
    allow_watch_only: bool,
    override_fee_rate: bool,
    pub fee_rate: u64,
    pub discard_fee_rate: u64,
    confirm_target: i32,
    avoid_partial_spends: bool,
    avoid_address_reuse: bool,
    min_depth: i32,
    max_depth: i32,
    pub coin_type: CoinType,
    pub set_selected: HashSet<TxOutPoint>
}

impl CoinControl {
    pub fn new() -> Self {
        Self {
            dest_change: None,
            allow_other_inputs: false,
            require_all_inputs: true,
            allow_watch_only: false,
            override_fee_rate: false,
            fee_rate: REFERENCE_DEFAULT_MIN_TX_FEE / 1000,
            discard_fee_rate: REFERENCE_DEFAULT_MIN_TX_FEE / 1000,
            confirm_target: -1,
            avoid_partial_spends: false,
            avoid_address_reuse: false,
            min_depth: 0,
            max_depth: 9999999,
            coin_type: CoinType::AllCoins,
            set_selected: HashSet::new()
        }
    }

    pub fn select(&mut self, out_point: TxOutPoint) {
        self.set_selected.insert(out_point);
    }

    pub fn unselect(&mut self, out_point: TxOutPoint) {
        self.set_selected.remove(&out_point);
    }
    
    pub fn encode(&self) -> ffi::CoinControl {
        ffi::CoinControl {
            coin_type: self.coin_type,
            min_depth: self.min_depth,
            max_depth: self.max_depth,
            avoid_address_reuse: self.avoid_address_reuse,
            allow_other_inputs: self.allow_other_inputs
        }
    }
}