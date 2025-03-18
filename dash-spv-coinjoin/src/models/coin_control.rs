use std::collections::HashSet;
use dashcore::OutPoint;
// use dash_spv_masternode_processor::ffi::{boxer::{boxed, boxed_vec}, ByteArray};

// use crate::ffi as ffi;

use crate::constants::REFERENCE_DEFAULT_MIN_TX_FEE;
// use super::{tx_destination::TxDestination, tx_outpoint::TxOutPoint};

#[derive(Clone, Copy, Debug, PartialEq)]
// #[repr(C)]
#[ferment_macro::export]
pub enum CoinType {
    AllCoins = 0,
    OnlyFullyMixed = 1,
    OnlyReadyToMix = 2,
    OnlyNonDenominated = 3,
    OnlyMasternodeCollateral = 4,
    OnlyCoinJoinCollateral = 5,
}

// CoinControl comes from Dash Core.  Not all functions fields and functions are supported within the Wallet class
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinControl {
    pub dest_change: Option<Vec<u8>>,
    pub allow_other_inputs: bool,
    pub fee_rate: u64,
    pub discard_fee_rate: u64,
    pub avoid_address_reuse: bool,
    pub min_depth: i32,
    pub max_depth: i32,
    pub coin_type: CoinType,
    pub set_selected: HashSet<OutPoint>
}

impl CoinControl {
    pub fn new() -> Self {
        Self {
            dest_change: None,
            allow_other_inputs: false,
            fee_rate: REFERENCE_DEFAULT_MIN_TX_FEE / 1000,
            discard_fee_rate: REFERENCE_DEFAULT_MIN_TX_FEE / 1000,
            avoid_address_reuse: false,
            min_depth: 0,
            max_depth: 9999999,
            coin_type: CoinType::AllCoins,
            set_selected: HashSet::new()
        }
    }

    pub fn select(&mut self, out_point: OutPoint) {
        self.set_selected.insert(out_point);
    }

    pub fn unselect(&mut self, out_point: OutPoint) {
        self.set_selected.remove(&out_point);
    }
    
    // pub fn encode(&self) -> ffi::coin_control::CoinControl {
    //     ffi::coin_control::CoinControl {
    //         coin_type: self.coin_type,
    //         min_depth: self.min_depth,
    //         max_depth: self.max_depth,
    //         avoid_address_reuse: self.avoid_address_reuse,
    //         allow_other_inputs: self.allow_other_inputs,
    //         set_selected: if self.set_selected.is_empty() {
    //             std::ptr::null_mut()
    //         } else {
    //             boxed_vec(
    //                 self.set_selected
    //                     .iter()
    //                     .map(|outpoint| boxed(ffi::tx_outpoint::TxOutPoint::from(outpoint.clone())))
    //                     .collect()
    //             )
    //         },
    //         set_selected_size: self.set_selected.len(),
    //         dest_change: if self.dest_change.is_none() {
    //             std::ptr::null_mut()
    //         } else {
    //             boxed(ByteArray::from(self.dest_change.as_ref().unwrap().to_vec()))
    //         }
    //     }
    // }
}
