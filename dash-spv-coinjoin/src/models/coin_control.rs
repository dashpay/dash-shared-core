use std::collections::HashSet;
use crate::{messages::transaction_outpoint::TransactionOutPoint, constants::REFERENCE_DEFAULT_MIN_TX_FEE};
use super::transaction_destination::TransactionDestination;

#[derive(Clone, Copy, Debug, PartialEq)]
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
    dest_change: Option<TransactionDestination>,
    allow_other_inputs: bool,
    require_all_inputs: bool,
    allow_watch_only: bool,
    override_fee_rate: bool,
    fee_rate: u64,
    discard_fee_rate: u64,
    confirm_target: i32,
    avoid_partial_spends: bool,
    avoid_address_reuse: bool,
    min_depth: i32,
    pub coin_type: CoinType,
    pub set_selected: HashSet<TransactionOutPoint>
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
            coin_type: CoinType::AllCoins,
            set_selected: HashSet::new()
        }
    }
}