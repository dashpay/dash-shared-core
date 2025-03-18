use std::{cell::RefCell, rc::Rc};
use dashcore::{ScriptBuf, TxOut};
use crate::wallet_ex::WalletEx;
use super::reserve_destination::ReserveDestination;

#[derive(Clone)]
pub struct TransactionBuilderOutput {
    reserve_destination: ReserveDestination,
    pub amount: u64,
    pub script: Option<Vec<u8>>
}

impl<'a> TransactionBuilderOutput {
    pub fn new(wallet: Rc<RefCell<WalletEx>>, amount: u64, dry_run: bool) -> Self {
        let mut reserve_destination = ReserveDestination::new(wallet);
        Self {
            script: if dry_run { Some(vec![0;20]) } else { reserve_destination.get_reserved_destination(false) },
            reserve_destination,
            amount,
        }
    }

    /// Tell the wallet to remove the key used by this output from the keypool
    pub fn keep_key(&mut self) {
        self.reserve_destination.keep_destination();
    }

    /// Tell the wallet to return the key used by this output to the keypool
    pub fn return_key(&mut self) {
        self.reserve_destination.return_destination();
    }

    /// Try update the amount of this output. Returns true if it was successful and false if not (e.g. insufficient amount left).
    pub fn update_amount(&mut self, new_amount: u64, amount_left: u64) -> bool {
        if new_amount - self.amount > amount_left {
            return false;
        }

        self.amount = new_amount;
        true
    }

    pub fn build_output(&self) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: ScriptBuf::from(self.script.clone().unwrap_or_default()),
        }
    }
}