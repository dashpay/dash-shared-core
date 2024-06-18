use std::{cell::RefCell, rc::Rc};

use crate::{wallet_ex::WalletEx, models::{reserve_destination::ReserveDestination, tx_destination::TxDestination}};

#[derive(Clone)]
pub(crate) struct KeyHolder {
    reserve_destination: ReserveDestination, // TODO(dashj): use ReserveKey
    pub destination: TxDestination,
}

impl KeyHolder {
    pub fn new(wallet: Rc<RefCell<WalletEx>>) -> Self {
        // Get the next CoinJoinKey?
        let mut reserve_destination = ReserveDestination::new(wallet);
        let destination = reserve_destination.get_reserved_destination(false);
        Self {
            reserve_destination,
            destination,
        }
    }

    pub fn keep_key(&mut self) {
        self.reserve_destination.keep_destination();
    }

    pub fn return_key(&mut self) {
        self.reserve_destination.return_destination();
    }
}