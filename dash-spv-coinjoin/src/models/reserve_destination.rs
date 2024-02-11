use std::{cell::RefCell, rc::Rc};

use crate::wallet_ex::WalletEx;

use super::tx_destination::TxDestination;

/** A wrapper to reserve an address from a wallet
 *
 * ReserveDestination is used to reserve an address. It is passed around
 * during the CreateTransaction/CommitTransaction procedure.
 *
 * Instantiating a ReserveDestination does not reserve an address. To do so,
 * GetReservedDestination() needs to be called on the object. Once an address has been
 * reserved, call KeepDestination() on the ReserveDestination object to make sure it is not
 * returned. Call ReturnDestination() to return the address so it can be re-used (for
 * example, if the address was used in a new transaction
 * and that transaction was not completed and needed to be aborted).
 *
 * If an address is reserved and KeepDestination() is not called, then the address will be
 * returned when the ReserveDestination goes out of scope.
 */
#[derive(Debug, Clone)]
pub struct ReserveDestination {
    wallet_ex: Rc<RefCell<WalletEx>>,
    pub index: i64,
    pub address: TxDestination,
    pub internal: bool,
}

impl<'a> ReserveDestination {
    pub fn new(wallet_ex: Rc<RefCell<WalletEx>>) -> Self {
        Self {
            wallet_ex,
            index: -1,
            address: None,
            internal: false,
        }
    }

    pub fn get_reserved_destination(&self, internal: bool) -> Option<Vec<u8>> {
        // TODO
        None
    }

    pub fn keep_destination(&mut self) {
        // TODO
    }

    pub fn return_destination(&mut self) {
        // TODO
    }
}