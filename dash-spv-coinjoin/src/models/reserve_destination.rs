use std::{cell::RefCell, rc::Rc};
use logging::*;
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
#[derive(Clone)]
pub struct ReserveDestination {
    wallet_ex: Rc<RefCell<WalletEx>>,
    pub key: TxDestination,
    pub internal: bool,
}

impl<'a> ReserveDestination {
    pub fn new(wallet_ex: Rc<RefCell<WalletEx>>) -> Self {
        Self {
            wallet_ex,
            key: None,
            internal: false,
        }
    }

    pub fn get_reserved_destination(&mut self, internal: bool) -> TxDestination {
        if self.key.is_none() {
            let mut wallet = self.wallet_ex.borrow_mut();
            
            if let Some(key) = wallet.get_unused_key(internal) {
                self.key = Some(key);
                self.internal = true;
            } else {
                return None;
            }
        }

        self.key.clone()
    }

    pub fn keep_destination(&mut self) {
        if self.key.is_some() {
            self.wallet_ex.borrow_mut().remove_unused_key(&self.key);
        } else {
            log_debug!(target: "CoinJoin", "cannot keep key");
        }

        self.key = None;
    }

    pub fn return_destination(&mut self) {
        if self.key.is_some() {
            self.wallet_ex.borrow_mut().add_unused_key(self.key.clone().unwrap());
        } else {
            log_debug!(target: "CoinJoin", "cannot return key");
        }

        self.key = None;
    }
}