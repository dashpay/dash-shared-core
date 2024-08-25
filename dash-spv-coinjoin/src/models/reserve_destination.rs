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
#[derive(Clone)]
pub struct ReserveDestination {
    wallet_ex: Rc<RefCell<WalletEx>>,
    pub address: TxDestination,
    pub internal: bool,
}

impl<'a> ReserveDestination {
    pub fn new(wallet_ex: Rc<RefCell<WalletEx>>) -> Self {
        Self {
            wallet_ex,
            address: None,
            internal: false,
        }
    }

    pub fn get_reserved_destination(&mut self, internal: bool) -> TxDestination {
        if self.address.is_none() {
            let mut wallet = self.wallet_ex.borrow_mut();
            
            if let Some(key) = wallet.get_unused_key(internal) {
                self.address = Some(key);
                self.internal = true;
            } else {
                return None;
            }
        }

        return self.address.clone();
    }

    pub fn keep_destination(&mut self) {
        if self.address.is_some() {
            self.wallet_ex.borrow_mut().remove_unused_key(&self.address);
        } else {
            println!("[RUST] CoinJoin: cannot keep key");
        }

        self.address = None;
    }

    pub fn return_destination(&mut self) {
        if self.address.is_some() {
            self.wallet_ex.borrow_mut().add_unused_key(&self.address);
        } else {
            println!("[RUST] CoinJoin: cannot return key");
        }

        self.address = None;
    }
}