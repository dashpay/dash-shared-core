use crate::{wallet_ex::WalletEx, models::transaction_destination::TransactionDestination};

#[derive(Debug)]
pub(crate) struct KeyHolder {
    reserve_destination: ReserveDestination, // TODO: use ReserveKey
    destination: TransactionDestination,
}

impl KeyHolder {
    pub fn new(wallet: &WalletEx) -> Self {
        // Get the next CoinJoinKey?
        let reserve_destination = ReserveDestination::new(wallet);
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

    pub fn get_script_for_destination(&self) -> Option<Vec<u8>> {
        self.destination.get_script()
    }
}