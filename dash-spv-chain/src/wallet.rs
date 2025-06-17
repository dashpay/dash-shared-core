use std::os::raw::c_void;
use std::sync::Arc;
use crate::{ChainError, TransactionModel};

pub trait WalletRef {
    fn wallet_ref(&self) -> &WalletController;
}

#[derive(Clone)]
pub struct WalletController {
    get_account_by_index: Arc<dyn Fn(*const c_void, u32) -> *const c_void>,
    publish_asset_lock_transaction: Arc<dyn Fn(*const c_void, /*amount*/u64, /*registration_address_script*/Vec<u8>, /*prompt*/String) -> Result<TransactionModel, ChainError>>,
    is_transient: Arc<dyn Fn(*const c_void) -> bool>
}

impl WalletController {
    pub fn new<
        GetAccountByIndex: Fn(*const c_void, u32) -> *const c_void + Send + Sync + 'static,
        PublishAssetLockTransaction: Fn(*const c_void, u64, Vec<u8>, String) -> Result<TransactionModel, ChainError> + Send + Sync + 'static,
        IsTransient: Fn(*const c_void) -> bool + Send + Sync + 'static,
    >(
        get_account_by_index: GetAccountByIndex,
        publish_asset_lock_transaction: PublishAssetLockTransaction,
        is_transient: IsTransient,
    ) -> WalletController {
        Self {
            get_account_by_index: Arc::new(get_account_by_index),
            publish_asset_lock_transaction: Arc::new(publish_asset_lock_transaction),
            is_transient: Arc::new(is_transient),
        }
    }

    pub fn account_by_index(&self, wallet_context: *const c_void, index: u32) -> *const c_void {
        (self.get_account_by_index)(wallet_context, index)
    }

    pub fn publish_asset_lock_transaction(&self, wallet_context: *const c_void, amount: u64, registration_address_script: Vec<u8>, prompt: String) -> Result<TransactionModel, ChainError> {
        (self.publish_asset_lock_transaction)(wallet_context, amount, registration_address_script, prompt)
    }

    pub fn is_transient(&self, wallet_context: *const c_void) -> bool {
        (self.is_transient)(wallet_context)
    }

}
