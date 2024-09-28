use std::{cell::RefCell, rc::Rc};
use tracing::info;
use crate::{utils::key_holder::KeyHolder, wallet_ex::WalletEx};

pub(crate) struct KeyHolderStorage {
    storage: Vec<KeyHolder>,
}

impl KeyHolderStorage {
    pub fn new() -> Self {
        Self {
            storage: Vec::new(),
        }
    }

    pub fn add_key(&mut self, wallet: Rc<RefCell<WalletEx>>) -> Option<Vec<u8>>  {
        let key_holder = KeyHolder::new(wallet);
        let script = key_holder.destination.clone();
        self.storage.push(key_holder);
        
        return script;
    }

    pub fn keep_all(&mut self) {
        let mut tmp = self.storage.clone();
        self.storage.clear();

        if !tmp.is_empty() {
            for key_holder in &mut tmp {
                key_holder.keep_key();
            }

            info!(target: "CoinJoin", "keepAll: {} keys kept", tmp.len());
        }
    }

    pub fn return_all(&mut self) {
        for key_holder in &mut self.storage {
            key_holder.return_key();
        }
    }
}