use crate::{utils::key_holder::KeyHolder, wallet_ex::WalletEx};

#[derive(Debug)]
pub(crate) struct KeyHolderStorage {
    storage: Vec<KeyHolder>
}

impl KeyHolderStorage {
    pub fn new() -> Self {
        Self {
            storage: Vec::new(),
        }
    }

    pub fn add_key(&self, wallet: &WalletEx) -> Option<Vec<u8>>  {
        let key_holder = KeyHolder::new(wallet);
        let script = key_holder.get_script_for_destination();
        self.storage.push(key_holder);
        script
    }

    pub fn keep_all(&self) {
        let tmp = std::mem::replace(&mut *self.storage, Vec::new());

        if !tmp.is_empty() {
            for key in tmp {
                key.keep_key();
            }
            println!("keepAll -- {} keys kept", tmp.len());
        }
    }

    pub fn return_all(&self) {
        let tmp = std::mem::replace(&mut *self.storage, Vec::new());

        if !tmp.is_empty() {
            for key in tmp {
                key.return_key();
            }
            println!("returnAll -- {} keys returned", tmp.len());
        }
    }
}