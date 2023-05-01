use std::collections::HashMap;
use crate::keys::{BLSKey, ECDSAKey, ED25519Key};

#[derive(Clone, Default)]
pub struct KeysCache {
    pub ecdsa: HashMap<u64, ECDSAKey>,
    pub bls: HashMap<u64, BLSKey>,
    pub ed25519: HashMap<u64, ED25519Key>,
}

impl std::fmt::Debug for KeysCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeysCache")
            .field("ecdsa", &self.ecdsa.len())
            .field("bls", &self.bls.len())
            .field("ed25519", &self.ed25519.len())
            .finish()
    }
}


impl KeysCache {
    pub fn clear(&mut self) {
        self.ecdsa.clear();
        self.bls.clear();
        self.ed25519.clear();
    }

    pub fn ecdsa_public_key_for_unique_id(&self, unique_id: u64) -> Option<&ECDSAKey> {
        self.ecdsa.get(&unique_id)
    }

    pub fn bls_public_key_for_unique_id(&self, unique_id: u64) -> Option<&BLSKey> {
        self.bls.get(&unique_id)
    }

    pub fn ed25519_public_key_for_unique_id(&self, unique_id: u64) -> Option<&ED25519Key> {
        self.ed25519.get(&unique_id)
    }
}
