use std::collections::BTreeMap;
use platform_value::Identifier;
use dash_spv_crypto::keys::OpaqueKey;

pub struct PotentialContact {
    pub username: String,
    pub display_name: String,
    pub avatar_path: String,
    pub public_message: String,
    pub associated_identity_unique_id: Option<Identifier>,

    pub key_dictionary: BTreeMap<u32, OpaqueKey>,
}

impl PotentialContact {
    pub fn with_username(username: String) -> Self {
        Self {
            username,
            display_name: String::new(),
            avatar_path: String::new(),
            public_message: String::new(),
            associated_identity_unique_id: None,
            key_dictionary: BTreeMap::new(),
        }
    }
    pub fn with_username_avatar_path_and_public_message(
        username: String,
        avatar_path: String,
        public_message: String
    ) -> Self {
        Self {
            username,
            display_name: String::new(),
            avatar_path,
            public_message,
            associated_identity_unique_id: None,
            key_dictionary: BTreeMap::new(),
        }
    }
    pub fn from_entity(
        username: String,
        avatar_path: String,
        public_message: String,
        associated_identity_unique_id: Identifier
    ) -> Self {
        Self {
            username,
            display_name: String::new(),
            avatar_path,
            public_message,
            associated_identity_unique_id: Some(associated_identity_unique_id),
            key_dictionary: BTreeMap::new(),
        }
    }
    pub fn add_public_key(&mut self, key: OpaqueKey, index: u32) {
        self.key_dictionary.insert(index, key);
    }

    pub fn public_key_at_index(&self, index: u32) -> Option<&OpaqueKey> {
        self.key_dictionary.get(&index)
    }

}