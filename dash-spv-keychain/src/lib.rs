use std::collections::HashMap;
use std::sync::Arc;

pub const DERIVATION_PATH_EXTENDED_PUBLIC_KEY_WALLET_BASED_LOCATION: &str ="DP_EPK_WBL";
pub const DERIVATION_PATH_EXTENDED_PUBLIC_KEY_STANDALONE_BASED_LOCATION: &str ="DP_EPK_SBL";
pub const DERIVATION_PATH_STANDALONE_INFO_DICTIONARY_LOCATION: &str ="DP_SIDL";
pub const DERIVATION_PATH_EXTENDED_SECRET_KEY_WALLET_BASED_LOCATION: &str ="DP_ESK_WBL";


#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum KeyChainKey {
    GetDataBytesKey { key: String },
    StandaloneInfoDictionaryLocationString { extended_public_key_identifier: String },
    StandaloneExtendedPublicKeyLocationString { extended_public_key_identifier: String },
    HasKnownBalanceUniqueIDString { reference: u32, unique_id: String },
    WalletBasedExtendedPrivateKeyLocationString { unique_id: String },
    WalletBasedExtendedPublicKeyLocationString { unique_id: String },
    WalletIdentitiesKey { wallet_id: String },
    WalletIdentitiesDefaultIndexKey { wallet_id: String },
    WalletInvitationsKey { wallet_id: String },
}

impl KeyChainKey {
    pub fn standalone_info_dictionary_location_string(extended_public_key_identifier: &str) -> Self {
        Self::StandaloneInfoDictionaryLocationString { extended_public_key_identifier: extended_public_key_identifier.to_string() }
    }
    pub fn standalone_extended_public_key_location_string(extended_public_key_identifier: &str) -> Self {
        Self::StandaloneExtendedPublicKeyLocationString { extended_public_key_identifier: extended_public_key_identifier.to_string() }
    }
    pub fn has_known_balance_unique_id_string(reference: u32, unique_id: &str) -> Self {
        Self::HasKnownBalanceUniqueIDString { reference, unique_id: unique_id.to_string() }
    }
    pub fn wallet_based_extended_private_key_location_string(unique_id: &str) -> Self {
        Self::WalletBasedExtendedPrivateKeyLocationString { unique_id: unique_id.to_string() }
    }
    pub fn wallet_based_extended_public_key_location_string(unique_id: &str) -> Self {
        Self::WalletBasedExtendedPublicKeyLocationString { unique_id: unique_id.to_string() }
    }
    pub fn wallet_identities_key(wallet_id: &str) -> Self {
        Self::WalletIdentitiesKey { wallet_id: wallet_id.to_string() }
    }
    pub fn wallet_identities_default_index_key(wallet_id: &str) -> Self {
        Self::WalletIdentitiesDefaultIndexKey { wallet_id: wallet_id.to_string() }
    }

    pub fn wallet_invitations_key(wallet_id: &str) -> Self {
        Self::WalletInvitationsKey { wallet_id: wallet_id.to_string() }
    }

}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum IdentityDictionaryItemValue {
    Index {
        index: u32
    },
    Outpoint {
        index: u32,
        locked_outpoint_data: [u8; 36],
    },
}
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum KeyChainValue {
    Bytes(Vec<u8>),
    Int64(i64),
    String(String),
    IdentityDictionary(HashMap<[u8; 32], IdentityDictionaryItemValue>),
    InvitationDictionary(HashMap<[u8; 36], u32>),
    None,
}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum KeyChainError {
    OsStatusCode(i32),
    WrongDataFormatForKey(String),
    WrongDataFormat(String),
}

pub trait KeychainRef {
    fn keychain_ref(&self) -> &KeychainController;
}

#[derive(Clone)]
pub struct KeychainController {
    pub get: Arc<dyn Fn(KeyChainKey) -> Result<KeyChainValue, KeyChainError> + Send + Sync>,
    pub set: Arc<dyn Fn(KeyChainKey, KeyChainValue, bool) -> Result<bool, KeyChainError> + Send + Sync>,
    pub has: Arc<dyn Fn(KeyChainKey) -> Result<bool, KeyChainError> + Send + Sync>,
    pub delete: Arc<dyn Fn(KeyChainKey) -> Result<bool, KeyChainError> + Send + Sync>,
}

#[ferment_macro::export]
impl KeychainController {
    pub fn new<
        GET: Fn(KeyChainKey) -> Result<KeyChainValue, KeyChainError> + Send + Sync + 'static,
        SET: Fn(KeyChainKey, KeyChainValue, bool) -> Result<bool, KeyChainError> + Send + Sync + 'static,
        HAS: Fn(KeyChainKey) -> Result<bool, KeyChainError> + Send + Sync + 'static,
        DEL: Fn(KeyChainKey) -> Result<bool, KeyChainError> + Send + Sync + 'static,
    >(
        get: GET,
        set: SET,
        has: HAS,
        delete: DEL,
    ) -> Self {
        Self {
            get: Arc::new(get),
            set: Arc::new(set),
            has: Arc::new(has),
            delete: Arc::new(delete),
        }
    }
    pub fn get(&self, key: KeyChainKey) -> Result<KeyChainValue, KeyChainError> {
        (self.get)(key)
    }
    pub fn set(&self, key: KeyChainKey, value: KeyChainValue, authenticated: bool) -> Result<bool, KeyChainError> {
        (self.set)(key, value, authenticated)
    }
    pub fn has(&self, key: KeyChainKey) -> Result<bool, KeyChainError> {
        (self.has)(key)
    }
    pub fn delete(&self, key: KeyChainKey) -> Result<bool, KeyChainError> {
        (self.delete)(key)
    }
}