use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use bitcoin_hashes::hex::DisplayHex;
use dpp::identity::{Identity, IdentityPublicKey, identity_public_key::key_type::KeyType};
use dash_sdk::platform::Fetch;
use dash_sdk::platform::types::identity::PublicKeyHash;
use dash_sdk::{RequestSettings, Sdk};
use dash_spv_macro::StreamManager;
use dpp::identity::accessors::IdentityGettersV0;
use dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dpp::identity::identity_public_key::contract_bounds::ContractBounds;
use dpp::identity::identity_public_key::{Purpose, SecurityLevel};
use dpp::identity::identity_public_key::v0::IdentityPublicKeyV0;
use drive_proof_verifier::types::RetrievedObjects;
use indexmap::IndexMap;
use platform_value::{BinaryData, Identifier};
use dash_spv_crypto::derivation::{IIndexPath, IndexPath, BIP32_HARD};
use dash_spv_crypto::hashes::hash160;
use dash_spv_crypto::keys::{BLSKey, ECDSAKey, IKey, KeyError, OpaqueKey};
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings};
use crate::error::Error;
use crate::util::{RetryStrategy, StreamManager, StreamSettings, StreamSpec, Validator};
const KEYS_TO_CHECK: u32 = 5;
const DEFAULT_SETTINGS: RequestSettings = RequestSettings {
    connect_timeout: Some(Duration::from_millis(20000)),
    timeout: Some(Duration::from_secs(0)),
    retries: Some(3),
    ban_failed_address: None,
};

#[derive(Clone)]
#[ferment_macro::export]
pub struct IndexedKey {
    pub index: u32,
    pub key: OpaqueKey
}

#[derive(Clone)]
#[ferment_macro::export]
pub enum IdentityValidator {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}
impl IdentityValidator {
    pub fn accept_not_found(&self) -> bool {
        match self {
            IdentityValidator::None => false,
            IdentityValidator::AcceptNotFoundAsNotAnError => true
        }
    }
}
impl Validator<Option<Identity>> for IdentityValidator {
    fn validate(&self, value: &Option<Identity>) -> bool {
        value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl Validator<RetrievedObjects<Identifier, Identity>> for IdentityValidator {
    fn validate(&self, _value: &RetrievedObjects<Identifier, Identity>) -> bool {
        true
        // value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl StreamSpec for IdentityValidator {
    type Validator = IdentityValidator;
    type Error = dash_sdk::Error;
    type Result = Option<Identity>;
    type ResultMany = IndexMap<Identifier, Option<Identity>>;
}


#[derive(Clone, StreamManager)]
#[ferment_macro::opaque]
pub struct IdentitiesManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
    pub foreign_identities: HashMap<Identifier, Identity>,
    pub last_synced_identities_timestamp: u64,
    pub has_recent_identities_sync: bool,
    // key is wallet_unique_id
    pub all_identities: Arc<RwLock<BTreeMap<String, BTreeMap<[u8; 20], Identity>>>>,
}

impl Debug for IdentitiesManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}] [IdentitiesManager]", self.chain_type.name()).as_str())
    }
}

impl IdentitiesManager {
    pub fn new(sdk: &Arc<Sdk>, chain_type: ChainType) -> Self {
        Self { chain_type, foreign_identities: HashMap::new(), all_identities: Arc::new(RwLock::new(BTreeMap::new())), sdk: Arc::clone(sdk), last_synced_identities_timestamp: 0, has_recent_identities_sync: false }
    }
}
#[ferment_macro::export]
impl IdentitiesManager {
    pub async fn fetch_by_id_bytes(&self, id_bytes: [u8; 32]) -> Result<Option<Identity>, Error> {
        self.fetch_by_id(Identifier::from(id_bytes)).await
    }
    pub async fn fetch_by_id(&self, id: Identifier) -> Result<Option<Identity>, Error> {
        Identity::fetch_by_identifier(&self.sdk, id).await.map_err(Error::from)
    }
    pub async fn fetch_by_key_hash(&self, key_hash: PublicKeyHash) -> Result<Option<Identity>, Error> {
        Identity::fetch(&self.sdk, key_hash).await.map_err(Error::from)
    }
    pub async fn fetch_balance(&self, id: Identifier) -> Result<Option<u64>, Error> {
        u64::fetch_by_identifier(&self.sdk, id).await.map_err(Error::from)
    }
    pub async fn fetch_balance_by_id_bytes(&self, id: [u8; 32]) -> Result<Option<u64>, Error> {
        self.fetch_balance(Identifier::from(id)).await
    }
    pub async fn get_identities_for_wallets_public_keys(&self, wallets: BTreeMap<String, Vec<[u8; 20]>>) -> Result<BTreeMap<String, BTreeMap<[u8; 20], Identity>>, Error> {
        let mut all_identities = BTreeMap::new();
        for (wallet_id, key_hashes) in wallets.into_iter() {
            println!("{self:?} get_identities_for_wallets_public_keys -> {} -- {:?}", wallet_id, key_hashes);
            let mut identities = BTreeMap::new();
            for key_hash in key_hashes {
                let identity_result = Identity::fetch_with_settings(&self.sdk, PublicKeyHash(key_hash), DEFAULT_SETTINGS).await;
                match identity_result {
                    Ok(Some(identity)) => {
                        println!("{self:?} Ok::get_identities_for_wallets -> wallet_id: {}: index: {}: identity_id: {}", wallet_id, key_hash.to_lower_hex_string(), identity.id().to_buffer().to_lower_hex_string());
                        identities.insert(key_hash, identity);
                    },
                    Ok(None) => {
                        println!("{self:?} None::get_identities_for_wallets -> wallet_id: {}: index: {}: identity_id: None", wallet_id, key_hash.to_lower_hex_string());
                    }
                    Err(error) => {
                        println!("{self:?} Error::get_identities_for_wallets -> wallet_id: {}: index: {}: error: {}", wallet_id, key_hash.to_lower_hex_string(), error.to_string());
                    }
                }
            }
            all_identities.insert(wallet_id, identities);
        }
        let mut lock = self.all_identities.write().unwrap();
        lock.extend(all_identities.clone());
        drop(lock);
        Ok(all_identities)
    }
    pub async fn get_identities_for_key_hashes(&self, wallet_id: String, key_hashes: Vec<[u8; 20]>, ) -> Result<BTreeMap<[u8; 20], Identity>, Error> {
        let mut identities = BTreeMap::new();
        for key_hash in key_hashes.into_iter() {
            match Identity::fetch_with_settings(&self.sdk, PublicKeyHash(key_hash), DEFAULT_SETTINGS).await {
                Ok(Some(identity)) => {
                    println!("{self:?} Ok::get_identities_for_wallets -> key_hash: {}: identity_id: {}", key_hash.to_lower_hex_string(), identity.id().to_buffer().to_lower_hex_string());
                    identities.insert(key_hash, identity);
                },
                Ok(None) => {
                    println!("{self:?} None::get_identities_for_wallets -> key_hash: {}: identity_id: None", key_hash.to_lower_hex_string());
                }
                Err(error) => {
                    println!("{self:?} Error::get_identities_for_wallets -> key_hash: {}: error: {}", key_hash.to_lower_hex_string(), error.to_string());
                }
            }
        }
        let mut lock = self.all_identities.write().unwrap();
        lock.entry(wallet_id)
            .or_default()
            .extend(identities.clone());
        drop(lock);
        Ok(identities)
    }
    pub async fn get_identities_by_pub_key_hashes_at_index_range(&self, extended_public_key: &ECDSAKey, unused_index: u32) -> Result<IndexMap<u32, Identity>, Error> {
        let mut identities = IndexMap::new();
        for i in unused_index..KEYS_TO_CHECK {
            let index_path = IndexPath::<u32>::new([i | BIP32_HARD, 0 | BIP32_HARD].to_vec());
            let index_key = extended_public_key.public_key_from_extended_public_key_data_at_index_path(&index_path)
                .map_err(Error::KeyError)?;
            let pub_key_data = index_key.public_key_data();
            if let Some(identity) = Identity::fetch(&self.sdk, PublicKeyHash(hash160::Hash::hash(&pub_key_data).to_byte_array()))
                .await? {
                identities.insert(i, identity);
            }
        }
        Ok(identities)
    }

    pub async fn monitor(&self, unique_id: Identifier, retry: RetryStrategy, options: IdentityValidator) -> Result<Option<Identity>, Error> {
        self.stream::<IdentityValidator, Identity, Identifier>(unique_id, retry, options).await
    }
    pub async fn monitor_for_id_bytes(&self, unique_id: [u8; 32], retry: RetryStrategy, options: IdentityValidator) -> Result<Option<Identity>, Error> {
        self.stream::<IdentityValidator, Identity, Identifier>(Identifier::from(unique_id), retry, options).await
    }
    pub async fn monitor_for_key_hash(&self, key_hash: [u8; 20], retry: RetryStrategy, options: IdentityValidator) -> Result<Option<Identity>, Error> {
        self.stream::<IdentityValidator, Identity, PublicKeyHash>(PublicKeyHash(key_hash), retry, options).await
    }
    pub async fn monitor_with_delay(&self, unique_id: [u8; 32], retry: RetryStrategy, options: IdentityValidator, delay: u64) -> Result<Option<Identity>, Error> {
        self.stream_with_settings::<IdentityValidator, Identity, Identifier>(Identifier::from(unique_id), retry, StreamSettings::default_with_delay(delay), options).await
    }
    pub async fn monitor_for_key_hashes(&self, key_hashes: Vec<[u8; 20]>, retry: RetryStrategy, options: IdentityValidator) -> Result<BTreeMap<[u8; 20], Identity>, Error> {
        println!("{self:?} monitor_for_key_hashes: {}", key_hashes.len());
        let mut identities = BTreeMap::new();
        for key_hash in key_hashes.into_iter() {
            match self.monitor_for_key_hash(key_hash, retry.clone(), options.clone()).await {
                Ok(Some(identity)) => {
                    let identity_id = identity.id();
                    let public_keys = identity.public_keys();
                    let debug_keys = public_keys.iter().fold(String::new(), |mut acc, (key_id, pub_key)| {
                        let debug_key = format!("[id: {}, key_type: {}, purpose: {}, security_level: {}, contract_bounds: {}, read_only: {}, data: {}, disabled_at: {}]",
                                                pub_key.id(), pub_key.key_type(), pub_key.purpose(), pub_key.security_level(),
                                                pub_key.contract_bounds().map_or("None".to_string(), |b| match b {
                                                    ContractBounds::SingleContract { id } => format!("SingleContract({})", id.to_buffer().to_lower_hex_string()),
                                                    ContractBounds::SingleContractDocumentType { id,  document_type_name} => format!("SingleContractDocumentType({}, {})", id.to_buffer().to_lower_hex_string(), document_type_name),
                                                }), pub_key.read_only(), pub_key.data().0.to_lower_hex_string(), pub_key.disabled_at().map_or("None".to_string(), |p| p.to_string()));
                        acc.push_str(format!("{}:{}", *key_id, debug_key).as_str());
                        acc
                    });
                    println!("{self:?} Ok::monitor_for_key_hashes -> key_hash: {}: identity: [id: {}, balance: {}, revision: {}, public_keys: {}]", key_hash.to_lower_hex_string(), identity.balance(), identity.revision(), identity_id.to_buffer().to_lower_hex_string(), debug_keys);
                    identities.insert(key_hash, identity);
                },
                Ok(None) => {
                    println!("{self:?} None::monitor_for_key_hashes -> key_hash: {}: identity: None", key_hash.to_lower_hex_string());
                }
                Err(error) => {
                    println!("{self:?} Error::monitor_for_key_hashes -> key_hash: {}: error: {:?}", key_hash.to_lower_hex_string(), error);
                }
            }
        }
        Ok(identities)
    }

}

// TODO: Here we have ugly thing with keys conversion.
// TODO: We should rework this to replace KeyKind with KeyType,
// TODO: but for now it's not easy to do

#[ferment_macro::export]
pub fn identity_registration_public_key(index: u32, public_key: OpaqueKey) -> IdentityPublicKey {
    IdentityPublicKey::V0(IdentityPublicKeyV0 {
        id: index,
        purpose: Purpose::AUTHENTICATION,
        security_level: SecurityLevel::MASTER,
        contract_bounds: None,
        key_type: KeyType::ECDSA_SECP256K1,
        read_only: false,
        data: BinaryData(public_key.public_key_data()),
        disabled_at: None,
    })
}

#[ferment_macro::export]
pub fn identity_public_key(index: u32, public_key: OpaqueKey, security_level: SecurityLevel, purpose: Purpose) -> IdentityPublicKey {
    IdentityPublicKey::V0(IdentityPublicKeyV0 {
        id: index,
        purpose,
        security_level,
        contract_bounds: None,
        key_type: KeyType::ECDSA_SECP256K1,
        read_only: false,
        data: BinaryData(public_key.public_key_data()),
        disabled_at: None,
    })
}

#[ferment_macro::export]
pub fn opaque_key_from_identity_public_key(public_key: IdentityPublicKey) -> Result<OpaqueKey, KeyError> {
    let public_key_data = public_key.data();
    match public_key.key_type() {
        KeyType::ECDSA_SECP256K1 =>
            ECDSAKey::key_with_public_key_data(public_key_data.as_slice())
                .map(OpaqueKey::ECDSA),
        KeyType::BLS12_381 => {
            <Vec<u8> as TryInto<[u8; 48]>>::try_into(public_key_data.to_vec())
                .map_err(|_e| KeyError::WrongLength(public_key_data.len()))
                .map(|pubkey| BLSKey::key_with_public_key(pubkey, false))
                .map(OpaqueKey::BLS)
        }
        key_type => Err(KeyError::Any(format!("unsupported type of key: {}", key_type))),
    }
}
#[ferment_macro::export]
pub fn security_level_to_index(level: SecurityLevel) -> u8 {
    match level {
        SecurityLevel::MASTER => 0,
        SecurityLevel::CRITICAL => 1,
        SecurityLevel::HIGH => 2,
        SecurityLevel::MEDIUM => 3,
    }
}
#[ferment_macro::export]
pub fn security_level_from_index(index: u8) -> SecurityLevel {
    match index {
        0 => SecurityLevel::MASTER,
        1 => SecurityLevel::CRITICAL,
        2 => SecurityLevel::HIGH,
        3 => SecurityLevel::MEDIUM,
        _ => panic!("Invalid security level index: {index}"),
    }
}

#[ferment_macro::export]
pub fn purpose_to_index(purpose: Purpose) -> u8 {
    match purpose {
        Purpose::AUTHENTICATION => 0,
        Purpose::ENCRYPTION => 1,
        Purpose::DECRYPTION => 2,
        Purpose::TRANSFER => 3,
        Purpose::SYSTEM => 4,
        Purpose::VOTING => 5,
        Purpose::OWNER => 6
    }
}
#[ferment_macro::export]
pub fn purpose_from_index(index: u8) -> Purpose {
    match index {
        0 => Purpose::AUTHENTICATION,
        1 => Purpose::ENCRYPTION,
        2 => Purpose::DECRYPTION,
        3 => Purpose::TRANSFER,
        4 => Purpose::SYSTEM,
        5 => Purpose::VOTING,
        6 => Purpose::OWNER,
        _ => panic!("Invalid purpose index: {index}"),
    }
}

#[ferment_macro::export]
pub fn key_type_from_opaque_key(opaque_key: OpaqueKey) -> Result<KeyType, KeyError> {
    match opaque_key {
        OpaqueKey::ECDSA(_) => Ok(KeyType::ECDSA_SECP256K1),
        OpaqueKey::BLS(_) => Ok(KeyType::BLS12_381),
        OpaqueKey::ED25519(_) => Ok(KeyType::EDDSA_25519_HASH160)
    }
}
#[ferment_macro::export]
pub fn key_kind_from_key_type(key_type: KeyType) -> KeyKind {
    match key_type {
        KeyType::ECDSA_SECP256K1 | KeyType::ECDSA_HASH160 | KeyType::BIP13_SCRIPT_HASH => KeyKind::ECDSA,
        KeyType::BLS12_381 => KeyKind::BLSBasic,
        KeyType::EDDSA_25519_HASH160 => KeyKind::ED25519
    }
}
#[ferment_macro::export]
pub fn key_kind_to_key_type_index(kind: KeyKind) -> u8 {
    match kind {
        KeyKind::ECDSA => 0,
        KeyKind::BLS | KeyKind::BLSBasic => 1,
        KeyKind::ED25519 => 4,
    }
}

#[ferment_macro::export]
pub fn opaque_key_to_key_type_index(opaque_key: OpaqueKey) -> u8 {
    match opaque_key {
        OpaqueKey::ECDSA(_) => 0,
        OpaqueKey::BLS(_) => 1,
        OpaqueKey::ED25519(_) => 4
    }
}
