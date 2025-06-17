pub mod identity;
pub mod provider;
pub mod signer;
pub mod thread_safe_context;
pub mod error;
pub mod util;
pub mod contract;
pub mod document;
pub mod models;
pub mod query;
pub mod transition;
pub mod cache;
mod wallet_cache;
mod notifications;

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::c_void;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use bitflags::bitflags;
use dapi_grpc::core::v0::GetTransactionRequest;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::{dpp, RequestSettings, Sdk, SdkBuilder};
use dash_sdk::dapi_client::{Address, AddressListError, DapiRequestExecutor};
use dash_sdk::platform::{Fetch, FetchMany, FetchUnproved};
use dash_sdk::platform::transition::put_contract::PutContract;
use dash_sdk::platform::transition::broadcast::BroadcastStateTransition;
use dash_sdk::platform::transition::put_document::PutDocument;
use dash_sdk::platform::transition::put_identity::PutIdentity;
use dash_sdk::platform::transition::put_settings::PutSettings;
use dash_sdk::platform::transition::waitable::Waitable;
use dash_sdk::platform::types::evonode::EvoNode;
use dash_sdk::platform::types::identity::PublicKeyHash;
use dash_sdk::sdk::AddressList;
use dashcore::blockdata::transaction::Transaction;
use dashcore::consensus::Decodable;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::{hash160, Hash};
use dashcore::prelude::DisplayHex;
use data_contracts::SystemDataContract;
use dpp::data_contract::{DataContract, DataContractFacade};
use dpp::data_contract::accessors::v0::{DataContractV0Getters, DataContractV0Setters};
use dpp::data_contract::created_data_contract::CreatedDataContract;
use dpp::data_contract::document_type::{DocumentType, DocumentTypeRef};
use dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dpp::data_contracts;
use dpp::errors::ProtocolError;
use dpp::identity::{Identity, IdentityFacade, Purpose};
use dpp::identity::identity_public_key::{IdentityPublicKey, KeyID, KeyType, SecurityLevel};
use dpp::document::{Document, DocumentV0Getters};
use dpp::document::document_factory::DocumentFactory;
use dpp::errors::consensus::basic::BasicError;
use dpp::errors::consensus::ConsensusError;
use dpp::identity::accessors::IdentityGettersV0;
use dpp::identity::core_script::CoreScript;
use dpp::identity::state_transition::asset_lock_proof::AssetLockProof;
use dpp::native_bls::NativeBlsModule;
use dpp::prelude::{BlockHeight, CoreBlockHeight};
use dpp::serialization::Signable;
use dpp::state_transition::state_transitions::document::batch_transition::batched_transition::document_transition_action_type::DocumentTransitionActionType;
use dpp::state_transition::state_transition_factory::StateTransitionFactory;
use dpp::state_transition::StateTransition;
use dpp::state_transition::state_transitions::identity::public_key_in_creation::IdentityPublicKeyInCreation;
use dpp::state_transition::proof_result::StateTransitionProofResult;
use dpp::tokens::token_payment_info::TokenPaymentInfo;
use dpp::withdrawal::Pooling;
use drive::query::{OrderClause, WhereClause};
use drive_proof_verifier::{ContextProvider, error::ContextProviderError};
use drive_proof_verifier::types::evonode_status::EvoNodeStatus;
use indexmap::IndexMap;
use platform_value::{Bytes32, Identifier, Value, ValueMap};
use platform_value::string_encoding::Encoding;
use platform_version::version::PlatformVersion;
use platform_version::version::v8::PLATFORM_V8;
use tokio::runtime::Runtime;
use dash_spv_chain::{ChainManager, chain::{ChainController, ChainRef}, ChainError};
use dash_spv_chain::derivation::{DerivationController, DerivationRef};
use dash_spv_chain::notification::{NotificationRef, IDENTITY_UPDATE_EVENT_KEY_UPDATE, INVITATION_DID_UPDATE_NOTIFICATION};
use dash_spv_crypto::crypto::byte_util::{Random, Reversed, Zeroable};
use dash_spv_crypto::derivation::{IIndexPath, IndexPath, BIP32_HARD};
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;
use dash_spv_crypto::keys::{DeriveKey, ECDSAKey, IKey, KeyError, OpaqueKey};
use dash_spv_crypto::network::ChainType;
use dash_spv_crypto::util::data_append::DataAppend;
use dash_spv_crypto::util::from_hash160_for_script_map;
use dash_spv_event_bus::DAPIAddressHandler;
use dash_spv_keychain::{KeyChainKey, KeyChainValue, KeychainController, KeychainRef};
use dash_spv_storage::{StorageContext, StorageRef};
use dash_spv_storage::controller::StorageController;
use dash_spv_storage::predicate::Predicate;
use crate::cache::PlatformCache;
use crate::contract::manager::ContractsManager;
use crate::document::contact_request::{ContactRequestManager, CONTACT_REQUEST_SETTINGS, DAPI_DOCUMENT_RESPONSE_COUNT_LIMIT};
use crate::document::manager::{DocumentsManager, PROFILE_SETTINGS, USERNAME_SETTINGS};
use crate::document::salted_domain_hashes::SaltedDomainHashesManager;
use crate::document::usernames::{UsernameStatus, UsernamesManager};
use crate::error::Error;
use crate::identity::callback::IdentityCallbacks;
use crate::identity::controller::{IdentityController, SaveIdentity};
use crate::identity::invitation::InvitationModel;
use crate::identity::key_info::KeyInfo;
use crate::identity::key_status::IdentityKeyStatus;
use crate::identity::manager::{identity_registration_public_key, key_type_from_opaque_key, IdentitiesManager, DEFAULT_FETCH_IDENTITY_RETRY_COUNT};
use crate::identity::model::{domains_for_username_full_paths, AssetLockSubmissionError, IdentityModel, DEFAULT_PROFILE_REGISTRATION_PURPOSE, DEFAULT_PROFILE_REGISTRATION_SECURITY_LEVEL, DEFAULT_USERNAME_REGISTRATION_PURPOSE, DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL};
use crate::identity::query_step::QueryStep;
use crate::identity::registration_step::RegistrationStep;
use crate::identity::username_registration_error::UsernameRegistrationError;
use crate::models::contact_request::ContactRequest;
use crate::models::profile::ProfileModel;
use crate::models::transient_dashpay_user::TransientDashPayUser;
use crate::notifications::{IdentityDidUpdate, InvitationDidUpdate};
use crate::provider::PlatformProvider;
use crate::query::QueryKind;
use crate::signer::CallbackSigner;
use crate::thread_safe_context::FFIThreadSafeContext;
use crate::transition::registration_model::RegistrationTransitionModel;
use crate::wallet_cache::WalletCache;

pub const WALLET_BLOCKCHAIN_USERS_KEY: &str = "WALLET_BLOCKCHAIN_USERS_KEY";
pub const IDENTITY_INDEX_KEY: &str = "IDENTITY_INDEX_KEY";
pub const IDENTITY_LOCKED_OUTPUT_KEY: &str = "IDENTITY_LOCKED_OUTPUT_KEY";

const DEFAULT_TESTNET_ADDRESS_LIST: [&str; 19] = [
    "34.214.48.68",
    // "35.166.18.166",
    // "35.165.50.126",
    "52.42.202.128",
    "52.12.176.90",
    // "44.233.44.95",
    // "35.167.145.149",
    "52.34.144.50",
    "44.240.98.102",
    "54.201.32.131",
    // "52.10.229.11",
    "52.13.132.146",
    "44.228.242.181",
    "35.82.197.197",
    // "52.40.219.41",
    // "44.239.39.153",
    "54.149.33.167",
    "35.164.23.245",
    "52.33.28.47",
    // "52.43.86.231",
    "52.43.13.92",
    "35.163.144.230",
    "52.89.154.48",
    "52.24.124.162",
    "44.227.137.77",
    // "35.85.21.179",
    "54.187.14.232",
    // "54.68.235.201",
    "52.13.250.182",
    // "35.82.49.196",
    // "44.232.196.6",
    // "54.189.164.39",
    // "54.213.204.85"
];
pub const MAINNET_ADDRESS_LIST: [&str; 158] = [
    "149.28.241.190", "216.238.75.46", "134.255.182.186", "66.245.196.52", "178.157.91.186", "157.66.81.162", "213.199.34.250", "157.90.238.161", "5.182.33.231", "185.198.234.68", "37.60.236.212", "207.244.247.40", "45.32.70.131", "158.220.122.76", "52.33.9.172", "185.158.107.124", "185.198.234.17", "93.190.140.101", "194.163.153.225", "194.146.13.7", "93.190.140.112", "75.119.132.2", "65.108.74.95", "44.240.99.214", "5.75.133.148", "192.248.178.237", "95.179.159.65", "139.84.232.129", "37.60.243.119", "194.195.87.34", "46.254.241.7", "45.77.77.195", "65.108.246.145", "64.176.10.71", "158.247.247.241", "37.60.244.220", "2.58.82.231", "139.180.143.115", "185.198.234.54", "213.199.44.112", "37.27.67.154", "134.255.182.185", "86.107.168.28", "139.84.137.143", "173.212.239.124", "157.10.199.77", "5.189.186.78", "139.84.170.10", "173.249.53.139", "37.60.236.151", "37.27.67.159", "104.200.24.196", "37.60.236.225", "172.104.90.249", "57.128.212.163", "37.60.236.249", "158.220.122.74", "185.198.234.25", "148.113.201.221", "134.255.183.250", "185.192.96.70", "134.255.183.248", "52.36.102.91", "134.255.183.247", "49.13.28.255", "168.119.102.10", "86.107.168.44", "49.13.237.193", "37.27.83.17", "134.255.182.187", "142.132.165.149", "193.203.15.209", "38.242.198.100", "192.175.127.198", "37.27.67.163", "79.137.71.84", "198.7.115.43", "70.34.206.123", "163.172.20.205", "65.108.74.78", "108.61.165.170", "157.10.199.79", "31.220.88.116", "185.166.217.154", "37.27.67.164", "31.220.85.180", "161.97.170.251", "157.10.199.82", "91.107.226.241", "167.88.169.16", "216.238.99.9", "62.169.17.112", "52.10.213.198", "149.28.201.164", "198.7.115.38", "37.60.236.161", "49.13.193.251", "46.254.241.9", "65.108.74.75", "192.99.44.64", "95.179.241.182", "95.216.146.18", "185.194.216.84", "31.220.84.93", "185.197.250.227", "149.28.247.165", "86.107.168.29", "213.199.34.251", "108.160.135.149", "185.198.234.12", "87.228.24.64", "45.32.52.10", "91.107.204.136", "64.176.35.235", "167.179.90.255", "157.66.81.130", "157.10.199.125", "46.254.241.8", "49.12.102.105", "134.255.182.189", "81.17.101.141", "65.108.74.79", "64.23.134.67", "54.69.95.118", "158.220.122.13", "49.13.154.121", "75.119.149.9", "93.190.140.111", "93.190.140.114", "195.201.238.55", "135.181.110.216", "45.76.141.74", "65.21.145.147", "50.116.28.103", "188.245.90.255", "130.162.233.186", "65.109.65.126", "188.208.196.183", "178.157.91.184", "37.60.236.201", "95.179.139.125", "213.199.34.248", "178.157.91.178", "213.199.35.18", "213.199.35.6", "37.60.243.59", "37.27.67.156", "37.60.236.247", "159.69.204.162", "46.254.241.11", "173.199.71.83", "185.215.166.126", "91.234.35.132", "157.66.81.218", "213.199.35.15", "114.132.172.215", "93.190.140.162", "65.108.74.109"
];
fn create_sdk<C: ContextProvider + 'static, T: IntoIterator<Item = Address>>(provider: C, address_list: T) -> Sdk {
    SdkBuilder::new(AddressList::from_iter(address_list))
        .with_context_provider(provider)
        .with_version(&PLATFORM_V8)
        .build()
        .unwrap()
}
pub const PUT_DOCUMENT_SETTINGS: PutSettings = PutSettings {
    request_settings: RequestSettings {
        connect_timeout: None,
        timeout: None,
        retries: Some(5),
        ban_failed_address: None,
    },
    identity_nonce_stale_time_s: None,
    user_fee_increase: None,
    state_transition_creation_options: None,
    wait_timeout: None,
};
const KEY_HASHES_SETTINGS: RequestSettings = RequestSettings {
    connect_timeout: Some(Duration::from_millis(20000)),
    timeout: Some(Duration::from_secs(0)),
    retries: Some(DEFAULT_FETCH_IDENTITY_RETRY_COUNT),
    ban_failed_address: None,
};
const DEFAULT_IDENTITY_SETTINGS: RequestSettings = RequestSettings {
    connect_timeout: Some(Duration::from_millis(20000)),
    timeout: Some(Duration::from_secs(0)),
    retries: Some(DEFAULT_FETCH_IDENTITY_RETRY_COUNT),
    ban_failed_address: None,
};

pub const REQUEST_SALTED_DOMAIN_HASHES_SETTINGS: RequestSettings = RequestSettings {
    connect_timeout: None,
    timeout: None,
    retries: Some(4),
    ban_failed_address: None,
};

bitflags! {
    #[derive(Copy, Clone, PartialEq, Debug)]
    pub struct PlatformSyncStateKind: u32 {
        const None = 0;
        const KeyHashes = 1;
        const Unsynced = 2;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ferment_macro::export]
pub enum PlatformSyncStateNotification {
    Start,
    Finish { timestamp: u64 },
    AddStateKind {
        kind: u32
    },
    RemoveStateKind {
        kind: u32
    },
    QueueChanged {
        count: u32,
        max_amount: u32
    }
}


#[ferment_macro::opaque]
pub struct PlatformSDK {
    pub runtime: Arc<Runtime>,
    pub chain_type: ChainType,
    pub sdk: Arc<Sdk>,
    pub chain: Arc<ChainManager>,
    pub identity_callbacks: Arc<IdentityCallbacks>,
    pub cache: PlatformCache,
    pub callback_signer: CallbackSigner,
    pub identity_manager: Arc<IdentitiesManager>,
    pub contract_manager: Arc<ContractsManager>,
    pub contact_requests: Arc<ContactRequestManager>,
    pub salted_domain_hashes: Arc<SaltedDomainHashesManager>,
    pub usernames: Arc<UsernamesManager>,
    pub doc_manager: Arc<DocumentsManager>,

    pub identities: IdentityFacade,
    pub contracts: DataContractFacade,
    pub documents: DocumentFactory,
    pub state_transition: StateTransitionFactory,


    pub get_data_contract_from_cache: Arc<dyn Fn(/*context*/*const c_void, SystemDataContract) -> DataContract>,

    // pub sign_and_publish_asset_lock_transaction: Arc<dyn Fn(*const c_void, /*topup_duff_amount*/u64, /*account_context*/ *const c_void, /*prompt*/String, /*steps*/u32) -> Result<u32, AssetLockSubmissionError>>,
    pub notify_sync_state: Arc<dyn Fn(*const c_void, Vec<PlatformSyncStateNotification>)>,

    // pub platform_client: PlatformGrpcClient
}
pub fn ip_from_bytes(address: [u8; 16]) -> Result<Address, AddressListError> {
    let addr = if address[..12] == [0; 10].to_vec() && address[10..12] == [0xFF, 0xFF] {
        Ipv4Addr::from([address[12], address[13], address[14], address[15]]).to_string()
    } else {
        Ipv6Addr::from(address).to_string()
    };

    Address::from_str(addr.as_str())
}

fn friend_request_value(to_user_id: [u8; 32], created_at: u64, encrypted_extended_public_key_data: Vec<u8>, sender_key_index: u32, recipient_key_index: u32, account_reference: u32) -> Value {
    Value::Map(Vec::from_iter([
        (Value::Text("$createdAt".to_string()), Value::U64(created_at)),
        (Value::Text("toUserId".to_string()), Value::Identifier(to_user_id.into())),
        (Value::Text("encryptedPublicKey".to_string()), Value::Bytes(encrypted_extended_public_key_data)),
        (Value::Text("senderKeyIndex".to_string()), Value::U32(sender_key_index)),
        (Value::Text("recipientKeyIndex".to_string()), Value::U32(recipient_key_index)),
        (Value::Text("accountReference".to_string()), Value::U32(account_reference)),
    ]))
}


impl DAPIAddressHandler for PlatformSDK {
    fn add_node(&self, _address: [u8; 16]) {
        // if let Ok(address) = ip_from_bytes(address) {
            // self.sdk.maybe_dapi_client().map(|dapi| dapi.address_list())
            // self.sdk.maybe_dapi_client().address_list().add(address);
            // self.sdk.address_list().add(address);
        // }
    }

    fn remove_node(&self, _address: [u8; 16]) {
        // if let Ok(address) = ip_from_bytes(address) {
        //     self.sdk.address_list().remove(&address);
        // }
    }

    fn add_nodes(&self, addresses: Vec<[u8; 16]>) {
        addresses.into_iter().for_each(|address| {
            self.add_node(address);
        })
    }

    fn remove_nodes(&self, addresses: Vec<[u8; 16]>) {
        addresses.into_iter().for_each(|address| {
            self.remove_node(address);
        })
    }
}

#[macro_export]
macro_rules! query_contract_docs {
    ($self:ident, $contract_id:ident, $document_type:ident, $query_variant:ident, $param_name:ident) => {{
        let contract = $self
            .contract_manager
            .fetch_contract_by_id_error_if_none($contract_id)
            .await?;
        let query = QueryKind::$query_variant(contract, $document_type, $param_name)?;
        $self.doc_manager.documents_with_query(query).await
    }};
}


#[ferment_macro::export]
impl PlatformSDK {

    pub fn identity_manager(&self) -> Arc<IdentitiesManager> {
        Arc::clone(&self.identity_manager)
    }
    pub fn contract_manager(&self) -> Arc<ContractsManager> {
        Arc::clone(&self.contract_manager)
    }
    pub fn doc_manager(&self) -> Arc<DocumentsManager> {
        Arc::clone(&self.doc_manager)
    }
    pub fn contact_requests(&self) -> Arc<ContactRequestManager> {
        Arc::clone(&self.contact_requests)
    }
    pub fn salted_domain_hashes(&self) -> Arc<SaltedDomainHashesManager> {
        Arc::clone(&self.salted_domain_hashes)
    }
    pub fn usernames(&self) -> Arc<UsernamesManager> {
        Arc::clone(&self.usernames)
    }

    pub async fn get_status(&self, address: &str) -> Result<bool, Error> {
        let evo_node = Address::from_str(address)
            .map_err(Error::from)
            .map(EvoNode::new)?;
        EvoNodeStatus::fetch_unproved(&self.sdk, evo_node)
            .await
            .map_err(Error::from)
            .map(|status| status.is_some())
    }

    pub async fn get_transaction_with_hash(&self, hash: [u8; 32]) -> Result<Transaction, Error> {
        let request = GetTransactionRequest { id: hash.reversed().to_lower_hex_string() };
        self.sdk.execute(request, RequestSettings::default()).await
            .map_err(Error::from)
            .map(|response| {
                let mut writer: &[u8] = &response.inner.transaction;
                let tx = Transaction::consensus_decode(&mut writer);
                tx.map_err(Error::from)
            })?
            // .map(|response| Transaction::consensus_decode(&*response.inner.transaction).map_err(Error::from))?
    }

    // pub async fn get_best_block_height(&self) -> Result<u32, Error> {
    //     let request = GetBestBlockHeightRequest {};
    //     self.sdk.execute(request, RequestSettings::default()).await
    //         .map_err(Error::from)
    //         .map(|response| {
    //             response.inner.height
    //             // let mut writer: &[u8] = &response.inner;
    //             // // let tx = Transaction::consensus_decode(&mut writer);
    //             // tx.map_err(Error::from)
    //         })?
    //
    // }

    pub async fn check_ping_times_for_current_masternode_list(&self) {

    }
    pub async fn put_document(
        &self,
        contract_id: Identifier,
        document_type: &str,
        document: Document,
        identity_public_key: IdentityPublicKey,
        block_height: BlockHeight,
        core_block_height: CoreBlockHeight
    ) -> Result<Document, Error> {
        let contract = self.contract_manager.fetch_contract_by_id_error_if_none(contract_id).await?;
        self.doc_manager.put_document(document, document_type, block_height, core_block_height, contract, identity_public_key, &self.callback_signer).await
    }
    pub async fn publish_document<'a>(&self, document_type: DocumentTypeRef<'a>, identity_public_key: IdentityPublicKey, value: Value, owner_id: Identifier, entropy: [u8; 32]) -> Result<Document, Error> {
        let debug_string = format!("[PlatformSDK] {} Publish Document: ", owner_id.to_string(Encoding::Hex));
        println!("{debug_string}: Publish document: {document_type:?}");
        let document = document_type.create_document_from_data(value, owner_id, 0, 0, entropy, self.sdk_version())
            .map_err(Error::from)?;
        println!("{debug_string}: Publish document: {document:?}");
        let state_transition = document.put_to_platform(
            self.sdk_ref(),
            document_type.to_owned_document_type(),
            entropy,
            identity_public_key,
            None,
            &self.callback_signer,
            Some(PUT_DOCUMENT_SETTINGS)
        ).await?;
        println!("{debug_string}: Wait for response: {state_transition:?}");
        Document::wait_for_response(self.sdk_ref(), state_transition, Some(PUT_DOCUMENT_SETTINGS)).await.map_err(Error::from)
    }

    pub async fn dpns_domain_starts_with(&self, contract_id: Identifier, document_type: &str, starts_with: &str) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        query_contract_docs!(self, contract_id, document_type, dpns_domain, starts_with)
    }
    pub async fn dpns_domain_by_id(&self, contract_id: Identifier, document_type: &str, unique_id: Identifier) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        query_contract_docs!(self, contract_id, document_type, records_identity, unique_id)
    }
    pub async fn dpns_usernames(&self, contract_id: Identifier, document_type: &str, usernames: Vec<String>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let usernames_ref = &usernames.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        // TODO: ferment fails with ['a ['a str]]
        query_contract_docs!(self, contract_id, document_type, usernames, usernames_ref)
    }
    pub async fn find_username(&self, contract_id: Identifier, document_type: &str, starts_with: &str) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        query_contract_docs!(self, contract_id, document_type, dpns_domain, starts_with)
    }

    pub async fn publish_contract(&self, contract: DataContract, identity_public_key: IdentityPublicKey) -> Result<DataContract, Error> {
        contract.put_to_platform_and_wait_for_response(&self.sdk, identity_public_key, &self.callback_signer, None)
            .await
            .map_err(Error::from)
    }

    pub fn identity_topup_signed_transition(&self, identity_id: [u8; 32], proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        let transition = self.identities.create_identity_topup_transition(Identifier::from(identity_id), proof)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::IdentityTopUp, transition, private_key)
    }
    pub fn identity_withdraw_signed_transition(&self, identity_id: [u8; 32], amount: u64, fee: u32, pooling: Pooling, private_key: OpaqueKey, script: Option<Vec<u8>>, nonce: u64) -> Result<StateTransition, Error> {
        let transition = self.identities.create_identity_credit_withdrawal_transition(Identifier::from(identity_id), amount, fee, pooling, script.map(CoreScript::from), nonce)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::IdentityCreditWithdrawal, transition, private_key)
    }
    pub fn identity_update_signed_transition(&self, identity: Identity, nonce: u64, add_public_keys: Option<Vec<IdentityPublicKeyInCreation>>, disable_key_ids: Option<Vec<KeyID>>, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        let transition = self.identities.create_identity_update_transition(identity, nonce, add_public_keys, disable_key_ids)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::IdentityUpdate, transition, private_key)
    }
    pub fn identity_transfer_signed_transition(&self, identity: Identity, recipient_id: [u8; 32], amount: u64, nonce: u64, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        let transition = self.identities.create_identity_credit_transfer_transition(&identity, Identifier::from(recipient_id), amount, nonce)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::IdentityCreditTransfer, transition, private_key)
    }

    pub fn data_contract_create_signed_transition(&self, owner_id: [u8; 32], nonce: u64, documents: Value, config: Option<Value>, definitions: Option<Value>, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        let created = self.contracts.create(Identifier::from(owner_id), nonce, documents, config, definitions).map_err(Error::from)?;
        let transition = self.contracts.create_data_contract_create_transition(created)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::DataContractCreate, transition, private_key)
    }
    pub fn data_contract_create_signed_transition2(&self, system_contract: SystemDataContract, owner_id: [u8; 32], nonce: u64, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        let mut data_contract = self.contract_manager().load_system_contract(system_contract);
        data_contract.set_owner_id(Identifier::from(owner_id));
        let created = CreatedDataContract::from_contract_and_identity_nonce(
            data_contract,
            nonce,
            self.sdk_version(),
        ).map_err(Error::from)?;
        let transition = self.contracts.create_data_contract_create_transition(created)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::DataContractCreate, transition, private_key)
    }
    pub fn data_contract_update_signed_transition(&self, data_contract: DataContract, nonce: u64, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        let transition = self.contracts.create_data_contract_update_transition(data_contract, nonce)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::DataContractUpdate, transition, private_key)
    }

    #[cfg(feature = "state-transitions")]
    pub fn document_batch_signed_transition<'a>(
        &self,
        documents: HashMap<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef<'a>, Bytes32, Option<TokenPaymentInfo>)>>,
        private_key: OpaqueKey,
    ) -> Result<StateTransition, Error> {
        let mut nonce_counter = BTreeMap::<(Identifier, Identifier), u64>::new();
        let transition = self.documents.create_state_transition(documents, &mut nonce_counter)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::Batch, transition, private_key)
    }

    pub fn add_wallet_if_not_exist(&mut self, wallet_id: &str) -> bool {
        if self.cache.wallets.contains_key(wallet_id) {
            return false
        }
        self.cache.wallets.insert(wallet_id.to_string(), WalletCache::new(wallet_id.to_string(), Arc::clone(&self.chain), Arc::clone(&self.identity_callbacks)));
        true
    }

    pub fn create_new_ecdsa_auth_key_if_need(&self, controller: &mut IdentityController, level: SecurityLevel, save_key: bool) -> Result<u32, Error> {
        if let Some(index) = controller.model.first_index_of_ecdsa_key_with_security_level(level) {
            Ok(index)
        } else if let Some(ref wallet_id) = controller.model.wallet_id() {
            let identity_id = controller.model.unique_id;
            let derivation_path_kind = DerivationPathKind::IdentityECDSA;
            let derivation_path = self.chain.get_derivation_path(wallet_id, derivation_path_kind);
            let key_id = controller.model.keys_created() as u32;
            println!("create_new_ecdsa_auth_key_if_need: level: {} save: {}", level, save_key);
            let identity_index = controller.model.index;
            let hardened_key_index = key_id | BIP32_HARD;
            let hardened_index_path_indexes = vec![identity_index | BIP32_HARD, hardened_key_index];
            let hardened_index_path = IndexPath::index_path_with_indexes(hardened_index_path_indexes);
            let key = self.chain.derivation.wallet_based_extended_private_key_location_string(derivation_path);
            let keychain_key = KeyChainKey::GetDataBytesKey { key };
            if let Ok(KeyChainValue::Bytes(extended_private_key_data)) = self.chain.keychain.get(keychain_key) {
                let private_key = ECDSAKey::key_with_extended_private_key_data(&extended_private_key_data)
                    .map_err(Error::KeyError)?;
                let derived_key = private_key.private_derive_to_path(&hardened_index_path)
                    .map_err(Error::KeyError)?;
                let derived_public_key_data = derived_key.public_key_data();
                let public_key = ECDSAKey::key_with_public_key_data(&derived_public_key_data)
                    .map_err(Error::KeyError)?;
                let public_key_data = public_key.public_key_data();
                let equal = derived_public_key_data.eq(&public_key_data);
                if !equal {
                    return Err(Error::KeyError(KeyError::Any("Private keys should be equal".to_string())))
                }
                let key_info = KeyInfo::registering(OpaqueKey::ECDSA(public_key), level, Purpose::AUTHENTICATION);
                controller.model.add_key_info(key_id, key_info);
                if save_key && !controller.model.is_transient() && self.cache.has_active_identity(&controller.model) {

                    let private_key_data = derived_key.private_key_data()
                        .map_err(Error::KeyError)?;

                    let key_path_entity_count = self.storage_ref()
                        .count(
                            Predicate::KeyPathContext {
                                wallet_id: wallet_id.clone(),
                                identity_id,
                                derivation_path_kind: derivation_path_kind.to_index(),
                                index_path: hardened_index_path.indexes().clone()
                            },
                            StorageContext::View
                        )
                        .map_err(Error::StorageError)?;
                    if key_path_entity_count > 0 {
                        return Ok(key_id);
                    }
                    controller.callbacks.save(
                        controller.model.context_type.clone(),
                        StorageContext::View,
                        SaveIdentity::NewKey {
                            identity_id,
                            derivation_path_kind: derivation_path_kind.to_index(),
                            index_path: hardened_index_path.indexes.clone(),
                            key_type: 0,
                            public_key_data,
                            key_status: IdentityKeyStatus::Registering.to_index(),
                            key_id,
                            security_level: level as u8,
                            purpose: Purpose::AUTHENTICATION as u8,
                        });

                    let keychain_key = KeyChainKey::GetDataBytesKey { key: format!("{}-{}-{}.{}", controller.model.unique_id_string(), self.chain.derivation.standalone_extended_public_key_unique_id(derivation_path), identity_index, key_id) };
                    let keychain_value = KeyChainValue::Bytes(private_key_data);
                    self.chain.keychain_ref().set(keychain_key, keychain_value, true)
                        .map_err(Error::KeychainError)?;

                    self.chain.notification_ref()
                        .identity_did_update(ferment::boxed(IdentityDidUpdate::new(self.chain_type.clone(), controller.model.clone(), vec![IDENTITY_UPDATE_EVENT_KEY_UPDATE])) as *mut c_void);
                }

                Ok(key_id)
            } else {
                Err(Error::Any(0, format!("failed to get extended private key for wallet: {}", wallet_id)))
            }
        } else {
            Err(Error::Any(0, format!("no wallet for identity: {}", controller.model.unique_id().to_lower_hex_string())))
        }
    }

    /// Publish state transition
    pub async fn create_and_publish_registration_transition(
        &self,
        controller: &mut IdentityController,
        registration_model: RegistrationTransitionModel,
        storage_context: StorageContext,
    ) -> Result<bool, Error> {
        let debug_string = format!("[PlatformSDK] {} register identity", controller.log_prefix());
        let asset_lock_tx_id = registration_model.asset_lock_tx_id();
        println!("{debug_string}: asset_lock_tx_id: {} ({:?}) is_lock_tx_id: {}", asset_lock_tx_id.to_string(), registration_model.transaction_model.transaction, registration_model.instant_lock.as_ref().map(|tx| tx.txid.to_string()).unwrap_or_default());

        if !controller.model.has_registration_funding_private_key() {
            return Err(Error::Any(500, "The blockchain identity funding private key should be first created with createFundingPrivateKeyWithCompletion".to_string()))
        }
        //let index = controller.first_index_of_ecdsa_auth_key_create_if_needed(SecurityLevel::MASTER, !registration_model.is_transient)?;


        let index = self.create_new_ecdsa_auth_key_if_need(controller, SecurityLevel::MASTER, !registration_model.is_transient)?;



        println!("{debug_string}: index: {}", index);
        if (index & !BIP32_HARD) != 0 {
            return Err(Error::Any(0, "The index should be 0 here".to_string()));
        }

        if let Some(InstantLock { txid, ..}) = &registration_model.instant_lock {
            if !asset_lock_tx_id.eq(txid) {
                return Err(Error::Any(0, format!("isd tx id {} doesnt't match with {}", txid.to_string(), asset_lock_tx_id.to_string())));
            }
        }

        let proof = match &registration_model.instant_lock {
            Some(..) => {
                AssetLockProof::Instant(registration_model.create_instant_proof())
            }
            None => {
                AssetLockProof::Chain(registration_model.create_chain_proof())
            }
        };
        let opaque_private_key = controller.model.registration_funding_private_key()
            .ok_or(Error::Any(0, "The registration funding private key should be set".to_string()))?;
        let opaque_public_key = controller.model.key_at_index(index)
            .ok_or(Error::Any(0, format!("The public key at index:{} should be set", index)))?;

        let private_key = opaque_private_key.convert_opaque_key_to_ecdsa_private_key(&self.chain_type).map_err(Error::KeyError)?;
        let public_key = identity_registration_public_key(index, opaque_public_key);
        let public_keys = BTreeMap::from_iter([(index, public_key.clone())]);
        let proof_id = proof.create_identifier().map_err(Error::from)?;
        let identity = Identity::new_with_id_and_keys(proof_id, public_keys.clone(), self.sdk_version()).map_err(Error::from)?;
        println!("{debug_string}: sdk: {:p} identity: {:p} {identity:?} model: {:p} proof: {:p} {proof:?} private_key: {:p} signer: {:p}", self.sdk_ref(), &identity, controller, &proof, &private_key, &self.callback_signer);
        let state_transition = identity.put_to_platform(self.sdk_ref(), proof, &private_key, &self.callback_signer, Some(PUT_DOCUMENT_SETTINGS)).await.map_err(Error::from)?;
        println!("{debug_string}: state_transition: {:p} {:?}", &state_transition, state_transition);
        let result = Identity::wait_for_response(self.sdk_ref(), state_transition, Some(PUT_DOCUMENT_SETTINGS)).await;
        println!("{debug_string}: result: {:?}", result);
        match result {
            Ok(identity) => {
                let is_active = self.cache.has_active_identity(&controller.model);
                controller.update_with_state_information(identity, is_active, storage_context)?;
                Ok(true)
            }
            Err(dash_sdk::Error::Protocol(ProtocolError::ConsensusError(ref err))) => {
                if let ConsensusError::BasicError(BasicError::InvalidInstantAssetLockProofSignatureError(err)) = &**err {
                    println!("{} ==> try with chain lock proof", err);
                    let proof = AssetLockProof::Chain(registration_model.create_chain_proof());
                    let proof_id = proof.create_identifier().map_err(Error::from)?;
                    let identity = Identity::new_with_id_and_keys(proof_id, public_keys.clone(), self.sdk_version()).map_err(Error::from)?;
                    let state_transition = identity.put_to_platform(self.sdk_ref(), proof, &private_key, &self.callback_signer, Some(PUT_DOCUMENT_SETTINGS)).await.map_err(Error::from)?;
                    let identity = Identity::wait_for_response(self.sdk_ref(), state_transition, Some(PUT_DOCUMENT_SETTINGS)).await.map_err(Error::from)?;
                    let is_active = self.cache.has_active_identity(&controller.model);
                    controller.update_with_state_information(identity, is_active, storage_context)?;
                    Ok(true)
                } else {
                    Err(Error::DashSDKError(format!("{err:?}")))
                }
            },
            Err(e) => Err(Error::from(e))
        }
    }

    pub async fn identity_topup(&self, identity_id: [u8; 32], proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("identity_topup: {} -- {proof:?} -- {private_key:?}", identity_id.to_lower_hex_string());
        let signed_transition = self.identity_topup_signed_transition(identity_id, proof, private_key)?;
        self.publish_state_transition(signed_transition).await
    }
    pub async fn identity_withdraw(&self, identity_id: [u8; 32], amount: u64, fee: u32, pooling: Pooling, private_key: OpaqueKey, script: Option<Vec<u8>>, nonce: u64) -> Result<StateTransitionProofResult, Error> {
        println!("identity_withdraw: {} -- {amount} {fee} {pooling:?} {private_key:?} -- {} -- {nonce}", identity_id.to_lower_hex_string(), script.as_ref().map_or("None".to_string(), |s| s.to_lower_hex_string()));
        let signed_transition = self.identity_withdraw_signed_transition(identity_id, amount, fee, pooling, private_key, script, nonce)?;
        self.publish_state_transition(signed_transition).await
    }

    pub async fn identity_update(&self, identity: Identity, nonce: u64, add_public_keys: Option<Vec<IdentityPublicKeyInCreation>>, disable_key_ids: Option<Vec<KeyID>>, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("identity_update: {identity:?} -- {nonce} -- {add_public_keys:?} -- {disable_key_ids:?} -- {private_key:?}");
        let signed_transition = self.identity_update_signed_transition(identity, nonce, add_public_keys, disable_key_ids, private_key)?;
        self.publish_state_transition(signed_transition).await
    }
    pub async fn identity_transfer(&self, identity: Identity, recipient_id: [u8; 32], amount: u64, nonce: u64, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("identity_transfer: {identity:?} -- {} -- {amount} -- {nonce} -- {private_key:?}", recipient_id.to_lower_hex_string());
        let signed_transition = self.identity_transfer_signed_transition(identity, recipient_id, amount, nonce, private_key)?;
        self.publish_state_transition(signed_transition).await
    }

    pub async fn data_contract_create(&self, owner_id: [u8; 32], nonce: u64, documents: Value, config: Option<Value>, definitions: Option<Value>, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("data_contract_create: {} -- {nonce} -- {documents:?} -- {config:?} -- {definitions:?} -- {private_key:?}", owner_id.to_lower_hex_string());
        let signed_transition = self.data_contract_create_signed_transition(owner_id, nonce, documents, config, definitions, private_key)?;
        self.publish_state_transition(signed_transition).await
    }
    pub async fn data_contract_create2(&self, system_contract: SystemDataContract, owner_id: [u8; 32], nonce: u64, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("data_contract_create2: {system_contract:?} {} -- {nonce} -- {private_key:?} ", owner_id.to_lower_hex_string());
        let signed_transition = self.data_contract_create_signed_transition2(system_contract, owner_id, nonce, private_key)?;
        self.publish_state_transition(signed_transition).await
    }
    pub async fn data_contract_update(&self, data_contract: DataContract, nonce: u64, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("data_contract_update: {data_contract:?} -- {nonce} -- {private_key:?}");
        let signed_transition = self.data_contract_update_signed_transition(data_contract, nonce, private_key)?;
        self.publish_state_transition(signed_transition).await
    }

    #[cfg(feature = "state-transitions")]
    pub async fn document_single(
        &self,
        document_type: DocumentType,
        document: Document,
        entropy: [u8; 32],
        identity_public_key: IdentityPublicKey,
    ) -> Result<Document, Error> {
        println!("[PlatformSDK]: Publish single document: {document_type:?} -- {document:?} -- {}", entropy.to_lower_hex_string());
        document.put_to_platform_and_wait_for_response(self.sdk_ref(), document_type, entropy, identity_public_key, None, &self.callback_signer, Some(PUT_DOCUMENT_SETTINGS)).await
            .map_err(Error::from)
    }

    pub fn friend_request_document(
        &self,
        contract: DataContract,
        identity_id: [u8; 32],
        table_name: &str,
        created_at: u64,
        to_user_id: [u8; 32],
        encrypted_extended_public_key_data: Vec<u8>,
        sender_key_index: u32,
        recipient_key_index: u32,
        account_reference: u32,
        entropy: [u8; 32]
    ) -> Result<Document, Error> {
        let owner_id = Identifier::from(identity_id);
        let document_type = contract.document_type_for_name(table_name)
            .map_err(Error::from)?;
        let dict = friend_request_value(to_user_id, created_at, encrypted_extended_public_key_data, sender_key_index, recipient_key_index, account_reference);
        document_type.create_document_from_data(dict, owner_id, 1000, 1000, entropy, self.sdk_version())
            .map_err(Error::from)
    }

    pub async fn send_friend_request(
        &self,
        contract: DataContract,
        identity_id: [u8; 32],
        created_at: u64,
        to_user_id: [u8; 32],
        encrypted_extended_public_key_data: Vec<u8>,
        sender_key_index: u32,
        recipient_key_index: u32,
        account_reference: u32,
        entropy: [u8; 32],
        private_key: OpaqueKey
    ) -> Result<StateTransitionProofResult, Error> {
        let dict = friend_request_value(to_user_id, created_at, encrypted_extended_public_key_data, sender_key_index, recipient_key_index, account_reference);
        self.send_friend_request_with_value(contract, identity_id, dict, entropy, private_key).await
    }
    pub async fn send_friend_request_with_value(
        &self,
        contract: DataContract,
        identity_id: [u8; 32],
        value: Value,
        entropy: [u8; 32],
        private_key: OpaqueKey
    ) -> Result<StateTransitionProofResult, Error> {
        let document_type = contract.document_type_for_name("contactRequest")
            .map_err(ProtocolError::from)?;

        // self.publish_document(document_type, )

        let owner_id = Identifier::from(identity_id);
        let document = document_type.create_document_from_data(value, owner_id, 0, 0, entropy, self.sdk_version())
            .map_err(Error::from)?;
        let documents_iter = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::from_iter([(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy), None)])]);
        let signed_transition = self.document_batch_signed_transition(documents_iter, private_key)?;
        self.publish_state_transition(signed_transition).await
    }


    pub async fn sign_and_publish_profile(
        &self,
        contract: DataContract,
        controller: &mut IdentityController,
        profile_model: ProfileModel,
    ) -> Result<Document, Error> {
        let wallet_id = controller.model.wallet_id().unwrap();
        let owner_id = controller.model.owner_id();
        let debug_string = format!("[PlatformSDK] {} Sign and Publish Profile", owner_id.to_string(Encoding::Hex));
        println!("{debug_string}");
        let document_type = contract.document_type_for_name("profile")
            .map_err(ProtocolError::from)?;
        let ProfileModel { profile, document_id, entropy_data } = profile_model;
        // controller.create_new_ecdsa_auth_key_of_level_if_needed(DEFAULT_PROFILE_REGISTRATION_SECURITY_LEVEL, !self.chain.is_wallet_transient(&wallet_id))?;
        self.create_new_ecdsa_auth_key_if_need(controller, DEFAULT_PROFILE_REGISTRATION_SECURITY_LEVEL, !self.chain.is_wallet_transient(&wallet_id))?;



        let identity_public_key = controller.model.first_identity_public_key(DEFAULT_PROFILE_REGISTRATION_SECURITY_LEVEL, DEFAULT_PROFILE_REGISTRATION_PURPOSE)
            .ok_or(Error::Any(0, format!("Key with security_level: {DEFAULT_PROFILE_REGISTRATION_SECURITY_LEVEL} and purpose: {DEFAULT_PROFILE_REGISTRATION_PURPOSE} should exist")))?;

        let document = if document_id.is_zero() {
            document_type.create_document_from_data(profile.to_value(), owner_id, 0, 0, entropy_data, self.sdk_version())
        } else {
            document_type.create_document_with_prevalidated_properties(Identifier::from(document_id), owner_id, 0, 0, profile.to_prevalidated_properties(), self.sdk_version())
        }.map_err(Error::from)?;

        let state_transition = document.put_to_platform(
            self.sdk_ref(),
            document_type.to_owned_document_type(),
            entropy_data,
            identity_public_key,
            None,
            &self.callback_signer,
            Some(PUT_DOCUMENT_SETTINGS)
        ).await?;

        println!("{debug_string}: Wait for response: {state_transition:?}");
        let document = Document::wait_for_response(self.sdk_ref(), state_transition, Some(PUT_DOCUMENT_SETTINGS)).await?;
        controller.save_profile_revision(StorageContext::Platform, profile.revision);
        println!("{debug_string}: OK({document:?})");
        Ok(document)
    }

    // pub async fn check_ping_times(&self, masternodes: Vec<MasternodeEntry>) -> Result<GetStatusResponse, Error> {
    //     self.sdk_ref()
    //         .execute(GetStatusRequest::default(), RequestSettings::default())
    // }

    pub async fn register_usernames_at_stage(&self, controller: &mut IdentityController, status: UsernameStatus) -> Result<(bool, Option<UsernameStatus>), Error> {
        let username_full_paths = controller.model.username_full_paths_with_status(status);
        println!("[PlatformSDK] {} register_usernames_at_stage: {status:?}: username_full_path: {:?}", controller.log_prefix(), username_full_paths);
        if username_full_paths.is_empty() {
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoFullPathsWithStatus { status, next_status: status.next_status() } ))
        } else {
            match status {
                UsernameStatus::Initial =>
                    self.register_initial_usernames(controller, username_full_paths).await,
                UsernameStatus::PreorderRegistrationPending =>
                    self.register_preorder_registration_pending_usernames(controller, username_full_paths).await,
                UsernameStatus::Preordered =>
                    self.register_preordered_usernames(controller, username_full_paths).await,
                UsernameStatus::RegistrationPending =>
                    self.register_registration_pending_usernames(controller, username_full_paths).await,
                _ =>
                    Err(Error::UsernameRegistrationError(UsernameRegistrationError::NotSupported(status))),
            }
        }
    }

    pub async fn register_initial_usernames(&self, controller: &mut IdentityController, username_full_paths: Vec<String>) -> Result<(bool, Option<UsernameStatus>), Error> {
        let status = UsernameStatus::Initial;
        let debug_string = format!("[PlatformSDK] {} register_usernames::initial", controller.log_prefix());
        println!("{debug_string}");
        let salted_domain_hashes = controller.salted_domain_hashes_for_username_full_paths(&username_full_paths);
        if salted_domain_hashes.is_empty() {
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoPreorderDocuments { status, next_status: status.next_status(), username_full_paths } ))
        } else {
            self.create_new_ecdsa_auth_key_if_need(controller, DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL, true)?;


            let identity_public_key = controller.model.first_identity_public_key(DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL, DEFAULT_USERNAME_REGISTRATION_PURPOSE)
                .ok_or(Error::Any(0, format!("Key with security_level: {DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL} and purpose: {DEFAULT_USERNAME_REGISTRATION_PURPOSE} should exist")))?;
            let entropy = <[u8; 32]>::random();

            let data_contract = self.get_dpns_data_contract();
            let document_type = data_contract.document_type_for_name("preorder")
                .map_err(Error::from)?;
            let owner_id = controller.model.owner_id();
            println!("{debug_string}: Publish document: owner: {} ({})", owner_id.to_string(Encoding::Hex), owner_id);
            println!("{debug_string}: Publish document: entropy: {}", entropy.to_lower_hex_string());
            println!("{debug_string}: Publish {document_type:?}");
            for salted_domain_hash in salted_domain_hashes.values() {
                let map = Value::Map(ValueMap::from_iter([(Value::Text("saltedDomainHash".to_string()), Value::Bytes32(salted_domain_hash.clone()))]));
                let document = self.publish_document(document_type, identity_public_key.clone(), map, owner_id, entropy).await?;
                println!("{debug_string}: salted_domain_hash: {}: OK({document:?})", salted_domain_hash.to_lower_hex_string());
            }
            if self.cache.has_active_identity(&controller.model) {
                controller.save_confirmed_username_full_paths_if_need(username_full_paths);
            }
            Ok((true, status.next_status()))
        }
    }
    pub async fn register_preorder_registration_pending_usernames(&self, controller: &mut IdentityController, username_full_paths: Vec<String>) -> Result<(bool, Option<UsernameStatus>), Error> {
        let status = UsernameStatus::PreorderRegistrationPending;
        let debug_string = format!("[PlatformSDK] {} Register Usernames (Preorder Registration Pending)", controller.log_prefix());
        println!("{debug_string}");
        let salted_domain_hashes = controller.salted_domain_hashes_for_username_full_paths(&username_full_paths);
        if salted_domain_hashes.is_empty() {
            println!("[Identity] OK (No saltedDomainHashes)");
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoPreorderDocuments { status, next_status: status.next_status(), username_full_paths } ))
        } else {
            let mut all_found = false;
            let data_contract = self.get_dpns_data_contract();
            let query = self.salted_domain_hashes().query_preorder_salted_domain_hashes(data_contract, salted_domain_hashes.values().cloned().collect())?;
            let (documents, _) = Document::fetch_many_with_metadata(self.sdk_ref(), query, Some(REQUEST_SALTED_DOMAIN_HASHES_SETTINGS)).await?;
            for (username_full_path, salted_domain_hash) in salted_domain_hashes {
                for document in documents.values() {
                    if let Some(document) = document {
                        all_found &= controller.process_salted_domain_hash_document(&username_full_path, salted_domain_hash, document);
                    } else {
                        all_found &= false;
                    }
                }
            }
            if all_found {
                Ok((true, status.next_status()))
            } else {
                // TODO: This needs to be done per username and not for all usernames
                if self.cache.has_active_identity(&controller.model) {
                    controller.save_initial_username_full_paths_if_need(username_full_paths);
                }

                Ok((false, status.next_status()))
            }
        }
    }

    pub async fn register_preordered_usernames(&self, controller: &mut IdentityController, username_full_paths: Vec<String>) -> Result<(bool, Option<UsernameStatus>), Error> {
        let status = UsernameStatus::Preordered;
        let debug_string = format!("[PlatformSDK] {} Register Usernames (Preordered)", controller.log_prefix());
        println!("{debug_string}");
        let salted_domain_hashes = controller.salted_domain_hashes_for_username_full_paths(&username_full_paths);
        if salted_domain_hashes.is_empty() {
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoPreorderDocuments { status, next_status: status.next_status(), username_full_paths }))
        } else {
            self.create_new_ecdsa_auth_key_if_need(controller, DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL, true)?;

            let data_contract = self.get_dpns_data_contract();
            let document_type = data_contract.document_type_for_name("domain")
                .map_err(Error::from)?;
            if controller.is_local() {
                Err(Error::Any(0, "Identity is not local".to_string()))
            } else {
                let owner_id = controller.model.owner_id();
                let identity_public_key = controller.model.first_identity_public_key(DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL, DEFAULT_USERNAME_REGISTRATION_PURPOSE)
                    .ok_or(Error::Any(0, format!("Key with security_level: {DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL} and purpose: {DEFAULT_USERNAME_REGISTRATION_PURPOSE} should exist")))?;
                let entropy = <[u8; 32]>::random();
                for username_full_path in salted_domain_hashes.keys() {
                    let value = controller.model.to_salted_domain_hash_value(username_full_path);
                    let document = self.publish_document(document_type, identity_public_key.clone(), value, owner_id, entropy).await?;
                    println!("{debug_string}: salted_domain_hash: {username_full_path}: OK({document:?})");
                }
                if self.cache.has_active_identity(&controller.model) {
                    controller.save_preordered_username_full_paths_if_need(username_full_paths);
                }
                Ok((true, Some(UsernameStatus::RegistrationPending)))
            }
        }
    }

    pub async fn register_registration_pending_usernames(&self, controller: &mut IdentityController, username_full_paths: Vec<String>) -> Result<(bool, Option<UsernameStatus>), Error> {
        let status = UsernameStatus::RegistrationPending;
        let debug_string = format!("[PlatformSDK] {} Register Usernames (Registration Pending)", controller.log_prefix());
        println!("{debug_string}");
        let domains = domains_for_username_full_paths(&username_full_paths);
        let data_contract = self.get_dpns_data_contract();
        // let wallet_context = self.chain.get_wallet_by_id(controller.model.wallet_id.as_ref().unwrap().as_str());

        // let mut finished = false;
        let mut count_all_found = 0;
        let mut count_returned = 0;
        let domains_count = domains.len();
        for (domain, usernames) in domains {
            let query = self.usernames().query_usernames(data_contract.clone(), domain, usernames.clone())?;
            let (documents, _metadata) = Document::fetch_many_with_metadata(self.sdk_ref(), query, Some(USERNAME_SETTINGS)).await?;
            let mut all_domain_found = false;
            for username in usernames {
                let lowercase_username = username.to_lowercase();
                for maybe_document in documents.values() {
                    if let Some(document) = maybe_document {
                        let normalized_label = document.get("normalizedLabel").unwrap().as_text().unwrap();
                        let label = document.get("label").unwrap().as_text().unwrap();
                        let normalized_parent_domain_name = document.get("normalizedParentDomainName").unwrap().as_text().unwrap();
                        let equal = normalized_label.eq(&lowercase_username);
                        println!("[Identity]: {}: {} == {}", equal, normalized_label, lowercase_username);
                        all_domain_found &= equal;
                        if equal {
                            controller.model.set_username_status_confirmed(username.clone(), normalized_parent_domain_name.to_string(), label.to_string());
                            if self.cache.has_active_identity(&controller.model) {
                                controller.save_confirmed_username_and_domain_if_need(&username, normalized_parent_domain_name);
                            }
                        }
                    }
                }
            }
            if all_domain_found {
                count_all_found += 1;
            }
            count_returned += 1;
            if count_returned == domains_count {
                // finished = true;
                return if count_all_found == domains_count {
                    Ok((true, status.next_status()))
                } else {
                    // TODO: This needs to be done per username and not for all usernames
                    if self.cache.has_active_identity(&controller.model) {
                        controller.save_preordered_username_full_paths_if_need(username_full_paths);
                    }
                    // TODO: should we introduce progress here to not to wait this step in some circumstances
                    Ok((false, status.next_status()))
                }
            }
        }
        Ok((count_all_found == domains_count, status.next_status()))
    }

    pub async fn fetch_needed_state_information(&self, controller: &mut IdentityController, storage_context: StorageContext) -> Result<u32, Error> {
        let debug_string = format!("[PlatformSDK] {} Fetch Needed State Information", controller.log_prefix());
        println!("{debug_string}");
        let mut steps_needed = QueryStep::None;
        let has_no_active_keys = controller.model.active_key_count() == 0;
        let is_local_identity = controller.is_local();
        if (has_no_active_keys && is_local_identity) || controller.model.usernames_are_outdated() {
            steps_needed.insert(QueryStep::Username);
        }

        if has_no_active_keys {
            steps_needed.insert(QueryStep::Identity);
            if is_local_identity {
                steps_needed.insert(QueryStep::Profile | QueryStep::ContactRequests);
            } else if controller.model.profile_is_outdated() {
                steps_needed.insert(QueryStep::Profile);
            }
        } else {
            let created_at = controller.matching_dashpay_user_entity_created_at(storage_context);
            if created_at == 0 && controller.model.profile_is_outdated() {
                steps_needed.insert(QueryStep::Profile);
            }

            if is_local_identity {
                if controller.model.incoming_contacts_is_outdated() {
                    steps_needed.insert(QueryStep::IncomingContactRequests);
                }
                if controller.model.outgoing_contacts_is_outdated() {
                    steps_needed.insert(QueryStep::OutgoingContactRequests);
                }
            }
        }
        self.fetch_network_state_information(controller, steps_needed.bits(), storage_context).await
    }

    pub async fn fetch_if_needed_network_state_information(&self, controller: &mut IdentityController, query_steps: u32, storage_context: StorageContext) -> Result<u32, Error> {
        let debug_string = format!("[PlatformSDK] {} Fetch (If needed) Network State Info ({:?})", controller.log_prefix(), query_steps);
        println!("{debug_string}");
        if controller.model.active_key_count() == 0 {
            if controller.is_local() {
                self.fetch_network_state_information(controller, query_steps, storage_context).await
            } else {
                let mut steps_needed = QueryStep::Identity;
                if controller.model.usernames_are_outdated() {
                    steps_needed |= QueryStep::Username;
                }
                if controller.model.profile_is_outdated() {
                    steps_needed |= QueryStep::Profile;
                }
                self.fetch_network_state_information(controller, QueryStep::from_bits(steps_needed.bits() | query_steps).unwrap().bits(), storage_context).await
            }
        } else {
            let mut steps_needed = QueryStep::None;
            if controller.model.usernames_are_outdated() {
                steps_needed |= QueryStep::Username;
            }
            let created_at = controller.matching_dashpay_user_entity_created_at(storage_context);
            if created_at == 0 && controller.model.profile_is_outdated() {
                steps_needed |= QueryStep::Profile;
            }
            if controller.is_local() && controller.model.incoming_contacts_is_outdated() {
                steps_needed |= QueryStep::IncomingContactRequests;
            }
            if controller.is_local() && controller.model.outgoing_contacts_is_outdated() {
                steps_needed |= QueryStep::OutgoingContactRequests;
            }
            if steps_needed.is_empty() {
                Ok(0)
            } else {
                self.fetch_network_state_information(controller, QueryStep::from_bits(steps_needed.bits() | query_steps).unwrap().bits(), storage_context).await
            }
        }
    }

    pub async fn fetch_network_state_information(&self, controller: &mut IdentityController, query_steps: u32, storage_context: StorageContext) -> Result<u32, Error> {
        let query_steps = QueryStep::from_bits(query_steps).ok_or(Error::Any(0, "Invalid query step".to_string()))?;
        let debug_string = format!("[PlatformSDK] {} Fetch Network State Info ({:?})", controller.log_prefix(), query_steps);
        println!("{debug_string}");
        if query_steps.contains(QueryStep::Identity) {
            match self.fetch_identity_network_state_information(controller, storage_context).await {
                Ok((false, _)) => Ok(QueryStep::Identity.bits()),
                Ok((_, false)) => Ok(QueryStep::NoIdentity.bits()),
                Err(error) => Err(error),
                _ => self.fetch_l3_network_state_information(controller, query_steps.bits(), storage_context).await,
            }
        } else {
            self.fetch_l3_network_state_information(controller, query_steps.bits(), storage_context).await
        }
    }

    pub async fn fetch_identity_network_state_information(
        &self,
        controller: &mut IdentityController,
        storage_context: StorageContext,
    ) -> Result<(bool, bool), Error> {
        let debug_string = format!("[PlatformSDK] {} Fetch Identity State", controller.log_prefix());
        println!("{debug_string}");
        let sdk_ref = self.sdk_ref();
        let identifier: Identifier = controller.unique_id().into();
        let maybe_identity = Identity::fetch_with_settings(sdk_ref, identifier, DEFAULT_IDENTITY_SETTINGS).await?;
        match maybe_identity {
            Some(identity) => {
                let is_active = self.cache.has_active_identity(&controller.model);

                controller.update_with_state_information(identity, is_active, storage_context)?;
                println!("{}: OK", debug_string);
                Ok((true, true))
            }
            None if controller.is_local() => {
                println!("{}: None (Ok)", debug_string);
                Ok((true, false))
            },
            None => {
                println!("{}: None (Error)", debug_string);
                Err(Error::Any(0, "Identity expected here".to_string()))
            }
        }
    }

    pub async fn fetch_l3_network_state_information(&self, controller: &mut IdentityController, query_steps: u32, storage_context: StorageContext) -> Result<u32, Error> {
        let query_steps = QueryStep::from_bits(query_steps).ok_or(Error::Any(0, "Invalid query step".to_string()))?;
        let debug_string = format!("[PlatformSDK] {} Fetch L3 Network State Information", controller.log_prefix());
        println!("{debug_string}: {query_steps:?}");
        if !query_steps.contains(QueryStep::Identity) && controller.model.active_key_count() == 0 {
            println!("{debug_string}: Error: Attempting to query without keys");
            // We need to fetch keys if we want to query other information
            return Err(Error::AttemptQueryWithoutKeys);
        }
        let mut failure_step = QueryStep::None;
        let mut errors = Vec::<Error>::new();

        let mut process_step = |step: QueryStep, result: Result<bool, Error>| {
            match result {
                Ok(success) => {
                    if !success {
                        failure_step |= step;
                    }
                },
                Err(error) => {
                    failure_step |= step;
                    errors.push(error);
                }
            }
        };

        if query_steps.contains(QueryStep::Username) {
            process_step(QueryStep::Username, self.fetch_usernames(controller, self.get_dpns_data_contract()).await);
        }
        if query_steps.contains(QueryStep::Profile) {
            process_step(QueryStep::Profile, self.fetch_profile_in_context(controller, self.get_dashpay_data_contract(), storage_context).await);
        }
        if query_steps.contains(QueryStep::OutgoingContactRequests) {
            process_step(QueryStep::OutgoingContactRequests, self.fetch_outgoing_contact_requests_in_context(controller, self.get_dashpay_data_contract(), None, storage_context).await);
        }
        if query_steps.contains(QueryStep::IncomingContactRequests) {
            process_step(QueryStep::IncomingContactRequests, self.fetch_incoming_contact_requests_in_context(controller, self.get_dashpay_data_contract(), None, storage_context).await);
        }
        println!("{debug_string}: Ok({query_steps:?} / {failure_step:?})");

        Ok(failure_step.bits())
    }
    pub async fn fetch_all_identity_state_info(&self, controller: &mut IdentityController, storage_context: StorageContext) -> Result<u32, Error> {
        let debug_string = format!("[PlatformSDK] {} Fetch All Identity State Info", controller.log_prefix());
        println!("{debug_string}");
        let mut query = QueryStep::Identity | QueryStep::Username | QueryStep::Profile;
        if controller.is_local() {
            query |= QueryStep::ContactRequests;
        }
        self.fetch_network_state_information(controller, query.bits(), storage_context).await
    }

    pub async fn fetch_contact_requests_in_context(&self, controller: &mut IdentityController, storage_context: StorageContext) -> Result<bool, Error> {
        let debug_string = format!("[PlatformSDK] {} Fetch Contact Requests in context", controller.log_prefix());
        println!("{debug_string}");
        let contract = self.get_dashpay_data_contract();
        self.fetch_incoming_contact_requests_in_context(controller, contract.clone(), None, storage_context).await?;
        self.fetch_outgoing_contact_requests_in_context(controller, contract, None, storage_context).await
    }

    pub async fn continue_registering_profile_on_network<
        NotifyProgress: Fn(*const c_void, u32) + Send + Sync + Clone + 'static
    >(
        &self,
        controller: &mut IdentityController,
        steps: u32,
        steps_already_completed: u32,
        progress_handler: NotifyProgress,
        progress_context: *const c_void
    ) -> Result<u32, Error> {
        let debug_string = format!("[PlatformSDK] {} Continue: Profile: ", controller.log_prefix());
        let steps = RegistrationStep::from_bits(steps)
            .ok_or(Error::Any(0, "Invalid query step".to_string()))?;
        let mut steps_already_completed = RegistrationStep::from_bits(steps_already_completed)
            .ok_or(Error::Any(0, "Invalid completed query step".to_string()))?;
        println!("{debug_string} {steps:?} / {steps_already_completed:?}");
        if !steps.contains(RegistrationStep::Profile) {
            println!("{debug_string}: Ok(No profile step)");
            return Ok(steps_already_completed.bits());
        }

        let storage_context = StorageContext::Platform;
        let profile = controller.load_profile(storage_context)?;
        let dashpay_contract = self.get_dashpay_data_contract();
        let revision = profile.profile.revision;
        let result = self.sign_and_publish_profile(dashpay_contract, controller, profile).await?;
        println!("{}: Ok({:?})", debug_string, result);
        controller.save_profile_revision(storage_context, revision);
        steps_already_completed.insert(RegistrationStep::Profile);
        progress_handler(progress_context, RegistrationStep::Profile.bits());
        Ok(steps_already_completed.bits())
    }

    pub async fn continue_registering_usernames_on_network<
        NotifyProgress: Fn(*const c_void, u32) + Send + Sync + Clone + 'static
    >(
        &self,
        controller: &mut IdentityController,
        steps: u32,
        steps_already_completed: u32,
        progress_handler: NotifyProgress,
        progress_context: *const c_void
    ) -> Result<u32, Error> {
        let debug_string = format!("[PlatformSDK] {} Continue: Usernames:", controller.log_prefix());
        println!("{debug_string} {steps:?} / {steps_already_completed:?}");

        let steps = RegistrationStep::from_bits(steps)
            .ok_or(Error::Any(0, "Invalid registration step".to_string()))?;
        let mut steps_already_completed = RegistrationStep::from_bits(steps_already_completed)
            .ok_or(Error::Any(0, "Invalid completed registration step".to_string()))?;
        if !steps.contains(RegistrationStep::Username) {
            println!("{debug_string}: Ok(No Username step)");
            return Ok(steps_already_completed.bits());
        }
        let success = self.register_usernames(controller).await?;

        println!("{debug_string}: Ok({success})");
        if success {
            progress_handler(progress_context, RegistrationStep::Username.bits());
            steps_already_completed.insert(RegistrationStep::Username);
            self.continue_registering_profile_on_network(controller, steps.bits(), steps_already_completed.bits(), progress_handler, progress_context).await
        } else {
            Ok(steps_already_completed.bits())
        }
    }

    pub async fn register_usernames(&self, controller: &mut IdentityController) -> Result<bool, Error> {
        let debug_string = format!("[PlatformSDK] {} Register Usernames:", controller.log_prefix());
        let mut status = UsernameStatus::Initial;
        let mut last_error: Option<Error> = None;
        let success = loop {
            match self.register_usernames_at_stage(controller, status).await {
                Ok((success, Some(next_status))) => {
                    println!("{debug_string} Ok(success: {success}, next_status: {next_status:?})");
                    status = next_status;
                },
                Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoPreorderDocuments { next_status: Some(next_status), .. } |
                                                     UsernameRegistrationError::NoFullPathsWithStatus { next_status:  Some(next_status), ..})) => {
                    println!("{debug_string} Error(next_status: {next_status:?})");
                    status = next_status;
                },
                Ok((successful, None)) => {
                    println!("{debug_string} Ok({successful})");
                    break successful;
                }
                Err(err) => {
                    last_error = Some(err.clone());
                    println!("{debug_string}: Err({err:?})");
                    break false;
                }
            }
        };
        last_error.map(Err).unwrap_or(Ok(success))
    }

    pub async fn continue_registering_identity_on_network<
        NotifyProgress: Fn(*const c_void, u32) + Send + Sync + Clone + 'static
    >(
        &self,
        controller: &mut IdentityController,
        steps: u32,
        steps_already_completed: u32,
        progress_handler: NotifyProgress,
        progress_context: *const c_void
    ) -> Result<u32, Error> {
        let debug_string = format!("[PlatformSDK] {} Continue: Identity:", controller.log_prefix());
        println!("{debug_string} {steps:?} / {steps_already_completed:?}");
        let steps = RegistrationStep::from_bits(steps)
            .ok_or(Error::Any(0, "Invalid query step".to_string()))?;
        let mut steps_already_completed = RegistrationStep::from_bits(steps_already_completed)
            .ok_or(Error::Any(0, "Invalid completed query step".to_string()))?;
        if !steps.contains(RegistrationStep::Identity) {
            println!("{debug_string} Ok(No identity step)");
            return Ok(steps_already_completed.bits());
        }
        let registration_model = controller.get_registration_transition_model()
            .ok_or(Error::AssetLockTransactionShouldBeKnown)?;
        match self.create_and_publish_registration_transition(controller, registration_model, StorageContext::Platform).await {
            Ok(true) => {
                steps_already_completed.insert(RegistrationStep::Identity);
                progress_handler(progress_context, RegistrationStep::Identity.bits());
                println!("{debug_string}: Ok({steps_already_completed:?}/{steps_already_completed:?})");
                self.continue_registering_usernames_on_network(controller, steps.bits(), steps_already_completed.bits(), progress_handler, progress_context).await
            },
            Ok(false) => {
                println!("{debug_string} Ok(unsuccessful)");
                Ok(steps_already_completed.bits())
            },
            Err(error) => {
                println!("{debug_string} Error: {error:?}");
                Err(error)
            }
        }
    }

    pub async fn continue_registering_on_network<
        NotifyProgress: Fn(*const c_void, u32) + Send + Sync + Clone + 'static
    >(
        &mut self,
        controller: &mut IdentityController,
        steps: u32,
        topup_duff_amount: u64,
        // funding_account_context: *const c_void,
        prompt: String,
        storage_context: StorageContext,
        progress_handler: NotifyProgress,
        progress_context: *const c_void

    ) -> Result<u32, Error> {
        let debug_string = format!("[PlatformSDK] {} Continue:", controller.log_prefix());
        println!("{debug_string} {steps:?}");

        if controller.model.asset_lock_registration_model.is_none() {
            self.register_on_network(controller, steps, topup_duff_amount, prompt, progress_handler, progress_context).await
        } else if !controller.model.is_registered() {
            self.continue_registering_identity_on_network(controller, steps, RegistrationStep::L1Steps.bits(), progress_handler, progress_context).await
        } else if controller.model.unregistered_username_full_paths_count() > 0 {
            self.continue_registering_usernames_on_network(controller, steps, RegistrationStep::L1Steps.bits() | RegistrationStep::Identity.bits(), progress_handler, progress_context).await
        } else if controller.get_stored_remote_profile_revision(storage_context) < 1 {
            self.continue_registering_profile_on_network(controller, steps, RegistrationStep::L1Steps.bits() | RegistrationStep::Identity.bits(), progress_handler, progress_context).await
        } else {
            Ok(steps)
        }
    }

    pub async fn register_on_network<
        NotifyProgress: Fn(*const c_void, u32) + Send + Sync + Clone + 'static
    >(
        &mut self,
        controller: &mut IdentityController,
        steps: u32,
        topup_duff_amount: u64,
        // funding_account_context: *const c_void,
        prompt: String,
        progress_handler: NotifyProgress,
        progress_context: *const c_void
    ) -> Result<u32, Error> {
        let steps = RegistrationStep::from_bits(steps)
            .ok_or(Error::Any(0, "Invalid query step".to_string()))?;
        let debug_string = format!("[PlatformSDK] {} Register On Network: {steps:?}", controller.log_prefix());
        println!("{debug_string}");
        let mut steps_completed = RegistrationStep::None;

        if !controller.has_extended_public_keys() {
            println!("{debug_string}: ERROR: AttemptQueryWithoutKeys");
            return Err(Error::AttemptQueryWithoutKeys);
        }
        if !steps.contains(RegistrationStep::FundingTransactionCreation) {
            println!("{debug_string}: Ok: No FundingTransactionCreation step");
            return Ok(steps_completed.bits());
        }

        let derivation_kind = if controller.model.is_outgoing_invitation() {
            DerivationPathKind::InvitationFunding
        } else {
            DerivationPathKind::IdentityRegistrationFunding
        };
        let wallet_id = controller.model.wallet_id().ok_or(Error::CannotSignIdentityWithoutWallet)?;
        let derivation_path = self.chain.get_derivation_path(&wallet_id, derivation_kind);
        let asset_lock_registration_address = self.chain.derivation_ref().address_at_index_path(derivation_path, vec![controller.model.index()]);
        let asset_lock_registration_script = DataAppend::script_pub_key_for_address(asset_lock_registration_address.as_str(), self.chain_type.script_map_ref());
        let wallet_context = self.chain.get_wallet_by_id(&wallet_id);
        self.add_wallet_if_not_exist(&wallet_id);
        let wallet_cache = self.cache.wallets.get_mut(&wallet_id).unwrap();
        match self.chain.wallet.publish_asset_lock_transaction(wallet_context, topup_duff_amount, asset_lock_registration_script, prompt) {
            Ok(transaction_model) => {
                steps_completed.insert(RegistrationStep::FundingTransactionCreation);
                if !steps.contains(RegistrationStep::LocalInWalletPersistence) {
                    return Ok(steps_completed.bits());
                }
                let credit_burn_public_key_hash = transaction_model.maybe_credit_burn_public_key_hash()
                    .ok_or(Error::AssetLockSubmission(AssetLockSubmissionError { steps_completed: steps_completed.bits() }))?;
                let identity_id = transaction_model.credit_burn_identity_identifier();
                let locked_outpoint = transaction_model.locked_outpoint();
                controller.model.unique_id = identity_id;
                controller.model.set_locked_outpoint(Some(locked_outpoint.clone()));
                if controller.model.is_outgoing_invitation {
                    controller.model.set_asset_lock_registration_model(transaction_model);
                    let invitation = InvitationModel::with_identity(identity_id, wallet_id.clone());
                    wallet_cache.register_invitation(invitation.clone());
                    controller.save_model_in_context(StorageContext::Platform);

                    // wallet_cache.mark_address_hash_as_used(credit_burn_public_key_hash.as_byte_array(), DerivationPathKind::InvitationFunding);
                    let address = from_hash160_for_script_map(credit_burn_public_key_hash.as_byte_array(), self.chain.controller.chain_type.script_map_ref());
                    let derivation_path = self.chain.get_derivation_path(&wallet_id, DerivationPathKind::InvitationFunding);
                    self.chain.derivation_ref().mark_address_as_used(derivation_path, address);

                    self.chain.notification_ref()
                        .notify_main_thread(INVITATION_DID_UPDATE_NOTIFICATION, ferment::boxed(InvitationDidUpdate::new(self.chain_type.clone(), invitation)) as *mut c_void);

                } else {
                    controller.model.set_asset_lock_registration_hash(transaction_model.transaction.txid().to_byte_array());
                    wallet_cache.register_identity(controller.clone());
                    controller.save_model_in_context(StorageContext::Platform);
                    // wallet_cache.mark_address_hash_as_used(credit_burn_public_key_hash.as_byte_array(), DerivationPathKind::IdentityRegistrationFunding);
                    let address = from_hash160_for_script_map(credit_burn_public_key_hash.as_byte_array(), self.chain.controller.chain_type.script_map_ref());
                    let derivation_path = self.chain.get_derivation_path(&wallet_id, DerivationPathKind::IdentityRegistrationFunding);
                    self.chain.derivation_ref().mark_address_as_used(derivation_path, address);

                }
                steps_completed.insert(RegistrationStep::LocalInWalletPersistence);

                if !steps.contains(RegistrationStep::FundingTransactionAccepted) {
                    println!("{debug_string}: Ok (Asset Lock Transaction no FundingTransactionAccepted)");
                    return Ok(steps_completed.bits());
                }

                println!("{debug_string}: Ok({steps_completed:?})");
                self.continue_registering_identity_on_network(controller, steps.bits(), steps_completed.bits(), progress_handler, progress_context).await
            },
            Err(ChainError::Cancelled) => {
                steps_completed.insert(RegistrationStep::Cancelled);
                println!("{debug_string}: Cancelled");
                Ok(steps_completed.bits())
            },
            Err(ChainError::SigningError(description) | ChainError::TransactionPublishError(description)) => {
                println!("{debug_string}: {description}");
                Err(Error::AssetLockSubmission(AssetLockSubmissionError { steps_completed: steps_completed.bits() }))
            },
            Err(ChainError::InstantSendLockError(description)) => {
                println!("{debug_string}: {description}");
                steps_completed.insert(RegistrationStep::FundingTransactionCreation);
                steps_completed.insert(RegistrationStep::LocalInWalletPersistence);
                Err(Error::AssetLockSubmission(AssetLockSubmissionError { steps_completed: steps_completed.bits() }))
            }
        }
    }

    pub async fn register_on_network_with_wallet_id_and_index<
        NotifyProgress: Fn(*const c_void, u32) + Send + Sync + Clone + 'static
    >(
        &mut self,
        wallet_id: &str,
        index: u32,
        steps: u32,
        topup_duff_amount: u64,
        prompt: String,
        progress_handler: NotifyProgress,
        progress_context: *const c_void
    ) -> Result<u32, Error> {
        self.add_wallet_if_not_exist(wallet_id);
        let controller = self.cache.identity_by_index(wallet_id, index)
            .ok_or(Error::Any(0, format!("No identity for {wallet_id}: {index}")))?;
        let chain = Arc::clone(&self.chain);

        let steps = RegistrationStep::from_bits(steps)
            .ok_or(Error::Any(0, "Invalid query step".to_string()))?;
        let debug_string = format!("[PlatformSDK] {} Register On Network: {steps:?}", controller.log_prefix());
        println!("{debug_string}");
        let mut steps_completed = RegistrationStep::None;

        if !controller.has_extended_public_keys() {
            println!("{debug_string}: ERROR: AttemptQueryWithoutKeys");
            return Err(Error::AttemptQueryWithoutKeys);
        }
        if !steps.contains(RegistrationStep::FundingTransactionCreation) {
            println!("{debug_string}: Ok: No FundingTransactionCreation step");
            return Ok(steps_completed.bits());
        }

        let derivation_kind = if controller.model.is_outgoing_invitation() {
            DerivationPathKind::InvitationFunding
        } else {
            DerivationPathKind::IdentityRegistrationFunding
        };
        let derivation_path = chain.get_derivation_path(wallet_id, derivation_kind);
        let asset_lock_registration_address = chain.derivation_ref().address_at_index_path(derivation_path, vec![controller.model.index()]);
        let asset_lock_registration_script = DataAppend::script_pub_key_for_address(asset_lock_registration_address.as_str(), self.chain_type.script_map_ref());
        let wallet_context = chain.get_wallet_by_id(wallet_id);

        let transaction_model = chain.wallet.publish_asset_lock_transaction(wallet_context, topup_duff_amount, asset_lock_registration_script, prompt)
            .map_err(|err| {
                match err {
                    ChainError::Cancelled => {
                        steps_completed.insert(RegistrationStep::Cancelled);
                        println!("{debug_string}: Cancelled");
                        Error::AssetLockSubmission(AssetLockSubmissionError { steps_completed: steps_completed.bits() })
                        // Ok(steps_completed.bits())
                    }
                    ChainError::SigningError(description) | ChainError::TransactionPublishError(description) => {
                        println!("{debug_string}: {description}");
                        Error::AssetLockSubmission(AssetLockSubmissionError { steps_completed: steps_completed.bits() })
                    }
                    ChainError::InstantSendLockError(description) => {
                        println!("{debug_string}: {description}");
                        steps_completed.insert(RegistrationStep::FundingTransactionCreation);
                        steps_completed.insert(RegistrationStep::LocalInWalletPersistence);
                        Error::AssetLockSubmission(AssetLockSubmissionError { steps_completed: steps_completed.bits() })
                    }
                }
            })?;

        steps_completed.insert(RegistrationStep::FundingTransactionCreation);
        if !steps.contains(RegistrationStep::LocalInWalletPersistence) {
            return Ok(steps_completed.bits());
        }
        let credit_burn_public_key_hash = transaction_model.maybe_credit_burn_public_key_hash()
            .ok_or(Error::AssetLockSubmission(AssetLockSubmissionError { steps_completed: steps_completed.bits() }))?;
        let identity_id = transaction_model.credit_burn_identity_identifier();
        let locked_outpoint = transaction_model.locked_outpoint();
        let WalletCache {
            identities,
            invitations,
            default_identity_index,
            ..
        } = self.cache.wallets.get_mut(wallet_id).unwrap();
        let is_known_by_id = identities.contains_key(&identity_id);
        let is_known_by_index = identities.values().any(|controller| controller.index() == index);


        let controller = if is_known_by_id {
            identities.get_mut(&identity_id).unwrap()
        } else if is_known_by_index {
            let controller = identities.values_mut().find_map(|controller| (controller.index() == index).then_some(controller)).unwrap();
            controller.model.unique_id = identity_id;
            controller
        } else {
            let model = IdentityModel::with_index_and_unique_id(index, identity_id, wallet_id.to_string());
            let controller = IdentityController::with_model(model, Arc::clone(&self.identity_callbacks));
            identities.insert(identity_id, controller);
            identities.get_mut(&identity_id).unwrap()
        };

        controller.model.set_locked_outpoint(Some(locked_outpoint.clone()));
        if controller.model.is_outgoing_invitation {
            controller.model.set_asset_lock_registration_model(transaction_model);
            let invitation = InvitationModel::with_identity(identity_id, wallet_id.to_string());
            invitations.insert(locked_outpoint.clone(), invitation.clone());
            _ = chain.save_invitation_into_keychain(wallet_id, locked_outpoint.clone(), index);
            controller.save_model_in_context(StorageContext::Platform);
            chain.mark_address_hash_as_used(credit_burn_public_key_hash.as_byte_array(), DerivationPathKind::InvitationFunding, wallet_id);
            chain.notification_ref()
                .notify_main_thread(INVITATION_DID_UPDATE_NOTIFICATION, ferment::boxed(InvitationDidUpdate::new(self.chain_type.clone(), invitation)) as *mut c_void);
        } else {
            controller.model.set_asset_lock_registration_hash(transaction_model.transaction.txid().to_byte_array());
            if !is_known_by_id && !is_known_by_index {
                _ = chain.save_identity_into_keychain(wallet_id, controller.unique_id(), controller.model.to_keychain_value());
                let index = controller.index();
                // if !controller.unique_id().eq(&[0u8; 32]) {
                //     identities.insert(controller.unique_id(), controller.clone());
                // }
                if default_identity_index.is_none() && index == 0 {
                    *default_identity_index = Some(index);
                }
            }
            controller.save_model_in_context(StorageContext::Platform);
            chain.mark_address_hash_as_used(credit_burn_public_key_hash.as_byte_array(), DerivationPathKind::IdentityRegistrationFunding, wallet_id);
        }
        steps_completed.insert(RegistrationStep::LocalInWalletPersistence);

        if !steps.contains(RegistrationStep::FundingTransactionAccepted) {
            println!("{debug_string}: Ok (Asset Lock Transaction no FundingTransactionAccepted)");
            return Ok(steps_completed.bits());
        }

        println!("{debug_string}: Ok({steps_completed:?})");
        self.continue_registering_identity_on_network(controller, steps.bits(), steps_completed.bits(), progress_handler, progress_context).await
    }

    pub async fn sync_identities<
        NotifyProgress: Fn(*const c_void) + Send + Sync + Clone + 'static,
    >(
        &mut self,
        block_height: u32,
        notify_progress: NotifyProgress,
    ) -> Result<bool, Error> {
        let debug_string = "[PlatformSDK] Sync Identities:".to_string();
        println!("{debug_string} KeyHashes");
        let wallets_to_sync = self.cache.wallets.len() as u32;
        let chain_context = self.chain.get_chain();
        self.notify_sync_state(chain_context, vec![
            PlatformSyncStateNotification::Start,
            PlatformSyncStateNotification::AddStateKind { kind: PlatformSyncStateKind::KeyHashes.bits() },
            PlatformSyncStateNotification::QueueChanged { count: 0, max_amount: wallets_to_sync }
        ]);
        let mut errors = Vec::<Error>::new();
        let wallet_ids: Vec<String> = self.cache.wallets.keys().cloned().collect();
        for (wallet_index, wallet_id) in wallet_ids.into_iter().enumerate() {
            let unused_index = self.cache.wallets.get(&wallet_id).map(|wallet| wallet.unused_identity_index()).unwrap_or_default();
            let result = self.monitor_key_hash_one_by_one(&wallet_id, unused_index, notify_progress.clone(), chain_context).await;

            match result {
                Ok(result) => {
                    for (index, identity) in result {
                        let controller = IdentityController::at_index_with_identity(
                            index,
                            identity,
                            wallet_id.clone(),
                            Arc::clone(&self.identity_callbacks),
                        );

                        let keychain_value = self.chain.maybe_keychain_identity(
                            &wallet_id,
                            index,
                            controller.unique_id(),
                            controller.model.locked_outpount.clone(),
                        );

                        if let Ok(true) = keychain_value.and_then(|value| self.chain.keychain.set(KeyChainKey::wallet_identities_key(&wallet_id), value, false)) {
                            controller.save_model_in_context(StorageContext::Platform);

                            if let Some(wallet) = self.cache.wallets.get_mut(&wallet_id) {
                                wallet.identities.insert(controller.unique_id(), controller);

                                if let Some(default_index) = wallet.default_identity_index {
                                    println!("{debug_string} Default Identity: already set {}", default_index);
                                } else {
                                    println!("{debug_string} Default Identity: set to {index}");
                                    wallet.default_identity_index = Some(index);
                                }
                            }
                        }

                        self.notify_sync_state(chain_context, vec![
                            PlatformSyncStateNotification::QueueChanged { count: wallet_index as u32, max_amount: wallets_to_sync }
                        ]);
                    }
                }
                Err(err) => {
                    println!("{debug_string}: {err:?}");
                    errors.push(err);
                }
            }
        }

        let num_unsynced = self.cache.unsynced_identities_count_at_block_height(block_height);
        println!("{debug_string} Unsynced: {}", num_unsynced);
        let notifications = if num_unsynced > 0 {
            vec![
                PlatformSyncStateNotification::RemoveStateKind { kind: PlatformSyncStateKind::KeyHashes.bits() },
                PlatformSyncStateNotification::AddStateKind { kind: PlatformSyncStateKind::Unsynced.bits() },
                PlatformSyncStateNotification::QueueChanged { count: 0, max_amount: num_unsynced as u32 }
            ]
        } else {
            vec![
                PlatformSyncStateNotification::RemoveStateKind { kind: PlatformSyncStateKind::KeyHashes.bits() }
            ]
        };
        self.notify_sync_state(chain_context, notifications);

        let identity_handles = self.cache.unsynced_identity_handles_at_block_height(block_height);
        let num_unsynced = identity_handles.len();
        for (unsynced_index, (wallet_id, identity_id)) in identity_handles.into_iter().enumerate() {
            self.process_unsynced_identity(
                &wallet_id,
                &identity_id,
                chain_context,
                unsynced_index as u32,
                num_unsynced as u32,
                &mut errors,
            ).await;
        }
        self.notify_sync_state(chain_context, vec![
            PlatformSyncStateNotification::QueueChanged { count: 0, max_amount: 0 },
            PlatformSyncStateNotification::Finish { timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
        ]);
        Ok(errors.len() == 0)
    }
    pub async fn process_unsynced_identity(
        &mut self,
        wallet_id: &str,
        identity_id: &[u8; 32],
        chain_context: *const c_void,
        unsynced_index: u32,
        max_amount: u32,
        errors: &mut Vec<Error>,
    ) {
        let controller = {
            self.cache.wallets
                .get_mut(wallet_id)
                .and_then(|wallet| wallet.identities.get_mut(identity_id))
                .map(|c| c as *mut IdentityController)
        };

        if let Some(controller_ptr) = controller {
            let controller = unsafe { &mut *controller_ptr };

            if let Err(err) = self.fetch_needed_state_information(controller, StorageContext::Platform).await {
                errors.push(err);
            }

            self.notify_sync_state(chain_context, vec![
                PlatformSyncStateNotification::QueueChanged {
                    count: unsynced_index + 1,
                    max_amount,
                },
            ]);
        }
    }

    pub async fn monitor_key_hash_one_by_one<
        NotifyProgress: Fn(*const c_void) + Send + Sync + Clone + 'static,
    >(
        &self,
        wallet_id: &str,
        unused_index: u32,
        notify_progress: NotifyProgress,
        chain_context: *const c_void
    ) -> Result<BTreeMap<u32, Identity>, Error> {
        let debug_string = format!("[PlatformSDK] Monitor KeyHashes (one-by-one) starting from {}", unused_index);
        println!("{debug_string}");
        let mut index = unused_index;
        let mut identities = BTreeMap::new();
        let derivation_path = self.chain.get_derivation_path(wallet_id, DerivationPathKind::IdentityECDSA);
        while let Ok((new_index, key_hash, Some(identity))) = self.fetch_identity_by_index(index, derivation_path).await {
            println!("{debug_string}/{}: Ok: key_hash: {}, identity: {}", new_index, key_hash.to_lower_hex_string(), identity.id().to_string(Encoding::Hex));
            notify_progress(chain_context);
            index = new_index;
            identities.insert(new_index, identity);
        }
        Ok(identities)
    }

    pub async fn fetch_identity_by_index(
        &self,
        index: u32,
        derivation_path: *const c_void,
    ) -> Result<(u32, [u8; 20], Option<Identity>), Error> {
        let debug_string = format!("[PlatformSDK] Fetch by index {}", index);
        let new_index = index + 1;
        let public_key_data = self.chain.derivation_ref().public_key_data_at_index_path(derivation_path, vec![new_index | BIP32_HARD, 0 | BIP32_HARD]);
        let public_key_hash = hash160::Hash::hash(&public_key_data).to_byte_array();
        println!("{debug_string}");
        let result = Identity::fetch_with_settings(self.sdk_ref(), PublicKeyHash(public_key_hash), KEY_HASHES_SETTINGS).await
            .map_err(Error::from)
            .map(|result| (new_index, public_key_hash, result));
        println!("{debug_string}: Result: {result:?}");
        result
    }

    pub async fn register_identity<
        NotifyProgress: Fn(*const c_void, u32) + Send + Sync + Clone + 'static
    >(
        &mut self,
        wallet_id: &str,
        index: u32,
        steps: u32,
        topup_duff_amount: u64,
        prompt: String,
        progress_handler: NotifyProgress,
        progress_context: *const c_void
    ) -> Result<u32, Error> {
        self.register_on_network_with_wallet_id_and_index(wallet_id, index, steps, topup_duff_amount, prompt, progress_handler, progress_context).await
/*        let controller = self.cache.identity_by_index_mut(wallet_id, index)
            .ok_or(Error::Any(0, format!("No identity for {wallet_id}: {index}")))?;
        self.register_on_network(controller, steps, topup_duff_amount, prompt, progress_handler, progress_context).await
*/    }

    pub async fn fetch_usernames(&self, controller: &mut IdentityController, contract: DataContract) -> Result<bool, Error> {
        let debug_string = format!("[DocManager] {} Fetch Usernames", controller.log_prefix());
        println!("{debug_string}");
        let query = self.doc_manager.query_dpns_documents_for_identity_with_user_id(contract, controller.unique_id())?;
        let (documents, _metadata) = Document::fetch_many_with_metadata(self.sdk_ref(), query, Some(USERNAME_SETTINGS)).await?;
        println!("{debug_string}: OK({})", documents.len());
        for (identifier, maybe_document) in documents {
            if let Some(document) = maybe_document {
                controller.update_with_username_document(document);
            } else {
                println!("[WARN] Document {} is nil", identifier.to_string(Encoding::Hex));
            }
        }
        Ok(true)
    }

    pub async fn fetch_profile(&self, model: &mut IdentityModel, contract: DataContract) -> Result<TransientDashPayUser, Error> {
        let debug_string = format!("[DocManager] {} Fetch Profile", model.log_prefix());
        println!("{debug_string}");
        let user_id = model.unique_id;
        let query = self.doc_manager.query_dashpay_profile_for_user_id(contract, user_id)?;
        let (document, _metadata) = Document::fetch_with_metadata(self.sdk_ref(), query, Some(PROFILE_SETTINGS)).await?;
        match document {
            Some(doc) =>
                Ok(TransientDashPayUser::with_profile_document(doc)),
            None =>
                Err(Error::Any(0, format!("Profile for {} not found", user_id.to_lower_hex_string())))
        }

    }
    pub async fn fetch_profile_in_context(&self, controller: &mut IdentityController, contract: DataContract, storage_context: StorageContext) -> Result<bool, Error> {
        let debug_string = format!("[DocManager] {} Fetch Profile in context", controller.log_prefix());
        println!("{debug_string}");
        match self.fetch_profile(&mut controller.model, contract).await {
            Ok(user) if self.cache.has_active_identity(&controller.model) => {
                println!("{debug_string}: Ok({user:?})");
                Ok(controller.save_profile(storage_context, user))
            },
            Ok(_) => {
                println!("{debug_string}: Ok(IdentityIsNoLongerActive)");
                Err(Error::IdentityIsNoLongerActive(controller.unique_id()))
            },
            Err(err) => {
                println!("{debug_string}: Err({err:?})");
                Err(err)
            },
        }


    }

    pub async fn fetch_incoming_contact_requests(
        &self,
        controller: &mut IdentityController,
        contract: DataContract,
        since: u64,
        start_after: Option<[u8; 32]>,
        storage_context: StorageContext,
    ) ->Result<(Vec<ContactRequest>, Option<[u8; 32]>), Error> {
        let debug_string = format!("[CRManager] {} Fetch OCR", controller.log_prefix());
        println!("{debug_string}");
        let user_id = controller.unique_id();
        let query = self.contact_requests.query_incoming_contact_requests(contract, user_id, since, start_after)?;
        let (documents, _metadata) = Document::fetch_many_with_metadata(self.sdk_ref(), query, Some(CONTACT_REQUEST_SETTINGS)).await?;
        let mut contact_requests = Vec::new();
        for (_, document) in documents {
            if let Some(doc) = document {
                let request = ContactRequest::try_from(doc)?;
                if user_id.eq(&request.recipient) && !controller.has_incoming_contact_request_with_id(storage_context, request.owner_id) {
                    contact_requests.push(request);
                }
            }
        }
        let has_more = contact_requests.len() == DAPI_DOCUMENT_RESPONSE_COUNT_LIMIT;
        if !has_more {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;

            controller.model.set_last_checked_outgoing_contacts_timestamp(now);
        }
        let start_after = contact_requests.last().map(|req| req.id);
        if !self.cache.has_active_identity(&controller.model) {
            return Err(Error::Any(0, "Identity is not active".to_string()));
        }
        Ok((contact_requests, start_after))
    }
    pub async fn fetch_outgoing_contact_requests(
        &self,
        controller: &mut IdentityController,
        contract: DataContract,
        since: u64,
        start_after: Option<[u8; 32]>,
        storage_context: StorageContext,
    ) -> Result<(Vec<ContactRequest>, Option<[u8; 32]>), Error> {
        let debug_string = format!("[CRManager] {} Fetch OCR", controller.log_prefix());
        println!("{debug_string}");
        let user_id = controller.unique_id();
        let query = self.contact_requests.query_outgoing_contact_requests(contract, user_id, since, start_after)?;
        let (documents, _metadata) = Document::fetch_many_with_metadata(self.sdk_ref(), query, Some(CONTACT_REQUEST_SETTINGS)).await?;
        let mut contact_requests = Vec::new();
        for (_, document) in documents {
            if let Some(doc) = document {
                let request = ContactRequest::try_from(doc)?;
                let recipient = request.recipient;
                if !user_id.eq(&recipient) && !controller.has_outgoing_contact_request_with_id(storage_context, recipient) {
                    contact_requests.push(request);
                }
            }
        }
        let has_more = contact_requests.len() == DAPI_DOCUMENT_RESPONSE_COUNT_LIMIT;
        if !has_more {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;

            controller.model.set_last_checked_outgoing_contacts_timestamp(now);
        }
        let start_after = contact_requests.last().map(|req| req.id);
        if !self.cache.has_active_identity(&controller.model) {
            return Err(Error::Any(0, "Identity is not active".to_string()));
        }
        println!("{debug_string}: OK({}, {start_after:?})", contact_requests.len());
        Ok((contact_requests, start_after))
    }

    pub async fn fetch_incoming_contact_requests_in_context(
        &self,
        controller: &mut IdentityController,
        contract: DataContract,
        start_after: Option<[u8; 32]>,
        storage_context: StorageContext,
    ) -> Result<bool, Error> {
        let debug_string = format!("[DocManager] {} Fetch ICR", controller.log_prefix());
        println!("{debug_string}");
        let loaded = controller.active_private_keys_are_loaded()?;
        if !loaded {
            println!("{debug_string}: Err(Private keys are not loaded)");
            return Err(Error::Any(0, "Private keys are not loaded".to_string()));
        }

        let timestamp = controller.model.last_checked_incoming_contacts_timestamp();
        let since = if timestamp >= 3600 { timestamp - 3600 } else { 0 };
        let mut start_after = start_after.clone();
        let mut success = true;
        while let Ok((requests, maybe_after)) = self.fetch_incoming_contact_requests(controller, contract.clone(), since, start_after, storage_context).await {
            if !requests.is_empty() {
                success &= controller.save_outgoing_contact_requests(storage_context, requests);
            }
            if maybe_after.is_some() {
                start_after = maybe_after;
            } else {
                break;
            }
        }
        println!("{debug_string}: OK({success})");
        Ok(success)
    }

    pub async fn fetch_outgoing_contact_requests_in_context(
        &self,
        controller: &mut IdentityController,
        contract: DataContract,
        start_after: Option<[u8; 32]>,
        storage_context: StorageContext,
    ) -> Result<bool, Error> {
        let debug_string = format!("[DocManager] {} Fetch OCR", controller.log_prefix());
        println!("{debug_string}");
        let loaded = controller.active_private_keys_are_loaded()?;
        if !loaded {
            println!("{debug_string}: Err(Private keys are not loaded)");
            return Err(Error::Any(0, "Private keys are not loaded".to_string()));
        }

        let timestamp = controller.model.last_checked_outgoing_contacts_timestamp();
        let since = if timestamp >= 3600 { timestamp - 3600 } else { 0 };
        let mut start_after = start_after.clone();
        let mut success = true;
        while let Ok((requests, maybe_after)) = self.fetch_outgoing_contact_requests(controller, contract.clone(), since, start_after, storage_context).await {
            if !requests.is_empty() {
                success &= controller.save_outgoing_contact_requests(storage_context, requests);
            }
            if maybe_after.is_some() {
                start_after = maybe_after;
            } else {
                break;
            }
        }
        println!("{debug_string}: OK({success})");
        Ok(success)
    }

}


impl PlatformSDK {
    pub fn new<
        GetQuorumPublicKey: Fn(u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync + 'static,
        GetDataContract: Fn(*const c_void, [u8; 32]) -> Option<DataContract> + Send + Sync + 'static,
        GetPlatformActivationHeight: Fn(*const c_void) -> u32 + Send + Sync + 'static,
        Sign: Fn(*const c_void, IdentityPublicKey) -> Option<OpaqueKey> + Send + Sync + 'static,
        CanSign: Fn(*const c_void, IdentityPublicKey) -> bool + Send + Sync + 'static,
        GetDataContractFromCache: Fn(*const c_void, SystemDataContract) -> DataContract + Send + Sync + 'static,
        SignAndPublishAssetLockTransaction: Fn(*const c_void, /*topup_duff_amount*/u64, /*account_context*/ *const c_void, /*prompt*/String, /*steps*/u32) -> Result<u32, AssetLockSubmissionError> + Sync + Send + 'static,
        // MaybeWalletIdentity: Fn(/*wallet_context*/*const c_void, [u8; 32], IdentityDictionaryItemValue) -> Option<IdentityController> + Send + Sync + 'static,
        // MaybeWalletInvitation: Fn(/*wallet_context*/*const c_void, [u8; 36], u32) -> Option<InvitationModel> + Send + Sync + 'static,
        NotifySyncState: Fn(*const c_void, Vec<PlatformSyncStateNotification>) + Send + Sync + 'static,
    >(
        chain: Arc<ChainManager>,
        identity_callbacks: IdentityCallbacks,
        get_quorum_public_key: Arc<GetQuorumPublicKey>,
        get_data_contract: GetDataContract,
        get_platform_activation_height: GetPlatformActivationHeight,
        callback_signer: Sign,
        callback_can_sign: CanSign,
        get_data_contract_from_cache: GetDataContractFromCache,
        // sign_and_publish_asset_lock_transaction: SignAndPublishAssetLockTransaction,

        notify_sync_state: NotifySyncState,
        address_list: Option<Vec<&'static str>>,
        chain_type: ChainType,
        context: *const c_void,
    ) -> Self {
        let context_arc = Arc::new(FFIThreadSafeContext::new(context));

        let host_list = address_list.unwrap_or(match &chain_type {
            ChainType::MainNet => Vec::from_iter(MAINNET_ADDRESS_LIST),
            _ => Vec::from_iter(DEFAULT_TESTNET_ADDRESS_LIST),
        });

        let provider = PlatformProvider::new(get_quorum_public_key, get_data_contract, get_platform_activation_height, context_arc.clone());
        let sdk = create_sdk(provider, host_list.iter().filter_map(|s| Address::from_str(format!("https://{s}:{}", chain_type.platform_port()).as_str()).ok()));

        let protocol_version = sdk.version().protocol_version;
        let sdk_arc = Arc::new(sdk);
        let cache = PlatformCache::new(Arc::clone(&chain));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .thread_name("dash-spv-platform")
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        Self {
            chain,
            cache,
            identity_callbacks: Arc::new(identity_callbacks),
            identity_manager: Arc::new(IdentitiesManager::new(&sdk_arc, chain_type.clone())),
            contract_manager: Arc::new(ContractsManager::new(&sdk_arc, chain_type.clone())),
            doc_manager: Arc::new(DocumentsManager::new(&sdk_arc, chain_type.clone())),
            contact_requests: Arc::new(ContactRequestManager::new(&sdk_arc, chain_type.clone())),
            salted_domain_hashes: Arc::new(SaltedDomainHashesManager::new(&sdk_arc, chain_type.clone())),
            usernames: Arc::new(UsernamesManager::new(&sdk_arc, chain_type.clone())),
            runtime: Arc::new(runtime),
            callback_signer: CallbackSigner::new(callback_signer, callback_can_sign, context_arc),
            identities: IdentityFacade::new(protocol_version),
            contracts: DataContractFacade::new(protocol_version).unwrap(),
            state_transition: StateTransitionFactory {},
            documents: DocumentFactory::new(protocol_version).unwrap(),
            get_data_contract_from_cache: Arc::new(get_data_contract_from_cache),
            // sign_and_publish_asset_lock_transaction: Arc::new(sign_and_publish_asset_lock_transaction),
            notify_sync_state: Arc::new(notify_sync_state),
            sdk: sdk_arc,
            chain_type,
        }
    }

    pub fn sdk_ref(&self) -> &Sdk {
        &self.sdk
    }
    pub fn sdk_version(&self) -> &PlatformVersion {
        self.sdk.version()
    }

    pub fn get_dashpay_data_contract(&self) -> DataContract {
        self.get_data_contract_in_context(self.chain.get_chain(), SystemDataContract::Dashpay)
    }
    pub fn get_dpns_data_contract(&self) -> DataContract {
        self.get_data_contract_in_context(self.chain.get_chain(), SystemDataContract::DPNS)
    }
    pub fn get_data_contract_in_context(&self, context: *const c_void, system_data_contract: SystemDataContract) -> DataContract {
        (self.get_data_contract_from_cache)(context, system_data_contract)
    }
    pub fn notify_sync_state(&self, context: *const c_void, notifications: Vec<PlatformSyncStateNotification>) {
        (self.notify_sync_state)(context, notifications)
    }

    #[cfg(feature = "state-transitions")]
    pub async fn document_batch<'a>(
        &self,
        documents: HashMap<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef<'a>, Bytes32, Option<TokenPaymentInfo>)>>,
        private_key: OpaqueKey,
    ) -> Result<StateTransitionProofResult, Error> {
        println!("document_batch: {documents:?} -- {private_key:?}");
        let signed_transition = self.document_batch_signed_transition(documents, private_key)?;
        self.publish_state_transition(signed_transition).await
    }

    pub async fn fetch_documents(
        &self,
        contract_id: Identifier,
        document_type: &str,
        where_clauses: Vec<WhereClause>,
        order_clauses: Vec<OrderClause>,
        limit: u32,
        start: Option<Start>
    ) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let contract = self.contract_manager.fetch_contract_by_id_error_if_none(contract_id).await?;
        let query = QueryKind::generic(contract, document_type, where_clauses, order_clauses, limit, start)?;
        self.doc_manager.documents_with_query(query).await
    }

    fn sign_transition<T: Signable, F: Fn(T) -> StateTransition>(f: F, transition: T, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        let private_key_data = private_key.private_key_data().map_err(Error::KeyError)?;
        let mut state_transition = f(transition);
        let data = state_transition.signable_bytes().map_err(Error::from)?;
        let key_type = key_type_from_opaque_key(private_key).map_err(Error::KeyError)?;
        println!("transition signable bytes: {}", data.to_lower_hex_string());
        state_transition.sign_by_private_key(&private_key_data, key_type, &NativeBlsModule).map_err(Error::from)?;
        println!("transition signature: {}", state_transition.signature().0.to_lower_hex_string());
        Ok(state_transition)
    }

    async fn publish_state_transition(&self, transition: StateTransition) -> Result<StateTransitionProofResult, Error> {
        println!("publish_state_transition: {:?}", transition);
        transition.broadcast_and_wait(&self.sdk, None).await.map_err(Error::from)
    }

    pub async fn sign_and_publish_state_transition(&self, private_key: &[u8], key_type: KeyType, mut state_transition: StateTransition) -> Result<StateTransitionProofResult, Error> {
        state_transition.sign_by_private_key(private_key, key_type, &NativeBlsModule)
            .map_err(Error::from)?;
        self.publish_state_transition(state_transition).await
    }

}

impl KeychainRef for PlatformSDK {
    fn keychain_ref(&self) -> &KeychainController {
        self.chain.keychain_ref()
    }
}

impl StorageRef for PlatformSDK {
    fn storage_ref(&self) -> &StorageController {
        self.chain.storage_ref()
    }
}

impl ChainRef for PlatformSDK {
    fn chain_ref(&self) -> &ChainController {
        self.chain.chain_ref()
    }
}
impl DerivationRef for PlatformSDK {
    fn derivation_ref(&self) -> &DerivationController {
        self.chain.derivation_ref()
    }
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;
    use std::str::FromStr;
    use std::sync::Arc;
    use dash_sdk::dapi_client::Address;
    use dash_sdk::Sdk;
    use dashcore::secp256k1::hashes::hex::DisplayHex;
    use dpp::identity::Identity;
    use drive_proof_verifier::error::ContextProviderError;
    use dash_spv_crypto::network::ChainType;
    use crate::{create_sdk, DEFAULT_TESTNET_ADDRESS_LIST, MAINNET_ADDRESS_LIST};
    use crate::error::Error;
    use crate::identity::manager::IdentitiesManager;
    use crate::provider::PlatformProvider;
    use crate::thread_safe_context::FFIThreadSafeContext;

    // asdtwotwooct
    #[allow(unused)]
    fn create_test_sdk(chain: &ChainType) -> Sdk {
        let address_list = match chain {
            ChainType::MainNet => Vec::from_iter(MAINNET_ADDRESS_LIST.iter().filter_map(|s| Address::from_str(format!("https://{s}:443").as_str()).ok())),
            _ => Vec::from_iter(DEFAULT_TESTNET_ADDRESS_LIST.iter().filter_map(|s| Address::from_str(format!("https://{s}:1443").as_str()).ok())),
        };
        let context_arc = Arc::new(FFIThreadSafeContext::new(std::ptr::null()));
        let get_data_contract = |_ctx, identifier| {
            println!("get_data_contract: {:?}", identifier);
            Err(ContextProviderError::Generic("DDDDD".to_string()))
        };
        let get_quorum_public_key = |quorum_type, quorum_hash, core_chain_locked_height| {
            println!("get_quorum_public_key: {:?} {:?} {}", quorum_type, quorum_hash, core_chain_locked_height);
            Err(ContextProviderError::Generic("DDDDD".to_string()))
        };
        let get_platform_activation_height = |_ctx| {
            println!("get_platform_activation_height");
            Ok(0)
        };
        create_sdk(
            PlatformProvider::new(
                Arc::new(get_quorum_public_key),
                get_data_contract,
                get_platform_activation_height,
                context_arc.clone()),
            address_list)
    }

    #[tokio::test]
    async fn test_testnet_get_identities_for_wallets_public_keys() {
        async fn testnet_get_identities_for_wallets_public_keys() -> Result<BTreeMap<String, BTreeMap<[u8; 20], Identity>>, Error> {
            use dashcore::hashes::hex::FromHex;
            // let key_hashes =
            //     [[61, 109, 200, 109, 172, 74, 46, 253, 71, 179, 136, 237, 252, 103, 3, 212, 243, 105, 230, 114],
            //         [138, 75, 20, 232, 201, 81, 135, 207, 206, 176, 233, 200, 155, 226, 11, 43, 69, 218, 235, 100],
            //         [212, 176, 162, 172, 173, 243, 14, 168, 196, 178, 235, 214, 97, 221, 188, 170, 146, 133, 186, 213],
            //         [36, 251, 54, 207, 245, 49, 18, 218, 112, 196, 174, 195, 166, 228, 199, 177, 71, 79, 183, 61],
            //         [131, 183, 222, 165, 235, 186, 250, 74, 70, 87, 236, 55, 208, 136, 178, 181, 212, 249, 106, 16]];
            let key_hashes = [
                [136, 226, 186, 122, 129, 233, 109, 32, 43, 42, 239, 97, 31, 1, 255, 200, 185, 184, 56, 243],
                [50, 184, 144, 250, 181, 179, 124, 121, 215, 190, 42, 190, 227, 83, 233, 235, 186, 187, 0, 247],
                [103, 161, 254, 195, 162, 50, 221, 58, 95, 177, 230, 64, 95, 145, 13, 191, 220, 175, 42, 168],
                [31, 35, 161, 72, 134, 75, 216, 179, 146, 121, 99, 172, 8, 156, 166, 97, 237, 81, 145, 39],
                [147, 219, 37, 98, 100, 110, 242, 176, 147, 244, 166, 220, 109, 201, 44, 116, 87, 82, 118, 1]
            ];

            let context_arc = Arc::new(FFIThreadSafeContext::new(std::ptr::null()));
            let get_data_contract = |_ctx, identifier| {
                println!("get_data_contract: {:?}", identifier);
                Err(ContextProviderError::Generic("get_data_contract: DDDDD".to_string()))
            };
            let get_quorum_public_key = Arc::new(|quorum_type: u32, quorum_hash: [u8; 32], core_chain_locked_height: u32| {
                println!("get_quorum_public_key: {:?} {:?} {}", quorum_type, quorum_hash.to_lower_hex_string(), core_chain_locked_height);
                Ok(<[u8; 48]>::from_hex("90bfc37734097f59401a45554a7ddcf0e846e333b74bcd70c8f973a3d932697bdaf5671d0e4a4961a7d2c9a853833429").unwrap())
            });
            let get_platform_activation_height = |_ctx| {
                println!("get_platform_activation_height");
                Ok(0)
            };
            // let address_list = Vec::from_iter(DEFAULT_TESTNET_ADDRESS_LIST.iter().filter_map(|s| Address::from_str(s).ok()));
            let address_list = Vec::from_iter(DEFAULT_TESTNET_ADDRESS_LIST.iter().filter_map(|s| Address::from_str(format!("https://{s}:1443").as_str()).ok()));

            let sdk = create_sdk(
                PlatformProvider::new(get_quorum_public_key, get_data_contract, get_platform_activation_height, context_arc.clone()), address_list);

            let sdk_arc = Arc::new(sdk);
            let manager = IdentitiesManager::new(&sdk_arc, ChainType::TestNet);
            let key_hashes = BTreeMap::from_iter([("e092d129ef12bb99".to_string(), key_hashes.to_vec())]);
            manager.get_identities_for_wallets_public_keys(key_hashes).await
        }

        match testnet_get_identities_for_wallets_public_keys().await {
            Ok(result) => {
                println!("Ok: {:?}", result);
            },
            Err(err) => {
                println!("Error: {:?}", err);
            }
        }
    }
}
