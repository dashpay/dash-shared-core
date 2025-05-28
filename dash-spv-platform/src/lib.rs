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

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::c_void;
use std::str::FromStr;
use std::sync::Arc;
use dapi_grpc::core::v0::GetTransactionRequest;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::{dpp, RequestSettings, Sdk, SdkBuilder};
use dash_sdk::dapi_client::{Address, AddressListError, DapiRequestExecutor};
use dash_sdk::platform::FetchUnproved;
use dash_sdk::platform::transition::put_contract::PutContract;
use dash_sdk::platform::transition::broadcast::BroadcastStateTransition;
use dash_sdk::platform::transition::put_document::PutDocument;
use dash_sdk::platform::transition::put_identity::PutIdentity;
use dash_sdk::platform::transition::put_settings::PutSettings;
use dash_sdk::platform::transition::waitable::Waitable;
use dash_sdk::platform::types::evonode::EvoNode;
use dash_sdk::sdk::AddressList;
use dashcore::blockdata::transaction::Transaction;
use dashcore::consensus::Decodable;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::OutPoint;
use dashcore::prelude::DisplayHex;
use data_contracts::SystemDataContract;
use dpp::data_contract::{DataContract, DataContractFacade};
use dpp::data_contract::accessors::v0::{DataContractV0Getters, DataContractV0Setters};
use dpp::data_contract::created_data_contract::CreatedDataContract;
use dpp::data_contract::document_type::{DocumentType, DocumentTypeRef};
use dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dpp::data_contracts;
use dpp::errors::ProtocolError;
use dpp::identity::{Identity, IdentityPublicKey, IdentityFacade, KeyID, KeyType, SecurityLevel};
use dpp::document::{Document, DocumentV0Getters};
use dpp::document::document_factory::DocumentFactory;
use dpp::errors::consensus::basic::BasicError;
use dpp::errors::consensus::ConsensusError;
use dpp::identity::core_script::CoreScript;
use dpp::identity::state_transition::asset_lock_proof::{AssetLockProof, InstantAssetLockProof};
use dpp::identity::state_transition::asset_lock_proof::chain::ChainAssetLockProof;
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
use platform_version::version::v8::PLATFORM_V8;
use tokio::runtime::Runtime;
use dash_spv_crypto::crypto::byte_util::{Random, Reversed};
use dash_spv_crypto::derivation::BIP32_HARD;
use dash_spv_crypto::keys::{IKey, OpaqueKey};
use dash_spv_crypto::network::ChainType;
use dash_spv_event_bus::DAPIAddressHandler;
use crate::cache::PlatformCache;
use crate::contract::manager::ContractsManager;
use crate::document::contact_request::ContactRequestManager;
use crate::document::manager::DocumentsManager;
use crate::document::salted_domain_hashes::{SaltedDomainHashValidator, SaltedDomainHashesManager};
use crate::document::usernames::{UsernameStatus, UsernameValidator, UsernamesManager};
use crate::error::Error;
use crate::identity::manager::{identity_registration_public_key, key_kind_to_key_type, key_type_from_opaque_key, IdentitiesManager};
use crate::identity::model::{domains_for_username_full_paths, IdentityModel, DEFAULT_USERNAME_REGISTRATION_PURPOSE, DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL};
use crate::identity::storage::username::SaveUsernameContext;
use crate::identity::username_registration_error::UsernameRegistrationError;
use crate::models::profile::Profile;
use crate::provider::PlatformProvider;
use crate::query::QueryKind;
use crate::signer::CallbackSigner;
use crate::thread_safe_context::FFIThreadSafeContext;
use crate::util::RetryStrategy;

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

#[ferment_macro::opaque]
pub struct PlatformSDK {
    pub runtime: Arc<Runtime>,
    pub chain_type: ChainType,
    pub sdk: Arc<Sdk>,
    pub cache: Arc<PlatformCache>,
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

    // #[cfg(feature = "state-transitions")]
    /// Create signed transition
    pub fn identity_registration_signed_transition(&self, identity: Identity, proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        self.identities.create_identity_create_transition(&identity, proof)
            .map_err(Error::from)
            .and_then(|transition|
                Self::sign_transition(StateTransition::IdentityCreate, transition, private_key))
    }
    pub fn identity_registration_signed_transition_with_public_keys(&self, public_keys: BTreeMap<u32, IdentityPublicKey>, proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        self.identities.create_identity_create_transition_using_public_keys(public_keys, proof)
            .map_err(Error::from)
            .and_then(|(_identity, transition)|
                Self::sign_transition(StateTransition::IdentityCreate, transition, private_key))
    }
    pub fn identity_registration_signed_transition_with_public_key_at_index(&self, public_key: IdentityPublicKey, index: u32, proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransition, Error> {
        self.identities.create_identity_create_transition_using_public_keys(BTreeMap::from_iter([(index, public_key)]), proof)
            .map_err(Error::from)
            .and_then(|(_identity, transition)|
                Self::sign_transition(StateTransition::IdentityCreate, transition, private_key))
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
            self.sdk.version(),
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
    pub fn document_single_signed_transition(
        &self,
        action_type: DocumentTransitionActionType,
        document_type: DocumentType,
        document: Document,
        entropy: [u8; 32],
        private_key: OpaqueKey
    ) -> Result<StateTransition, Error> {
        let doc_type_ref = document_type.as_ref();
        let documents_iter = IndexMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::from_iter([(action_type, vec![(document, doc_type_ref, Bytes32(entropy), None)])]);
        let mut nonce_counter = BTreeMap::<(Identifier, Identifier), u64>::new();
        let transition = self.documents.create_state_transition(documents_iter, &mut nonce_counter)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::Batch, transition, private_key)
    }

    #[cfg(feature = "state-transitions")]
    pub fn document_single_on_table_signed_transition(
        &self,
        data_contract: DataContract,
        action_type: DocumentTransitionActionType,
        table_name: &str,
        document: Document,
        entropy: [u8; 32],
        private_key: OpaqueKey
    ) -> Result<StateTransition, Error> {
        let document_type = data_contract.document_type_for_name(table_name).map_err(Error::from)?;
        let documents_iter = IndexMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::from_iter([(action_type, vec![(document, document_type, Bytes32(entropy), None)])]);
        let mut nonce_counter = BTreeMap::<(Identifier, Identifier), u64>::new();
        let transition = self.documents.create_state_transition(documents_iter, &mut nonce_counter)
            .map_err(Error::from)?;
        Self::sign_transition(StateTransition::Batch, transition, private_key)
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

    /// Publish state transition
    pub async fn identity_register(&self, identity: Identity, proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("identity_register: {identity:?} -- {proof:?} -- {private_key:?}");
        let signed_transition = self.identity_registration_signed_transition(identity, proof, private_key)?;
        self.publish_state_transition(signed_transition).await
    }
    pub async fn identity_register2(&self, identity: Identity, proof: AssetLockProof, private_key: OpaqueKey) -> Result<Identity, Error> {
        println!("identity_register: {identity:?} -- {proof:?} -- {private_key:?}");
        let maybe_private_key = private_key.convert_opaque_key_to_ecdsa_private_key(&self.chain_type).map_err(Error::KeyError)?;
        identity.put_to_platform_and_wait_for_response(self.sdk_ref(), proof, &maybe_private_key, &self.callback_signer, Some(PutSettings::default())).await
            .map_err(Error::from)
    }


    pub async fn identity_register_using_public_keys(&self, public_keys: BTreeMap<u32, IdentityPublicKey>, proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
        println!("identity_register_using_public_keys: {public_keys:?} -- {proof:?} -- {private_key:?}");
        let signed_transition = self.identity_registration_signed_transition_with_public_keys(public_keys, proof, private_key)?;
        self.publish_state_transition(signed_transition).await
    }

    pub async fn create_and_publish_registration_transition(
        &self,
        model: &mut IdentityModel,
        asset_lock_transaction: Transaction,
        core_chain_locked_height: u32,
        is_lock: Option<InstantLock>,
        save_key_if_need: bool,
        storage_context: *const c_void,
        context: *const c_void
    ) -> Result<bool, Error> {
        let debug_string = format!("[PlatformSDK: {}] register identity", model.unique_id.to_lower_hex_string());
        let asset_lock_tx_id = asset_lock_transaction.txid();
        println!("{debug_string}: asset_lock_tx_id: {} is_lock_tx_id: {}", asset_lock_tx_id.to_string(), is_lock.as_ref().map(|tx| tx.txid.to_string()).unwrap_or_default());
        if !model.has_registration_funding_private_key() {
            return Err(Error::Any(500, "The blockchain identity funding private key should be first created with createFundingPrivateKeyWithCompletion".to_string()))
        }
        let index = model.first_index_of_ecdsa_auth_key_create_if_needed(SecurityLevel::MASTER, save_key_if_need, context)?;
        println!("{debug_string}: index: {}", index);
        if (index & !BIP32_HARD) != 0 {
            return Err(Error::Any(0, "The index should be 0 here".to_string()));
        }

        let output_index = 0;
        let proof = match is_lock {
            Some(instant_lock) => {
                AssetLockProof::Instant(InstantAssetLockProof {
                    instant_lock,
                    transaction: asset_lock_transaction.clone(),
                    output_index,
                })
            },
            None => {
                AssetLockProof::Chain(ChainAssetLockProof {
                    core_chain_locked_height,
                    out_point: OutPoint::new(asset_lock_tx_id, output_index),
                })
            }
        };
        let opaque_private_key = model.registration_funding_private_key()
            .ok_or(Error::Any(0, "The registration funding private key should be set".to_string()))?;
        let opaque_public_key = model.key_at_index(index)
            .ok_or(Error::Any(0, format!("The public key at index:{} should be set", index)))?;

        let private_key = opaque_private_key.convert_opaque_key_to_ecdsa_private_key(&self.chain_type).map_err(Error::KeyError)?;
        let public_key = identity_registration_public_key(index, opaque_public_key);
        let public_keys = BTreeMap::from_iter([(index, public_key.clone())]);
        let proof_id = proof.create_identifier().map_err(Error::from)?;
        let identity = Identity::new_with_id_and_keys(proof_id, public_keys.clone(), self.sdk.version()).map_err(Error::from)?;
        println!("{debug_string}: sdk: {:p} identity: {:p} {identity:?} model: {:p} proof: {:p} {proof:?} private_key: {:p} signer: {:p}", self.sdk_ref(), &identity, model, &proof, &private_key, &self.callback_signer);
        let settings = PutSettings::default();
        let state_transition = identity.put_to_platform(self.sdk_ref(), proof, &private_key, &self.callback_signer, Some(settings)).await.map_err(Error::from)?;
        println!("{debug_string}: state_transition: {:p} {:?}", &state_transition, state_transition);
        let result = Identity::wait_for_response(self.sdk_ref(), state_transition, Some(settings)).await;
        println!("{debug_string}: result: {:?}", result);
        match result {
            Ok(identity) => {
                model.update_with_state_information(identity, storage_context, context)?;
                Ok(true)
            }
            Err(dash_sdk::Error::Protocol(ProtocolError::ConsensusError(ref err))) => {
                if let ConsensusError::BasicError(BasicError::InvalidInstantAssetLockProofSignatureError(err)) = &**err {
                    println!("{} ==> try with chain lock proof", err);
                    let proof = AssetLockProof::Chain(ChainAssetLockProof {
                        core_chain_locked_height,
                        out_point: OutPoint::new(asset_lock_tx_id, output_index),
                    });
                    let proof_id = proof.create_identifier().map_err(Error::from)?;
                    let identity = Identity::new_with_id_and_keys(proof_id, public_keys.clone(), self.sdk.version()).map_err(Error::from)?;
                    let state_transition = identity.put_to_platform(self.sdk_ref(), proof, &private_key, &self.callback_signer, Some(PutSettings::default())).await.map_err(Error::from)?;
                    let identity = Identity::wait_for_response(self.sdk_ref(), state_transition, Some(settings)).await.map_err(Error::from)?;
                    model.update_with_state_information(identity, storage_context, context)?;
                    Ok(true)
                } else {
                    Err(Error::DashSDKError(format!("{err:?}")))
                }
            },
            Err(e) => Err(Error::from(e))
        }
    }

    pub async fn identity_register_using_public_key_at_index(&self, public_key: IdentityPublicKey, index: u32, proof: AssetLockProof, private_key: OpaqueKey) -> Result<Identity, Error> {
        println!("identity_register_using_public_key_at_index: {public_key:?} -- {index} -- {proof:?} -- {private_key:?}");
        let public_keys = BTreeMap::from_iter([(index, public_key)]);
        let identity = proof.create_identifier()
            .and_then(|identifier| Identity::new_with_id_and_keys(identifier, public_keys, self.sdk.version()))
            .map_err(Error::from)?;
        let maybe_private_key = private_key.convert_opaque_key_to_ecdsa_private_key(&self.chain_type).map_err(Error::KeyError)?;
        identity.put_to_platform_and_wait_for_response(self.sdk_ref(), proof, &maybe_private_key, &self.callback_signer, Some(PutSettings::default())).await
            .map_err(Error::from)
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
        action_type: DocumentTransitionActionType,
        document_type: DocumentType,
        document: Document,
        entropy: [u8; 32],
        private_key: OpaqueKey
    ) -> Result<StateTransitionProofResult, Error> {
        // TODO: switch onto DocumentsBatchTransition::new_document_creation_transition_from_document
        // DocumentsBatchTransition::DocumentsBatchTransition::new_document_creation_transition_from_document()
        println!("document_single: {action_type:?} -- {document_type:?} -- {document:?} -- {} -- {private_key:?}", entropy.to_lower_hex_string());
        let signed_transition = self.document_single_signed_transition(action_type, document_type, document, entropy, private_key)?;
        self.publish_state_transition(signed_transition).await
    }
    #[cfg(feature = "state-transitions")]
    pub async fn document_single2(
        &self,
        document_type: DocumentType,
        document: Document,
        entropy: [u8; 32],
        identity_public_key: IdentityPublicKey,
    ) -> Result<Document, Error> {
        println!("document_single2: {document_type:?} -- {document:?} -- {}", entropy.to_lower_hex_string());
        document.put_to_platform_and_wait_for_response(self.sdk_ref(), document_type, entropy, identity_public_key, None, &self.callback_signer, Some(PutSettings::default())).await
            .map_err(Error::from)
    }

    #[cfg(feature = "state-transitions")]
    pub async fn document_single_on_table(
        &self,
        data_contract: DataContract,
        action_type: DocumentTransitionActionType,
        table_name: &str,
        document: Document,
        entropy: [u8; 32],
        private_key: OpaqueKey
    ) -> Result<StateTransitionProofResult, Error> {
        println!("document_single_on_table: {data_contract:?} -- {action_type:?} -- {table_name} -- {document:?} -- {} -- {private_key:?}", entropy.to_lower_hex_string());
        let signed_transition = self.document_single_on_table_signed_transition(data_contract, action_type, table_name, document, entropy, private_key)?;
        self.publish_state_transition(signed_transition).await
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
        document_type.create_document_from_data(dict, owner_id, 1000, 1000, entropy, self.sdk.version())
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
        let owner_id = Identifier::from(identity_id);
        let document = document_type.create_document_from_data(value, owner_id, 1000, 1000, entropy, self.sdk.version())
            .map_err(Error::from)?;
        let documents_iter = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::from_iter([(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy), None)])]);
        let signed_transition = self.document_batch_signed_transition(documents_iter, private_key)?;
        self.publish_state_transition(signed_transition).await
    }

    pub async fn register_username_domains_for_username_full_paths<
        SUC: Fn(*const c_void, UsernameStatus) + Send + Sync + 'static,
    >(
        &self,
        contract: DataContract,
        identity_id: [u8; 32],
        username_values: Vec<Value>,
        entropy: [u8; 32],
        private_key: OpaqueKey,
        save_context: *const c_void,
        save_callback: SUC,
    ) -> Result<StateTransitionProofResult, Error> {
        let document_type = contract.document_type_for_name("domain")
            .map_err(ProtocolError::from)?;
        let owner_id = Identifier::from(identity_id);
        let mut documents = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::new();
        for value in username_values.into_iter() {
            let document = document_type.create_document_from_data(value, owner_id, 1000, 1000, entropy, self.sdk.version())
                .map_err(Error::from)?;
            documents.insert(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy), None)]);
        }
        let signed_transition = self.document_batch_signed_transition(documents, private_key)?;
        self.publish_state_transition(signed_transition).await
            .map(|result| {
                save_callback(save_context, UsernameStatus::Confirmed);
                result
            })
    }

    pub async fn register_preordered_salted_domain_hashes_for_username_full_paths<
        SUC: Fn(*const c_void, UsernameStatus) + Send + Sync + 'static,
    >(
        &self,
        contract: DataContract,
        identity_id: [u8; 32],
        salted_domain_hashes: Vec<Vec<u8>>,
        entropy: [u8; 32],
        private_key: OpaqueKey,
        save_context: *const c_void,
        save_callback: SUC,
    ) -> Result<StateTransitionProofResult, Error> {
        let document_type = contract.document_type_for_name("preorder")
            .map_err(ProtocolError::from)?;
        let owner_id = Identifier::from(identity_id);
        let mut documents = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::new();
        for salted_domain_hash in salted_domain_hashes.into_iter() {
            let map = ValueMap::from_iter([(Value::Text("saltedDomainHash".to_string()), Value::Bytes(salted_domain_hash))]);
            let document = document_type.create_document_from_data(Value::Map(map), owner_id, 1000, 1000, entropy, self.sdk.version())
                .map_err(Error::from)?;
            documents.insert(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy), None)]);
        }

        let signed_transition = self.document_batch_signed_transition(documents, private_key)?;
        save_callback(save_context, UsernameStatus::PreorderRegistrationPending);

        self.publish_state_transition(signed_transition).await
            .map(|result| {
                save_callback(save_context, UsernameStatus::Preordered);
                result
            })
    }

    pub async fn register_preordered_salted_domain_hash_for_username_full_path(
        &self, 
        contract: DataContract,
        identity_id: [u8; 32], 
        identity_public_key: IdentityPublicKey, 
        salted_domain_hash: Vec<u8>, 
        entropy: [u8; 32]
    ) -> Result<Document, Error> {
        println!("register_preordered_salted_domain_hash_for_username_full_path: {} -- {identity_public_key:?} -- {} -- {}", identity_id.to_lower_hex_string(), salted_domain_hash.to_lower_hex_string(), entropy.to_lower_hex_string());
        let map = Value::Map(ValueMap::from_iter([(Value::Text("saltedDomainHash".to_string()), Value::Bytes(salted_domain_hash))]));
        let document_type = contract.document_type_for_name("preorder")
            .map_err(Error::from)?;
        let document = document_type.create_document_from_data(map, Identifier::from(identity_id), 0, 0, entropy, self.sdk.version())
            .map_err(Error::from)?;
        self.document_single2(document_type.to_owned_document_type(), document, entropy, identity_public_key).await
    }

    // pub async fn register_preordered_salted_domain_hashes_for_username_full_paths2<
    //     SUC: Fn(*const std::os::raw::c_void, UsernameStatus) + Send + Sync + 'static,
    // >(
    //     &self,
    //     contract: DataContract,
    //     identity_id: [u8; 32],
    //     salted_domain_hashes: Vec<Vec<u8>>,
    //     entropy: [u8; 32],
    //     private_key: OpaqueKey,
    //     save_context: *const std::os::raw::c_void,
    //     save_callback: SUC,
    // ) -> Result<StateTransitionProofResult, Error> {
    //     let document_type = contract.document_type_for_name("preorder")
    //         .map_err(ProtocolError::from)?;
    //     let owner_id = Identifier::from(identity_id);
    //     let mut documents = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32)>>::new();
    //     for salted_domain_hash in salted_domain_hashes.into_iter() {
    //         let map = Value::Map(ValueMap::from_iter([(Value::Text("saltedDomainHash".to_string()), Value::Bytes(salted_domain_hash))]));
    //         let document = document_type.create_document_from_data(map, owner_id, 0, 0, entropy, self.sdk.version())
    //             .map_err(Error::from)?;
    //         documents.insert(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy))]);
    //     }
    //
    //     Document::put_to_platform_and_wait_for_response(self.sdk.as_ref(), )
    //
    //     let signed_transition = self.document_batch_signed_transition(documents, private_key)?;
    //     save_callback(save_context, UsernameStatus::PreorderRegistrationPending);
    //
    //     self.publish_state_transition(signed_transition).await
    //         .map(|result| {
    //             save_callback(save_context, UsernameStatus::Preordered);
    //             result
    //         })
    //
    //     // document.put_to_platform_and_wait_for_response(self.sdk.as_ref(), document_type, entropy, identity_public_key, &self.callback_signer, Some(PutSettings::default())).await
    //     //     .map_err(Error::from)
    //
    // }

    pub async fn sign_and_publish_profile(
        &self,
        contract: DataContract,
        identity_id: [u8; 32],
        profile: Profile,
        entropy: [u8; 32],
        document_id: Option<[u8; 32]>,
        private_key: OpaqueKey
    ) -> Result<StateTransitionProofResult, Error> {
        let document_type = contract.document_type_for_name("profile")
            .map_err(ProtocolError::from)?;
        let owner_id = Identifier::from(identity_id);
        let document = match document_id {
            None =>
                document_type.create_document_from_data(profile.to_value(), owner_id, 1000, 1000, entropy, self.sdk.version()),
            Some(document_id) =>
                document_type.create_document_with_prevalidated_properties(Identifier::from(document_id), owner_id, 1000, 1000, profile.to_prevalidated_properties(), self.sdk.version()),
        }.map_err(Error::from)?;
        let documents_iter = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::from_iter([(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy), None)])]);
        let signed_transition = self.document_batch_signed_transition(documents_iter, private_key)?;
        self.publish_state_transition(signed_transition).await
    }

    // pub async fn check_ping_times(&self, masternodes: Vec<MasternodeEntry>) -> Result<GetStatusResponse, Error> {
    //     self.sdk_ref()
    //         .execute(GetStatusRequest::default(), RequestSettings::default())
    // }

    pub async fn register_usernames_at_stage(&self, model: &mut IdentityModel, status: UsernameStatus, context: *const c_void) -> Result<bool, Error> {
        let username_full_paths = model.username_full_paths_with_status(status);
        println!("[PlatformSDK] [Identity: {}] register_usernames_at_stage: {status:?}: username_full_path: {:?}", model.unique_id.to_lower_hex_string(), username_full_paths);
        if username_full_paths.is_empty() {
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoUsernameFullPathsWithStatus(status)))
        } else {
            match status {
                UsernameStatus::Initial =>
                    self.register_initial_usernames(model, username_full_paths, context).await,
                UsernameStatus::PreorderRegistrationPending =>
                    self.register_preorder_registration_pending_usernames(model, username_full_paths, context).await,
                UsernameStatus::Preordered =>
                    self.register_preordered_usernames(model, username_full_paths, context).await,
                UsernameStatus::RegistrationPending =>
                    self.register_registration_pending_usernames(model, username_full_paths, context).await,
                _ =>
                    Err(Error::UsernameRegistrationError(UsernameRegistrationError::NotSupported(status))),
            }
        }
    }

    pub async fn register_initial_usernames(&self, model: &mut IdentityModel, username_full_paths: Vec<String>, context: *const c_void) -> Result<bool, Error> {
        let salted_domain_hashes = model.salted_domain_hashes_for_username_full_paths(&username_full_paths, context);
        if salted_domain_hashes.is_empty() {
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoUsernamePreorderDocuments(UsernameStatus::Initial, username_full_paths)))
        } else {
            model.create_new_ecdsa_auth_key_of_level_if_needed(context, DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL)?;
            let identity_public_key = model.first_identity_public_key(DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL, DEFAULT_USERNAME_REGISTRATION_PURPOSE)
                .ok_or(Error::Any(0, "Key with security_level: HIGH and purpose: AUTHENTICATION should exist".to_string()))?;
            let entropy = <[u8; 32]>::random();
            let data_contract = self.get_dpns_data_contract_in_context(context);
            for salted_domain_hash in salted_domain_hashes.values() {
                let map = Value::Map(ValueMap::from_iter([(Value::Text("saltedDomainHash".to_string()), Value::Bytes32(salted_domain_hash.clone()))]));
                let document_type = data_contract.document_type_for_name("preorder")
                    .map_err(Error::from)?;
                let document = document_type.create_document_from_data(map, model.identifier(), 0, 0, entropy, self.sdk.version())
                    .map_err(Error::from)?;
                self.document_single2(document_type.to_owned_document_type(), document, entropy, identity_public_key.clone()).await?;
            }
            model.save_username_in_context(context, SaveUsernameContext::confirmed_username_full_paths(model.usernames_and_domains(username_full_paths)));
            // self.save_username_in_context(context, )
            // [self setAndSaveUsernameFullPaths:usernameFullPaths toStatus:DSBlockchainIdentityUsernameStatus_Preordered inContext:context];


            Ok(true)
            //self.register_preorder_registration_pending_usernames(platform, context).await
        }
    }
    pub async fn register_preorder_registration_pending_usernames(&self, model: &mut IdentityModel, username_full_paths: Vec<String>, context: *const c_void) -> Result<bool, Error> {
        let salted_domain_hashes = model.salted_domain_hashes_for_username_full_paths(&username_full_paths, context);
        if salted_domain_hashes.is_empty() {
            println!("[Identity] OK (No saltedDomainHashes)");
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoUsernamePreorderDocuments(UsernameStatus::PreorderRegistrationPending, username_full_paths)))

            // self.register_preordered_usernames(platform, context).await
        } else {
            let mut all_found = false;
            let data_contract = self.get_dpns_data_contract_in_context(context);
            let documents = self.salted_domain_hashes().stream_preorder_salted_domain_hashes_with_contract(salted_domain_hashes.values().cloned().collect(), data_contract, RetryStrategy::Linear(4), SaltedDomainHashValidator::None, 100).await?;
            for (username_full_path, salted_domain_hash) in salted_domain_hashes {
                for document in documents.values() {
                    if let Some(document) = document {
                        all_found &= model.process_salted_domain_hash_document(&username_full_path, salted_domain_hash, document, context);
                    } else {
                        all_found &= false;
                    }
                }
            }
            if all_found {
                Ok(true)
                // self.register_preordered_usernames(platform, context).await
            } else {
                // TODO: This needs to be done per username and not for all usernames
                model.save_username_in_context(context, SaveUsernameContext::initial_username_full_paths(model.usernames_and_domains(username_full_paths)));
                Ok(false)
                // self.register_initial_usernames(platform, context).await
            }
        }
    }

    pub async fn register_preordered_usernames(&self, model: &mut IdentityModel, username_full_paths: Vec<String>, context: *const c_void) -> Result<bool, Error> {
        let salted_domain_hashes = model.salted_domain_hashes_for_username_full_paths(&username_full_paths, context);
        if salted_domain_hashes.is_empty() {
            Err(Error::UsernameRegistrationError(UsernameRegistrationError::NoUsernamePreorderDocuments(UsernameStatus::Preordered, username_full_paths)))
        } else {
            model.create_new_ecdsa_auth_key_of_level_if_needed(context, SecurityLevel::MASTER)?;
            let data_contract = self.get_dpns_data_contract_in_context(context);
            let document_type = data_contract.document_type_for_name("domain")
                .map_err(Error::from)?;
            let documents = model.create_salted_domain_hashes_documents(self.sdk.version(), &salted_domain_hashes, document_type)?;
            if model.is_local {
                Err(Error::Any(0, "Identity is not local".to_string()))
            } else {
                let private_key_data = model.get_main_private_key_in_context(context)
                    .ok_or(Error::Any(0, "No private key".to_string()))?;
                let mut nonce_counter = BTreeMap::<(Identifier, Identifier), u64>::new();
                let state_transition = self.documents.create_state_transition(documents, &mut nonce_counter)
                    .map_err(Error::from)?;
                self.sign_and_publish_state_transition(&private_key_data, key_kind_to_key_type(model.current_main_key_type), StateTransition::Batch(state_transition)).await?;
                model.save_username_in_context(context, SaveUsernameContext::preordered_username_full_paths(model.usernames_and_domains(username_full_paths)));
                Ok(true)
                // self.register_registration_pending_usernames(platform, context).await
            }
        }
    }

    pub async fn register_registration_pending_usernames(&self, model: &mut IdentityModel, username_full_paths: Vec<String>, context: *const c_void) -> Result<bool, Error> {
        let domains = domains_for_username_full_paths(&username_full_paths);
        let data_contract = self.get_dpns_data_contract_in_context(context);
        // let mut finished = false;
        let mut count_all_found = 0;
        let mut count_returned = 0;
        let domains_count = domains.len();
        for (domain, usernames) in domains {
            let documents = self.usernames().stream_usernames_with_contract(domain, usernames.clone(), data_contract.clone(), RetryStrategy::Linear(5), UsernameValidator::None, 5000).await?;
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
                            model.set_username_status_confirmed(username.clone(), normalized_parent_domain_name.to_string(), label.to_string());
                            model.save_username_in_context(context, SaveUsernameContext::confirmed_username(&username, normalized_parent_domain_name));
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
                    Ok(true)
                } else {
                    // TODO: This needs to be done per username and not for all usernames
                    model.save_username_in_context(context, SaveUsernameContext::preordered_username_full_paths(model.usernames_and_domains(username_full_paths)));
                    // TODO: should we introduce progress here to not to wait this step in some circumstances

                    // self.register_preordered_usernames(platform, context).await
                    Ok(false)
                }
            }
        }
        Ok(count_all_found == domains_count)
    }

    // pub async fn incoming_contact_requests_with_contract(&self, model: &mut IdentityModel, context: *const c_void) -> Result<bool, Error> {
    //     // let mut debug_string = format!("[PlatformSDK] Fetch Incoming Contact Requests: (after: {})");
    //     // NSMutableString *debugInfo = [NSMutableString stringWithFormat:@"%@ Fetch Incoming Contact Requests: (after: %@)", self.logPrefix, startAfter ? startAfter.hexString : @"NULL"];
    //
    // }
    // pub async fn outgoing_contact_requests_with_contract(&self, model: &mut IdentityModel, context: *const c_void) -> Result<bool, Error> {
    //
    // }
}


impl PlatformSDK {
    pub fn new<
        GetQuorumPublicKey: Fn(u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync + 'static,
        GetDataContract: Fn(*const c_void, [u8; 32]) -> Option<DataContract> + Send + Sync + 'static,
        GetPlatformActivationHeight: Fn(*const c_void) -> u32 + Send + Sync + 'static,
        Sign: Fn(*const c_void, IdentityPublicKey) -> Option<OpaqueKey> + Send + Sync + 'static,
        CanSign: Fn(*const c_void, IdentityPublicKey) -> bool + Send + Sync + 'static,
        GetDataContractFromCache: Fn(*const c_void, SystemDataContract) -> DataContract + Send + Sync + 'static,
    >(
        cache: Arc<PlatformCache>,
        get_quorum_public_key: Arc<GetQuorumPublicKey>,
        get_data_contract: GetDataContract,
        get_platform_activation_height: GetPlatformActivationHeight,
        callback_signer: Sign,
        callback_can_sign: CanSign,
        get_data_contract_from_cache: GetDataContractFromCache,
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

        let runtime = tokio::runtime::Builder::new_current_thread()
            .thread_name("dash-spv-platform")
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        Self {
            cache,
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
            chain_type,
            sdk: sdk_arc
        }
    }

    pub fn sdk_ref(&self) -> &Sdk {
        &self.sdk
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

    pub fn get_data_contract_in_context(&self, context: *const c_void, system_data_contract: SystemDataContract) -> DataContract {
        (self.get_data_contract_from_cache)(context, system_data_contract)
    }
    pub fn get_dpns_data_contract_in_context(&self, context: *const c_void) -> DataContract {
        self.get_data_contract_in_context(context, SystemDataContract::DPNS)
    }
    pub fn get_dashpay_data_contract_in_context(&self, context: *const c_void) -> DataContract {
        self.get_data_contract_in_context(context, SystemDataContract::Dashpay)
    }


}
#[cfg(test)]
mod tests {

    // pub fn identity_contract_bounds(id: Identifier, contract_identifier: Option<Identifier>) -> Result<Identity, ProtocolError> {
    //     let mut rng = rand::rngs::StdRng::from_entropy();
    //     let ipk1 = IdentityPublicKeyV0::random_ecdsa_master_authentication_key_with_rng(1, &mut rng, LATEST_PLATFORM_VERSION)?.0;
    //     let ipk2 = IdentityPublicKeyV0::random_ecdsa_master_authentication_key_with_rng(1, &mut rng, LATEST_PLATFORM_VERSION)?.0;
    //     let public_keys = BTreeMap::from_iter([(1, IdentityPublicKey::V0(
    //         IdentityPublicKeyV0 {
    //             id: ipk1.id(),
    //             purpose: Purpose::AUTHENTICATION,
    //             security_level: SecurityLevel::MASTER,
    //             contract_bounds: contract_identifier.map(|id| ContractBounds::SingleContract { id }),
    //             key_type: KeyType::ECDSA_SECP256K1,
    //             read_only: false,
    //             data: ipk1.data().clone(),
    //             disabled_at: Some(1)
    //         }
    //     )), (2, IdentityPublicKey::V0(
    //         IdentityPublicKeyV0 {
    //             id: ipk2.id(),
    //             purpose: Purpose::AUTHENTICATION,
    //             security_level: SecurityLevel::MASTER,
    //             contract_bounds: contract_identifier.map(|id| ContractBounds::SingleContract { id }),
    //             key_type: KeyType::ECDSA_SECP256K1,
    //             read_only: ipk2.read_only(),
    //             data: ipk2.data().clone(),
    //             disabled_at: Some(1)
    //         }
    //     ))]);
    //     Ok(Identity::V0(IdentityV0 { id, public_keys, balance: 2, revision: 1 }))
    // }

    // #[tokio::test]
    // async fn test_mainnet_get_identities_for_wallets_public_keys() {
    //     async fn mainnet_get_identities_for_wallets_public_keys() -> Result<BTreeMap<String, BTreeMap<[u8; 20], Identity>>, Error> {
    //         let key_hashes =
    //             [[56, 130, 69, 49, 128, 208, 91, 105, 110, 162, 39, 35, 66, 49, 38, 28, 133, 213, 133, 252], [91, 201, 141, 60, 109, 100, 243, 8, 136, 121, 118, 100, 169, 165, 198, 96, 228, 231, 76, 164], [238, 40, 164, 26, 84, 158, 90, 227, 77, 165, 195, 121, 94, 23, 24, 160, 173, 14, 21, 48], [102, 22, 141, 109, 43, 97, 177, 93, 105, 200, 103, 76, 134, 17, 198, 209, 120, 167, 71, 53], [59, 216, 144, 232, 223, 201, 28, 131, 40, 174, 25, 104, 227, 51, 26, 85, 54, 46, 98, 114]];
    //
    //         let context_arc = Arc::new(FFIThreadSafeContext::new(std::ptr::null()));
    //         let get_data_contract = |ctx, identifier| {
    //             println!("get_data_contract: {:?}", identifier);
    //             Err(ContextProviderError::Generic("DDDDD".to_string()))
    //         };
    //         let get_quorum_public_key = |ctx, quorum_type, quorum_hash, core_chain_locked_height| {
    //             println!("get_quorum_public_key: {:?} {:?} {}", quorum_type, quorum_hash, core_chain_locked_height);
    //             Err(ContextProviderError::Generic("DDDDD".to_string()))
    //         };
    //         let get_platform_activation_height = |ctx| {
    //             println!("get_platform_activation_height");
    //             Ok(0)
    //         };
    //         // let masternode_provider = Arc::new(MasternodeProvider::new());
    //         let address_list = Vec::from_iter(MAINNET_ADDRESS_LIST.iter().filter_map(|s| Address::from_str(format!("https://{s}:443").as_str()).ok()));
    //         let sdk = create_sdk(
    //             PlatformProvider::new(get_quorum_public_key, get_data_contract, get_platform_activation_height, context_arc.clone()), address_list);
    //
    //         let sdk_arc = Arc::new(sdk);
    //         let manager = IdentitiesManager::new(&sdk_arc);
    //         let key_hashes = BTreeMap::from_iter([("fcd1b9a4fc61468a".to_string(), key_hashes.to_vec())]);
    //         manager.get_identities_for_wallets_public_keys(key_hashes).await
    //     }
    //
    //     match mainnet_get_identities_for_wallets_public_keys().await {
    //         Ok(result) => {
    //             println!("Ok: {:?}", result);
    //         },
    //         Err(err) => {
    //             println!("Error: {:?}", err);
    //         }
    //     }
    // }

    // fn values_to_documents<'a>(document_type: DocumentTypeRef<'a>, identity_id: [u8; 32], entropy: [u8; 32], values: Vec<Value>, version: &'a PlatformVersion) -> Result<IndexMap<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef<'a>, Bytes32)>>, Error> {
    //     let owner_id = Identifier::from(identity_id);
    //     let mut documents = IndexMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32)>>::new();
    //     for value in values.into_iter() {
    //         let document = document_type.create_document_from_data(value, owner_id, 1000, 1000, entropy, version)
    //             .map_err(Error::from)?;
    //         documents.insert(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy))]);
    //     }
    //     Ok(documents)
    // }

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
    // #[tokio::test]
    // async fn search_identity_by_name() {
    //     use dpp::system_data_contracts::SystemDataContract;
    //     use dash_sdk::platform::DocumentQuery;
    //     let chain = ChainType::TestNet;
    //     let sdk = create_test_sdk(&chain);
    //     let contract_id = SystemDataContract::DPNS.id();
    //     let sdk_arc = Arc::new(sdk);
    //     let doc_manager = DocumentsManager::new(&sdk_arc, chain);
    //
    //     let query = DocumentQuery::new_with_data_contract_id(&sdk_arc, contract_id, "domain").await;
    //     match query {
    //         Ok(doc_query) => {
    //             match doc_manager.documents_with_query(doc_query).await {
    //                 Ok(result) => {
    //                     println!("Ok: {:?}", result);
    //                 }
    //                 Err(err) => {
    //                     println!("Error: {:?}", err);
    //                 }
    //             }
    //         }
    //         Err(error) => {
    //             println!("{:?}", error);
    //         }
    //     }
    //     // let domain = "dash";
    //     // let name = "asdtwotwooct";
    //
    //
    //
    // }

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
