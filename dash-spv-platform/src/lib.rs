pub mod identity;
pub mod provider;
pub mod signer;
pub mod thread_safe_context;
pub mod error;
pub mod util;
pub mod contract;
pub mod document;
pub mod query;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::{dpp, Sdk, SdkBuilder};
use dash_sdk::dapi_client::Address;
use dash_sdk::dpp::dashcore::secp256k1::rand;
use dash_sdk::dpp::dashcore::secp256k1::rand::SeedableRng;
// use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
// use dash_sdk::dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dash_sdk::platform::FetchUnproved;
// use dash_sdk::platform::transition::put_document::PutDocument;
use dash_sdk::platform::types::evonode::EvoNode;
use dash_sdk::sdk::{AddressList, Uri};
use dpp::data_contract::DataContract;
use dpp::errors::ProtocolError;
use dpp::identity::{Identity, identity_public_key::{accessors::v0::IdentityPublicKeyGettersV0, contract_bounds::ContractBounds, IdentityPublicKey, KeyType, Purpose, SecurityLevel, v0::IdentityPublicKeyV0}, v0::IdentityV0};
use dpp::document::Document;
use dpp::prelude::{BlockHeight, CoreBlockHeight};
use drive::query::{OrderClause, WhereClause};
use drive_proof_verifier::{ContextProvider, error::ContextProviderError};
use drive_proof_verifier::types::EvoNodeStatus;
use platform_version::version::LATEST_PLATFORM_VERSION;
use platform_value::{BinaryData, Identifier};
use tokio::runtime::Runtime;
use crate::contract::manager::ContractsManager;
use crate::document::manager::DocumentsManager;
use crate::error::Error;
use crate::identity::manager::IdentitiesManager;
use crate::provider::PlatformProvider;
use crate::query::QueryKind;
use crate::signer::CallbackSigner;
use crate::thread_safe_context::FFIThreadSafeContext;

// #[no_mangle]
const DEFAULT_TESTNET_ADDRESS_LIST: [&str; 28] = [
    "34.214.48.68",
    "35.166.18.166",
    // "35.165.50.126",
    "52.42.202.128",
    "52.12.176.90",
    "44.233.44.95",
    "35.167.145.149",
    "52.34.144.50",
    "44.240.98.102",
    "54.201.32.131",
    // "52.10.229.11",
    "52.13.132.146",
    "44.228.242.181",
    "35.82.197.197",
    "52.40.219.41",
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
    "54.68.235.201",
    "52.13.250.182",
    "35.82.49.196",
    "44.232.196.6",
    "54.189.164.39",
    "54.213.204.85"
];
fn create_sdk<C: ContextProvider + 'static, T: IntoIterator<Item = Uri>>(provider: C, address_list: T) -> Sdk {
    SdkBuilder::with_context_provider(
        SdkBuilder::new(AddressList::from_iter(address_list)),
        provider)
        .build()
        .unwrap()
}

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct PlatformSDK {
    pub runtime: *mut Runtime,
    pub sdk: *const Sdk,
    pub callback_signer: CallbackSigner,
    pub identity_manager: IdentitiesManager,
    pub contract_manager: ContractsManager,
    pub doc_manager: DocumentsManager,
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

impl PlatformSDK {
    pub fn sdk_ref(&self) -> &Sdk {
        unsafe { &*self.sdk }
    }
}
#[ferment_macro::export]
impl PlatformSDK {
    pub fn new<
        QP: Fn(*const std::os::raw::c_void, u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync + 'static,
        DC: Fn(*const std::os::raw::c_void, Identifier) -> Result<Option<Arc<DataContract>>, ContextProviderError> + Send + Sync + 'static,
        AH: Fn(*const std::os::raw::c_void) -> Result<CoreBlockHeight, ContextProviderError> + Send + Sync + 'static,
        CS: Fn(*const std::os::raw::c_void, &IdentityPublicKey, Vec<u8>) -> Result<BinaryData, ProtocolError> + Send + Sync + 'static,
        CCS: Fn(*const std::os::raw::c_void, &IdentityPublicKey) -> bool + Send + Sync + 'static,
        AC1: Fn(*const std::os::raw::c_void, u32, Vec<u8>, u32) -> Vec<u8> + Send + Sync + 'static,
        AC2: Fn(u32, [u8; 32], u32) -> [u8; 96] + Send + Sync + 'static,
        AC3: Fn(u32, [u8; 32], u32) -> [u8; 96],
        AC4: Fn(*const std::os::raw::c_void, u32, String) -> String
    >(
        get_quorum_public_key: QP,
        get_data_contract: DC,
        get_platform_activation_height: AH,
        callback_signer: CS,
        callback_can_sign: CCS,
        ac1: AC1,
        ac2: AC2,
        _ac3: AC3,
        _ac4: AC4,
        address_list: Option<Vec<&'static str>>,
        context: *const std::os::raw::c_void,
    ) -> Self {
        let context_arc = Arc::new(FFIThreadSafeContext::new(context));
        let sdk = create_sdk(
            PlatformProvider::new(get_quorum_public_key, get_data_contract, get_platform_activation_height, ac1, ac2, context_arc.clone()),
            address_list.unwrap_or(Vec::from_iter(DEFAULT_TESTNET_ADDRESS_LIST))
                .iter()
                .filter_map(|s| Uri::from_str(s).ok()));

        let sdk_arc = Arc::new(sdk);
        Self {
            identity_manager: IdentitiesManager::new(&sdk_arc),
            contract_manager: ContractsManager::new(&sdk_arc),
            doc_manager: DocumentsManager::new(&sdk_arc),
            runtime: ferment::boxed(Runtime::new().unwrap()),
            callback_signer: CallbackSigner::new(callback_signer, callback_can_sign, context_arc),
            sdk: Arc::into_raw(sdk_arc)
        }
    }

    pub async fn get_status(&self, address: &str) -> Result<bool, Error> {
        let evo_node = Uri::from_str(address)
            .map_err(|e| Error::DashSDKError(e.to_string()))
            .map(Address::from)
            .map(EvoNode::new)?;
        EvoNodeStatus::fetch_unproved(self.sdk_ref(), evo_node)
            .await
            .map_err(Error::from)
            .map(|status| status.is_some())
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
    pub async fn dpns_domain_starts_with(&self, contract_id: Identifier, document_type: &str, starts_with: &str) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        query_contract_docs!(self, contract_id, document_type, dpns_domain, starts_with)
    }
    pub async fn dpns_domain_by_id(&self, contract_id: Identifier, document_type: &str, unique_id: Identifier) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        query_contract_docs!(self, contract_id, document_type, records_identity, unique_id)
    }
    // pub async fn dpns_usernames(&self, contract_id: Identifier, document_type: &str, usernames: &'static [&'static str]) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
    pub async fn dpns_usernames(&self, contract_id: Identifier, document_type: &str, usernames: Vec<String>) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        let usernames_ref = &usernames.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        // TODO: ferment fails with ['a ['a str]]
        query_contract_docs!(self, contract_id, document_type, usernames, usernames_ref)
    }
    pub async fn find_username(&self, contract_id: Identifier, document_type: &str, starts_with: &str) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        query_contract_docs!(self, contract_id, document_type, dpns_domain, starts_with)
    }
    // pub async fn profile_for_user_id(&self, user_id: Identifier) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
    //
    //
    // }

    pub async fn outgoing_contact_requests(&self, contract_id: Identifier, document_type: &str, _since: u64) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        let contract = self.contract_manager.fetch_contract_by_id_error_if_none(contract_id).await?;
        let query = QueryKind::outgoing_contact_requests(contract, document_type)?;
        self.doc_manager.documents_with_query(query).await
    }
}

impl PlatformSDK  {
    pub async fn fetch_documents(
        &self,
        contract_id: Identifier,
        document_type: &str,
        where_clauses: Vec<WhereClause>,
        order_clauses: Vec<OrderClause>,
        limit: u32,
        start: Option<Start>
    ) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        let contract = self.contract_manager.fetch_contract_by_id_error_if_none(contract_id).await?;
        let query = QueryKind::generic(contract, document_type, where_clauses, order_clauses, limit, start)?;
        self.doc_manager.documents_with_query(query).await
    }
}

pub fn identity_contract_bounds(id: Identifier, contract_identifier: Option<Identifier>) -> Result<Identity, ProtocolError> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let ipk1 = IdentityPublicKeyV0::random_ecdsa_master_authentication_key_with_rng(1, &mut rng, LATEST_PLATFORM_VERSION)?.0;
    let ipk2 = IdentityPublicKeyV0::random_ecdsa_master_authentication_key_with_rng(1, &mut rng, LATEST_PLATFORM_VERSION)?.0;
    let public_keys = BTreeMap::from_iter([(1, IdentityPublicKey::V0(
        IdentityPublicKeyV0 {
            id: ipk1.id(),
            purpose: Purpose::AUTHENTICATION,
            security_level: SecurityLevel::MASTER,
            contract_bounds: contract_identifier.map(|id| ContractBounds::SingleContract { id }),
            key_type: KeyType::ECDSA_SECP256K1,
            read_only: false,
            data: ipk1.data().clone(),
            disabled_at: Some(1)
        }
    )), (2, IdentityPublicKey::V0(
        IdentityPublicKeyV0 {
            id: ipk2.id(),
            purpose: Purpose::AUTHENTICATION,
            security_level: SecurityLevel::MASTER,
            contract_bounds: contract_identifier.map(|id| ContractBounds::SingleContract { id }),
            key_type: KeyType::ECDSA_SECP256K1,
            read_only: ipk2.read_only(),
            data: ipk2.data().clone(),
            disabled_at: Some(1)
        }
    ))]);
    Ok(Identity::V0(IdentityV0 { id, public_keys, balance: 2, revision: 1 }))
}
