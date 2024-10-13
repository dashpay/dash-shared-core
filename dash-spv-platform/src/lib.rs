pub mod signer;
pub mod provider;
pub mod thread_safe_context;

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::{dpp, Error, Sdk, SdkBuilder};
use dash_sdk::dpp::dashcore::secp256k1::rand;
use dash_sdk::dpp::dashcore::secp256k1::rand::SeedableRng;
use dash_sdk::dpp::data_contract::accessors::v0::DataContractV0Getters;
use dash_sdk::dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dash_sdk::dpp::prelude::{BlockHeight, CoreBlockHeight};
use dash_sdk::platform::{DocumentQuery, Fetch, FetchMany};
use dash_sdk::platform::transition::put_document::PutDocument;
use dash_sdk::platform::types::identity::PublicKeyHash;
use dash_sdk::sdk::AddressList;

use drive_proof_verifier::{ContextProvider, error::ContextProviderError};
use dpp::data_contract::DataContract;
use dpp::errors::ProtocolError;
use dpp::identity::{Identity, identity_public_key::{accessors::v0::IdentityPublicKeyGettersV0, contract_bounds::ContractBounds, IdentityPublicKey, KeyType, Purpose, SecurityLevel, v0::IdentityPublicKeyV0}, v0::IdentityV0};
use dpp::document::{Document, DocumentV0Getters};
use dpp::util::entropy_generator::{DefaultEntropyGenerator, EntropyGenerator};
use drive::query::{OrderClause, WhereClause, WhereOperator};
use dash_sdk::sdk::Uri;
use platform_version::version::{LATEST_PLATFORM_VERSION, PlatformVersion};
use platform_value::{BinaryData, Identifier, Value};
use tokio::runtime::Runtime;
use crate::signer::CallbackSigner;
use crate::provider::PlatformProvider;
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
    pub sdk: *mut Sdk,
    pub callback_signer: CallbackSigner,
    pub foreign_identities: HashMap<Identifier, Identity>,
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
        Self {
            foreign_identities: HashMap::new(),
            runtime: ferment::boxed(Runtime::new().unwrap()),
            callback_signer: CallbackSigner::new(callback_signer, callback_can_sign, context_arc.clone()),
            sdk: ferment::boxed(
                create_sdk(
                    PlatformProvider::new(get_quorum_public_key, get_data_contract, get_platform_activation_height, ac1, ac2, context_arc),
                    address_list.unwrap_or(Vec::from_iter(DEFAULT_TESTNET_ADDRESS_LIST))
                        .iter()
                        .filter_map(|s| Uri::from_str(s).ok())))
        }
    }
    pub async fn fetch_contract_by_id(&self, id: Identifier) -> Result<Option<DataContract>, Error> {
        DataContract::fetch_by_identifier(self.sdk_ref(), id).await
    }
    pub async fn fetch_identity_by_id(&self, id: Identifier) -> Result<Option<Identity>, Error> {
        Identity::fetch_by_identifier(self.sdk_ref(), id).await
    }
    pub async fn fetch_identity_by_key_hash(&self, key_hash: PublicKeyHash) -> Result<Option<Identity>, Error> {
        Identity::fetch(self.sdk_ref(), key_hash).await
    }
    pub async fn fetch_identity_balance(&self, id: Identifier) -> Result<Option<u64>, Error> {
        u64::fetch_by_identifier(self.sdk_ref(), id).await
    }
    pub async fn put_document(
        &self,
        document: Document,
        contract_id: Identifier,
        document_type: &str,
        identity_public_key: IdentityPublicKey,
        block_height: BlockHeight,
        core_block_height: CoreBlockHeight
    ) -> Result<Document, Error> {
        let sdk = self.sdk_ref();
        match self.fetch_contract_by_id(contract_id).await? {
            None => Err(Error::Config("no contract".to_string())),
            Some(contract) => {
                let document_type = contract.document_type_for_name(document_type)
                    .map_err(ProtocolError::from)?;
                let entropy = DefaultEntropyGenerator.generate().unwrap();
                document_type
                    .create_document_from_data(
                        Value::from(document.properties()),
                        document.owner_id(),
                        block_height,
                        core_block_height,
                        entropy,
                        PlatformVersion::latest())
                    .map_err(Error::from)?
                    .put_to_platform_and_wait_for_response(
                        sdk,
                        document_type.to_owned_document_type(),
                        entropy,
                        identity_public_key,
                        Arc::new(contract),
                        &self.callback_signer)
                    .await
            },
        }
    }

    pub async fn dpns_domain_starts_with(&self, starts_with: &str, document_type: &str, contract_id: Identifier) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        match self.fetch_contract_by_id(contract_id).await? {
            None =>
                Err(Error::Config("Contract not exist".to_string())),
            Some(contract) =>
                self.documents_with_query(DocumentQuery::new(contract, document_type)?
                    .with_where(WhereClause {
                        field: "normalizedLabel".to_string(),
                        operator: WhereOperator::StartsWith,
                        value: Value::Text(starts_with.to_string())
                    })
                    .with_where(WhereClause {
                        field: "normalizedParentDomainName".to_string(),
                        operator: WhereOperator::Equal,
                        value: Value::Text("dash".to_string())
                    })
                    .with_order_by(OrderClause {
                        field: "normalizedLabel".to_string(), ascending: true
                    }))
                    .await
        }
    }
    pub async fn dpns_domain_by_id(&self, unique_id: Identifier, document_type: &str, contract_id: Identifier) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        match self.fetch_contract_by_id(contract_id).await? {
            None => Err(Error::Config("Contract not exist".to_string())),
            Some(contract) => {
                self.documents_with_query(DocumentQuery::new(contract, document_type)?
                    .with_where(WhereClause {
                        field: "records.identity".to_string(),
                        operator: WhereOperator::Equal,
                        value: Value::from(unique_id),
                    })).await
            }
        }
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
        match self.fetch_contract_by_id(contract_id).await? {
            Some(contract) => {
                let mut query = DocumentQuery::new(contract, document_type)?;
                query.where_clauses.extend(where_clauses);
                query.order_by_clauses.extend(order_clauses);
                query.limit = limit;
                query.start = start;
                self.documents_with_query(query).await
            },
            None =>
                Err(Error::Config("Contract not exist".to_string())),
        }
    }
    pub async fn documents_with_query(&self, query: DocumentQuery) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        Document::fetch_many(self.sdk_ref(), query).await
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
