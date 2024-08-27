mod identity;
mod contract;
pub mod document;
mod document_request;
mod provider;

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use dash_sdk::{dpp, Error, Sdk, SdkBuilder};
use dash_sdk::dpp::dashcore::secp256k1::rand;
use dash_sdk::dpp::dashcore::secp256k1::rand::SeedableRng;
use dash_sdk::platform::Fetch;

use drive_proof_verifier::{ContextProvider, error::ContextProviderError};
use dash_sdk::sdk::AddressList;
use dpp::data_contract::DataContract;
use dpp::errors::ProtocolError;
use dpp::identity::{Identity, identity_public_key::{accessors::v0::IdentityPublicKeyGettersV0, contract_bounds::ContractBounds, IdentityPublicKey, KeyType, Purpose, SecurityLevel, v0::IdentityPublicKeyV0}, v0::IdentityV0};
use http::Uri;
use platform_version::version::LATEST_PLATFORM_VERSION;
use platform_value::Identifier;
use tokio::runtime::Runtime;
use crate::document::CallbackSigner;
use crate::provider::PlatformProvider;

pub const ADDRESS_LIST: [&str; 28] = [
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

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct PlatformSDK {
    pub runtime: *mut Runtime,
    pub sdk: *mut Sdk,
    pub callback_signer: CallbackSigner,
    pub foreign_identities: HashMap<Identifier, Identity>
}

impl PlatformSDK {
    pub fn sdk_ref(&self) -> &Sdk {
        unsafe { &*self.sdk }
    }
}

// #[ferment_macro::opaque]
// pub type GetQuorumPublicKey = dyn Fn(*const FFIContext, u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync;
// #[ferment_macro::opaque]
// pub type GetDataContract = dyn Fn(*const FFIContext, &Identifier) -> Result<Option<Arc<DataContract>>, ContextProviderError> + Send + Sync;

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct FFIContext {

}



#[ferment_macro::export]
impl PlatformSDK {
    pub fn new<
        // CS: Fn(*const FFIContext, IdentityPublicKey, &[u8]) -> Result<BinaryData, ProtocolError> + 'static,
        QPK: Fn(*const FFIContext, u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync + 'static,
        DC: Fn(*const FFIContext, Identifier) -> Result<Option<Arc<DataContract>>, ContextProviderError> + Send + Sync + 'static>(
        get_quorum_public_key: QPK,
        get_data_contract: DC,
        callback_signer: CallbackSigner,
        context: Arc<FFIContext>
    ) -> Self {
        Self {
            foreign_identities: HashMap::new(),
            runtime: ferment_interfaces::boxed(Runtime::new().unwrap()),
            callback_signer,
            sdk: ferment_interfaces::boxed(create_sdk(PlatformProvider::new(get_quorum_public_key, get_data_contract, context)))
        }
    }
    pub async fn fetch_contract_by_id(&self, id: Identifier) -> Result<Option<DataContract>, Error> {
        DataContract::fetch_by_identifier(self.sdk_ref(), id).await
    }

}

fn create_sdk<C: ContextProvider + 'static>(provider: C) -> Sdk {
    let address_list = AddressList::from_iter(ADDRESS_LIST.iter().filter_map(|a| Uri::from_str(a).ok()));
    let builder = SdkBuilder::new(address_list);
    SdkBuilder::with_context_provider(builder, provider)
        .build()
        .unwrap()
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
