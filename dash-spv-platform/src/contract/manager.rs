use std::collections::HashSet;
use std::sync::Arc;
use dash_sdk::{platform::Fetch, Sdk};
use dpp::data_contract::accessors::v0::DataContractV0Getters;
use dpp::data_contract::{DataContract, DocumentName};
use dpp::data_contracts::SystemDataContract;
#[cfg(feature = "state-transitions")]
use dpp::state_transition::state_transitions::contract::data_contract_create_transition::DataContractCreateTransition;
use dpp::system_data_contracts::load_system_data_contract;
use drive_proof_verifier::types::RetrievedObjects;
use indexmap::IndexMap;
use platform_value::Identifier;
#[cfg(feature = "state-transitions")]
use platform_version::TryFromPlatformVersioned;
use dash_spv_crypto::network::ChainType;
use dash_spv_macro::StreamManager;
use crate::error::Error;
use crate::util::{RetryStrategy, StreamManager, StreamSettings, StreamSpec, Validator};

#[derive(Clone, Debug, StreamManager)]
#[ferment_macro::opaque]
pub struct ContractsManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
    // pub dashpay_contract: ContractModel,
    // pub dpns_contract: ContractModel,
}
impl ContractsManager {
    pub fn new(sdk: &Arc<Sdk>, chain_type: ChainType) -> Self {
        Self { sdk: Arc::clone(sdk), chain_type }
    }
}
#[ferment_macro::export]
impl ContractsManager {
    pub fn load_dashpay_contract(&self) -> DataContract {
        load_system_data_contract(SystemDataContract::Dashpay, self.sdk.version())
            .expect("Dashpay contract should be loaded")
    }
    pub fn load_dpns_contract(&self) -> DataContract {
        load_system_data_contract(SystemDataContract::DPNS, self.sdk.version())
            .expect("DPNS contract should be loaded")
    }
    pub async fn fetch_contract_by_id_bytes(&self, id_bytes: [u8; 32]) -> Result<Option<DataContract>, Error> {
        self.fetch_contract_by_id(Identifier::from(id_bytes)).await
    }
    pub async fn fetch_contract_by_id(&self, id: Identifier) -> Result<Option<DataContract>, Error> {
        DataContract::fetch_by_identifier(&self.sdk, id)
            .await
            .map_err(Error::from)
    }

    pub async fn fetch_contract_by_id_error_if_none(&self, id: Identifier) -> Result<DataContract, Error> {
        self.fetch_contract_by_id(id)
            .await
            .and_then(|contract| contract.ok_or(Error::DashSDKError("Contract not exist".to_string())))
    }

    #[cfg(feature = "state-transitions")]
    pub fn contract_registration_transition(&self, contract: DataContract) -> Result<DataContractCreateTransition, Error> {
        DataContractCreateTransition::try_from_platform_versioned(contract, self.sdk.version())
            .map_err(Error::from)
    }

    // #[cfg(feature = "state-transitions")]
    // pub fn create_sign_and_publish_transition(&self, contract: DataContract, private_key: &[u8]) -> Result<DataContractCreateTransition, Error> {
    //     let mut data_contract_create = self.contract_registration_transition(contract)?;
    //     let data = data_contract_create.signable_bytes()
    //         .map_err(Error::from)?;
    //     let signature = signer::sign(&data, private_key)?;
    //     data_contract_create.set_signature_bytes(signature.to_vec());
    //     // data_contract_create
    //     // data_contract_create.
    //         // .broadcast_state_transition(data_contract_create)
    //         // .await
    //
    //     //data_contract_create.publi
    //     contract.put_to_platform_and_wait_for_response(&self.sdk)
    //
    //     Ok(data_contract_create)
    // }
    //

    pub async fn monitor(&self, unique_id: Identifier, retry: RetryStrategy, options: ContractValidator) -> Result<Option<DataContract>, Error> {
        self.stream::<ContractValidator, DataContract, Identifier>(unique_id, retry, options).await
    }
    pub async fn monitor_for_id_bytes(&self, unique_id: [u8; 32], retry: RetryStrategy, options: ContractValidator) -> Result<Option<DataContract>, Error> {
        self.stream::<ContractValidator, DataContract, Identifier>(Identifier::from(unique_id), retry, options).await
    }
    pub async fn monitor_with_delay(&self, unique_id: [u8; 32], retry: RetryStrategy, options: ContractValidator, delay: u64) -> Result<Option<DataContract>, Error> {
        self.stream_with_settings::<ContractValidator, DataContract, Identifier>(Identifier::from(unique_id), retry, StreamSettings::default().with_delay(delay), options).await
    }
}

#[ferment_macro::export]
pub enum ContractValidator {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}
impl ContractValidator {
    pub fn accept_not_found(&self) -> bool {
        match self {
            ContractValidator::None => false,
            ContractValidator::AcceptNotFoundAsNotAnError => true
        }
    }
}
impl Validator<Option<DataContract>> for ContractValidator {
    fn validate(&self, value: &Option<DataContract>) -> bool {
        value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl Validator<RetrievedObjects<Identifier, DataContract>> for ContractValidator {
    fn validate(&self, _value: &RetrievedObjects<Identifier, DataContract>) -> bool {
        true
        // value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl StreamSpec for ContractValidator {
    type Validator = ContractValidator;
    type Error = dash_sdk::Error;
    type Result = Option<DataContract>;
    type ResultMany = IndexMap<Identifier, Option<DataContract>>;
}


#[ferment_macro::export]
pub fn is_document_defined_for_type(contract: DataContract, ty: &str) -> bool {
    contract.document_types().contains_key(ty)
}
#[ferment_macro::export]
pub fn has_equal_document_type_keys(contract1: DataContract, contract2: DataContract) -> bool {
    let set1 = HashSet::<&DocumentName>::from_iter(contract1.document_types().keys());
    let set2 = HashSet::<&DocumentName>::from_iter(contract2.document_types().keys());
    set1.difference(&set2).count() == 0
}
