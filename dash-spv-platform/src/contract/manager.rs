use std::sync::Arc;
use dash_sdk::{platform::Fetch, Sdk};
use dpp::data_contract::DataContract;
use platform_value::Identifier;
use crate::error::Error;

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct ContractsManager {
    pub sdk: Arc<Sdk>,
}
impl ContractsManager {
    pub fn new(sdk: &Arc<Sdk>) -> Self {
        Self { sdk: Arc::clone(sdk) }
    }
}

#[ferment_macro::export]
impl ContractsManager {
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

}