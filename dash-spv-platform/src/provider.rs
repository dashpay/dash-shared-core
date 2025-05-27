use std::os::raw::c_void;
use std::sync::Arc;
use dash_sdk::dpp::prelude::CoreBlockHeight;
use dash_sdk::platform::DataContract;
use dpp::data_contract::TokenConfiguration;
use drive_proof_verifier::ContextProvider;
use drive_proof_verifier::error::ContextProviderError;
use platform_value::Identifier;
use platform_version::version::PlatformVersion;
use crate::FFIThreadSafeContext;


#[derive(Clone)]
pub struct PlatformProvider {
    pub get_quorum_public_key: Arc<dyn Fn(u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync>,
    pub get_data_contract: Arc<dyn Fn(*const c_void, [u8; 32]) -> Option<DataContract> + Send + Sync>,
    pub get_platform_activation_height: Arc<dyn Fn(*const c_void) -> u32 + Send + Sync>,
    pub context: Arc<FFIThreadSafeContext>
}

impl PlatformProvider {
    pub fn new<
        QPK: Fn(u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync + 'static,
        DC: Fn(*const c_void, [u8; 32]) -> Option<DataContract> + Send + Sync + 'static,
        AH: Fn(*const c_void) -> u32 + Send + Sync + 'static,
    >(
        get_quorum_public_key: Arc<QPK>,
        get_data_contract: DC,
        get_platform_activation_height: AH,
        context: Arc<FFIThreadSafeContext>
    ) -> Self {
        Self {
            get_quorum_public_key,
            get_data_contract: Arc::new(get_data_contract),
            get_platform_activation_height: Arc::new(get_platform_activation_height),
            context
        }
    }
}

impl ContextProvider for PlatformProvider {
    fn get_quorum_public_key(&self, quorum_type: u32, quorum_hash: [u8; 32], core_chain_locked_height: u32) -> Result<[u8; 48], ContextProviderError> {
        (self.get_quorum_public_key)(quorum_type, quorum_hash, core_chain_locked_height)
    }
    fn get_data_contract(
        &self,
        id: &Identifier,
        _platform_version: &PlatformVersion,
    ) -> Result<Option<Arc<DataContract>>, ContextProviderError> {
        let context = self.context.inner.lock().unwrap();
        let maybe_contract = (self.get_data_contract)(*context, id.to_buffer());
        drop(context);
        Ok(maybe_contract.map(Arc::new))
    }


    fn get_platform_activation_height(&self) -> Result<CoreBlockHeight, ContextProviderError> {
        let context = self.context.inner.lock().unwrap();
        let block_height = (self.get_platform_activation_height)(*context);
        drop(context);
        if block_height == u32::MAX {
            Err(ContextProviderError::Generic("Platform activation height is not set".to_string()))
        } else {
            Ok(block_height)
        }
    }

    fn get_token_configuration(&self, token_id: &Identifier) -> Result<Option<TokenConfiguration>, ContextProviderError> {
        Err(ContextProviderError::TokenConfigurationFailure(format!("Not implemented {token_id}")))
    }
}
