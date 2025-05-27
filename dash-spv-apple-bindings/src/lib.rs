#![allow(dead_code)]
#![allow(unused_variables)]

mod address;
#[cfg(not(test))]
pub mod custom;
#[cfg(not(test))]
mod fermented;
#[cfg(not(test))]
mod fermented_extended;

#[cfg(test)]
mod tests;
mod ffi_core_provider;

pub extern crate dash_spv_masternode_processor;
pub extern crate dash_spv_coinjoin;

use std::fmt::{Debug, Formatter};
use std::os::raw::c_void;
use std::sync::Arc;
use dashcore::{Network, QuorumHash};
use dashcore::hashes::Hash;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use data_contracts::SystemDataContract;
use dpp::data_contract::DataContract;
use dpp::identity::identity_public_key::IdentityPublicKey;

use drive_proof_verifier::error::ContextProviderError;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings};
use dash_spv_masternode_processor::processing::MasternodeProcessor;
use dash_spv_platform::PlatformSDK;
use dash_spv_crypto::crypto::byte_util::Reversed;
use dash_spv_crypto::keys::OpaqueKey;
use dash_spv_masternode_processor::processing::processor::DiffConfig;
use dash_spv_platform::cache::PlatformCache;
use crate::ffi_core_provider::FFICoreProvider;

#[ferment_macro::opaque]
pub struct DashSPVCore {
    pub processor: Arc<MasternodeProcessor>,
    pub platform: Arc<PlatformSDK>,
    context: *const c_void,
}

impl Debug for DashSPVCore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}] [SPVCore]", self.processor.provider.chain_type().name()).as_str())
    }
}

#[ferment_macro::export]
impl DashSPVCore {

    pub fn with_callbacks<
        // platform
        GetDataContract: Fn(*const c_void, [u8; 32]) -> Option<DataContract> + Send + Sync + 'static,
        GetPlatformActivationHeight: Fn(*const c_void) -> u32 + Send + Sync + 'static,
        Sign: Fn(*const c_void, IdentityPublicKey) -> Option<OpaqueKey> + Send + Sync + 'static,
        CanSign: Fn(*const c_void, IdentityPublicKey) -> bool + Send + Sync + 'static,
        GetDataContractFromCache: Fn(*const c_void, SystemDataContract) -> DataContract + Send + Sync + 'static,
        // masternode
        GetBlockHeightByBlockHash: Fn(*const c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        GetBlockHashByBlockHeight: Fn(*const c_void, u32) -> Option<[u8; 32]> + Send + Sync + 'static,
        UpdateMasternodesAddressUsage: Fn(*const c_void, Vec<QualifiedMasternodeListEntry>) + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        diff_config: Option<DiffConfig>,
        address_list: Option<Vec<&'static str>>,

        get_data_contract: GetDataContract,
        get_platform_activation_height: GetPlatformActivationHeight,
        callback_signer: Sign,
        callback_can_sign: CanSign,
        get_data_contract_from_cache: GetDataContractFromCache,

        get_block_height_by_hash: GetBlockHeightByBlockHash,
        get_block_hash_by_height: GetBlockHashByBlockHeight,
        update_address_usage_of_masternodes: UpdateMasternodesAddressUsage,

        context: *const c_void) -> Self {
        let provider = Arc::new(FFICoreProvider::new(
            chain_type.clone(),
            get_block_height_by_hash,
            get_block_hash_by_height,
            update_address_usage_of_masternodes,
            context));
        let network = Network::from(chain_type.clone());
        let processor = MasternodeProcessor::from_diff_config(provider.clone(), network, diff_config);
        let processor_arc = Arc::new(processor);
        let processor_arc_clone = Arc::clone(&processor_arc);
        let get_quorum_public_key = Arc::new(move |llmq_type: u32, llmq_hash: [u8; 32], core_chain_locked_height: u32| {
            let llmq_type = LLMQType::from_u16(llmq_type as u16);
            let llmq_hash = QuorumHash::from_byte_array(llmq_hash.reversed());
            processor_arc_clone.engine.find_quorum_public_key(&llmq_type, &llmq_hash)
                .map(|key| key.0)
                .ok_or(ContextProviderError::InvalidQuorum(format!("Quorum not found: {}: {}", llmq_type, llmq_hash.to_string())))
        });
        let platform = Arc::new(PlatformSDK::new(
            Arc::new(PlatformCache::default()),
            get_quorum_public_key,
            get_data_contract,
            get_platform_activation_height,
            callback_signer,
            callback_can_sign,
            get_data_contract_from_cache,
            address_list,
            chain_type,
            context
        ));
        // let dapi_address_handler = Arc::clone(&platform);
        // processor.dapi_address_handler = Some(dapi_address_handler);
        // let processor_arc = Arc::new(processor);
        Self {
            processor: processor_arc,
            platform,
            context,
        }
    }

    pub fn platform_cache(&self) -> Arc<PlatformCache> {
        Arc::clone(&self.platform.cache)
    }
    pub fn processor(&self) -> Arc<MasternodeProcessor> {
        Arc::clone(&self.processor)
    }
    pub fn platform(&self) -> Arc<PlatformSDK> {
        Arc::clone(&self.platform)
    }
}

