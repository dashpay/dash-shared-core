#![allow(dead_code)]
#![allow(unused_variables)]

mod address;
// mod chain;
// mod common;
// mod crypto;
#[cfg(not(test))]
mod fermented;
#[cfg(not(test))]
mod fermented_extended;

// mod keys;
// mod masternode;
// mod tx;

#[cfg(test)]
mod tests;
mod ffi_core_provider;
// mod ffi;
// mod types;
pub mod custom;
mod bindings;

pub extern crate dash_spv_masternode_processor;
pub extern crate dash_spv_platform;
pub extern crate merk;
pub extern crate bitcoin_hashes as hashes;

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use dpp::data_contract::DataContract;
use dpp::identity::identity_public_key::IdentityPublicKey;

use dpp::prelude::CoreBlockHeight;
use dpp::errors::ProtocolError;
use drive_proof_verifier::error::ContextProviderError;
use hashes::hex::ToHex;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_masternode_processor::common::block::{Block, MBlock};
use dash_spv_masternode_processor::models::{masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};
use dash_spv_masternode_processor::processing::core_provider::CoreProviderError;
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache};
use dash_spv_platform::PlatformSDK;
use platform_value::{BinaryData, Identifier};
use dash_spv_crypto::crypto::byte_util::Reversed;
use dash_spv_masternode_processor::models::sync_state::CacheState;
use dash_spv_platform::cache::PlatformCache;
use crate::ffi_core_provider::FFICoreProvider;

#[ferment_macro::opaque]
pub struct DashSPVCore {
    pub processor: Arc<MasternodeProcessor>,
    pub platform: Arc<PlatformSDK>,
    context: *const std::os::raw::c_void,
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
        // QP: Fn(*const std::os::raw::c_void, u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync + 'static,
        DC: Fn(*const std::os::raw::c_void, Identifier) -> Result<Option<Arc<DataContract>>, ContextProviderError> + Send + Sync + 'static,
        AH: Fn(*const std::os::raw::c_void) -> Result<CoreBlockHeight, ContextProviderError> + Send + Sync + 'static,
        CS: Fn(*const std::os::raw::c_void, &IdentityPublicKey, Vec<u8>) -> Result<BinaryData, ProtocolError> + Send + Sync + 'static,
        CCS: Fn(*const std::os::raw::c_void, &IdentityPublicKey) -> bool + Send + Sync + 'static,
        // masternode
        BHT: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        BHH: Fn(*const std::os::raw::c_void, u32) -> [u8; 32] + Send + Sync + 'static,
        TIPBH: Fn(*const std::os::raw::c_void) -> u32 + Send + Sync + 'static,
        BORLT: Fn(*const std::os::raw::c_void, u32) -> Result<Block, CoreProviderError> + Send + Sync + 'static,
        BBH: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MBlock, CoreProviderError> + Send + Sync + 'static,
        LBBBH: Fn(*const std::os::raw::c_void, [u8; 32], *const std::os::raw::c_void) -> Result<MBlock, CoreProviderError> + Send + Sync + 'static,
        INS: Fn(*const std::os::raw::c_void, [u8; 32]) + Send + Sync + 'static,
        CLSBH: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<[u8; 96], CoreProviderError> + Send + Sync + 'static,
        SML: Fn(*const std::os::raw::c_void, [u8; 32], BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        LML: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MasternodeList, CoreProviderError> + Send + Sync + 'static,
        SLS: Fn(*const std::os::raw::c_void, [u8; 32], LLMQSnapshot) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        LLS: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<LLMQSnapshot, CoreProviderError> + Send + Sync + 'static,
        UMU: Fn(*const std::os::raw::c_void, Vec<MasternodeEntry>) + Send + Sync + 'static,
        RRIR: Fn(*const std::os::raw::c_void, bool, [u8; 32], [u8; 32]) -> bool + Send + Sync + 'static,
        IWMLFP: Fn(*const std::os::raw::c_void, bool, *const std::os::raw::c_void) + Send + Sync + 'static,
        NSS: Fn(*const std::os::raw::c_void, CacheState) + Send + Sync + 'static,
        DML: Fn(*const std::os::raw::c_void, bool) + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        address_list: Option<Vec<&'static str>>,

        // get_quorum_public_key: QP,
        get_data_contract: DC,
        get_platform_activation_height: AH,
        callback_signer: CS,
        callback_can_sign: CCS,

        get_block_height_by_hash: BHT,
        get_block_hash_by_height: BHH,
        get_block_by_height_or_last_terminal: BORLT,
        block_by_hash: BBH,
        last_block_for_block_hash: LBBBH,
        get_tip_height: TIPBH,
        add_insight: INS,
        get_cl_signature_by_block_hash: CLSBH,
        load_masternode_list_from_db: LML,
        save_masternode_list_into_db: SML,
        load_llmq_snapshot_from_db: LLS,
        save_llmq_snapshot_into_db: SLS,
        update_address_usage_of_masternodes: UMU,
        remove_request_in_retrieval: RRIR,
        issue_with_masternode_list_from_peer: IWMLFP,
        notify_sync_state: NSS,
        dequeue_masternode_list: DML,

        context: *const std::os::raw::c_void) -> Self {
        let provider = Arc::new(FFICoreProvider::new(
            chain_type.clone(),
            get_block_height_by_hash,
            get_block_hash_by_height,
            get_block_by_height_or_last_terminal,
            block_by_hash,
            last_block_for_block_hash,
            get_tip_height,
            add_insight,
            get_cl_signature_by_block_hash,
            load_masternode_list_from_db,
            save_masternode_list_into_db,
            load_llmq_snapshot_from_db,
            save_llmq_snapshot_into_db,
            update_address_usage_of_masternodes,
            remove_request_in_retrieval,
            issue_with_masternode_list_from_peer,
            notify_sync_state,
            dequeue_masternode_list,
            context));
        let processor = MasternodeProcessor::new(provider.clone(), Arc::new(MasternodeProcessorCache::new(provider)));
        let processor_arc = Arc::new(processor);
        let processor_arc_clone = Arc::clone(&processor_arc);
        let get_quorum_public_key = Arc::new(move |llmq_type: u32, llmq_hash: [u8; 32], core_chain_locked_height: u32| {
            let llmq_type = LLMQType::from_u16(llmq_type as u16);
            processor_arc_clone.cache.find_llmq_entry_public_key(llmq_type, llmq_hash.reversed())
                .ok_or(ContextProviderError::InvalidQuorum(format!("Quorum not found: {}: {} ({})", llmq_type, llmq_hash.to_hex(), llmq_hash.reversed().to_hex())))
        });
        let platform = Arc::new(PlatformSDK::new(
            Arc::new(PlatformCache::default()),
            get_quorum_public_key,
            get_data_contract,
            get_platform_activation_height,
            callback_signer,
            callback_can_sign,
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

    pub fn cache(&self) -> Arc<MasternodeProcessorCache> {
        Arc::clone(&self.processor.cache)
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

