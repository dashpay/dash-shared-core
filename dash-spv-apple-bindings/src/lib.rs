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
use std::sync::Arc;
use dpp::data_contract::DataContract;
use dpp::identity::identity_public_key::IdentityPublicKey;

use dpp::prelude::CoreBlockHeight;
use dpp::errors::ProtocolError;
use drive_proof_verifier::error::ContextProviderError;
use dash_spv_crypto::network::ChainType;
use dash_spv_masternode_processor::common::block::Block;
use dash_spv_masternode_processor::models::{masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};
use dash_spv_masternode_processor::processing::core_provider::CoreProviderError;
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache};
use dash_spv_platform::PlatformSDK;
use platform_value::{BinaryData, Identifier};
use crate::ffi_core_provider::FFICoreProvider;

// #[macro_export]
// macro_rules! impl_ffi_bytearray {
//     ($var_type: ident) => {
//         impl From<$var_type> for crate::ffi::common::ByteArray {
//             fn from(value: $var_type) -> Self {
//                 let vec = value.0.to_vec();
//                 vec.into()
//             }
//         }
//         impl From<Option<$var_type>> for crate::ffi::common::ByteArray {
//             fn from(value: Option<$var_type>) -> Self {
//                 if let Some(v) = value {
//                     v.into()
//                 } else {
//                     crate::ffi::common::ByteArray::default()
//                 }
//             }
//         }
//     }
// }
//
// impl_ffi_bytearray!(UInt128);
// impl_ffi_bytearray!(UInt160);
// impl_ffi_bytearray!(UInt256);
// impl_ffi_bytearray!(UInt384);
// impl_ffi_bytearray!(UInt512);
// impl_ffi_bytearray!(UInt768);

// use test_mod::Clone;

#[derive(Debug)]
#[ferment_macro::opaque]
pub struct DashSPVCore {
    pub processor: Arc<MasternodeProcessor>,
    pub cache: Arc<MasternodeProcessorCache>,
    pub platform: Arc<PlatformSDK>,
    context: *const std::os::raw::c_void,
}

#[ferment_macro::export]
impl DashSPVCore {

    pub fn with_callbacks<
        // platform
        QP: Fn(*const std::os::raw::c_void, u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync + 'static,
        DC: Fn(*const std::os::raw::c_void, Identifier) -> Result<Option<Arc<DataContract>>, ContextProviderError> + Send + Sync + 'static,
        AH: Fn(*const std::os::raw::c_void) -> Result<CoreBlockHeight, ContextProviderError> + Send + Sync + 'static,
        CS: Fn(*const std::os::raw::c_void, &IdentityPublicKey, Vec<u8>) -> Result<BinaryData, ProtocolError> + Send + Sync + 'static,
        CCS: Fn(*const std::os::raw::c_void, &IdentityPublicKey) -> bool + Send + Sync + 'static,
        // masternode
        BHT: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        BHH: Fn(*const std::os::raw::c_void, u32) -> Result<[u8; 32], CoreProviderError> + Send + Sync + 'static,
        BORLT: Fn(*const std::os::raw::c_void, u32) -> Result<Block, CoreProviderError> + Send + Sync + 'static,
        MR: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<[u8; 32], CoreProviderError> + Send + Sync + 'static,
        INS: Fn(*const std::os::raw::c_void, [u8; 32]) + Send + Sync + 'static,
        PIRQ: Fn(*const std::os::raw::c_void, [u8; 32], bool) -> bool + Send + Sync + 'static,
        SML: Fn(*const std::os::raw::c_void, Arc<MasternodeList>, BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        LML: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<Arc<MasternodeList>, CoreProviderError> + Send + Sync + 'static,
        SLS: Fn(*const std::os::raw::c_void, [u8; 32], LLMQSnapshot) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        LLS: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<LLMQSnapshot, CoreProviderError> + Send + Sync + 'static,
        UMU: Fn(*const std::os::raw::c_void, Vec<MasternodeEntry>) + Send + Sync + 'static,
        MDQ: Fn(*const std::os::raw::c_void, bool) -> Option<[u8; 32]> + Send + Sync + 'static,
        RRIR: Fn(*const std::os::raw::c_void, bool, [u8; 32], [u8; 32]) -> bool + Send + Sync + 'static,
        RFRQ: Fn(*const std::os::raw::c_void, bool, [u8; 32]) + Send + Sync + 'static,
        IWMLFP: Fn(*const std::os::raw::c_void, bool, *const std::os::raw::c_void) + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        address_list: Option<Vec<&'static str>>,

        get_quorum_public_key: QP,
        get_data_contract: DC,
        get_platform_activation_height: AH,
        callback_signer: CS,
        callback_can_sign: CCS,

        get_block_height_by_hash: BHT,
        get_block_hash_by_height: BHH,
        get_block_by_height_or_last_terminal: BORLT,
        get_merkle_root_by_hash: MR,
        add_insight: INS,
        load_masternode_list_from_db: LML,
        save_masternode_list_into_db: SML,
        load_llmq_snapshot_from_db: LLS,
        save_llmq_snapshot_into_db: SLS,
        update_address_usage_of_masternodes: UMU,
        persist_in_retrieval_queue: PIRQ,
        first_in_retrieval_queue: MDQ,
        remove_from_retrieval_queue: RFRQ,
        remove_request_in_retrieval: RRIR,
        issue_with_masternode_list_from_peer: IWMLFP,

        context: *const std::os::raw::c_void) -> Self {
        let provider = Arc::new(FFICoreProvider::new(
            chain_type,get_block_height_by_hash,
            get_block_hash_by_height,
            get_block_by_height_or_last_terminal,
            get_merkle_root_by_hash,
            add_insight,
            load_masternode_list_from_db,
            save_masternode_list_into_db,
            load_llmq_snapshot_from_db,
            save_llmq_snapshot_into_db,
            update_address_usage_of_masternodes,
            persist_in_retrieval_queue,
            first_in_retrieval_queue,
            remove_from_retrieval_queue,
            remove_request_in_retrieval,
            issue_with_masternode_list_from_peer, context));
        let cache = Arc::new(MasternodeProcessorCache::default());
        let processor = Arc::new(MasternodeProcessor::new(provider, Arc::clone(&cache)));
        let platform = Arc::new(PlatformSDK::new(
            get_quorum_public_key,
            get_data_contract,
            get_platform_activation_height,
            callback_signer,
            callback_can_sign,
            address_list,
            Arc::clone(&processor),
            context
        ));
        Self {
            processor,
            cache,
            platform,
            context,
        }
    }

    pub fn cache(&self) -> Arc<MasternodeProcessorCache> {
        Arc::clone(&self.cache)
    }
    pub fn processor(&self) -> Arc<MasternodeProcessor> {
        Arc::clone(&self.processor)
    }
    pub fn platform(&self) -> Arc<PlatformSDK> {
        Arc::clone(&self.platform)
    }
}

