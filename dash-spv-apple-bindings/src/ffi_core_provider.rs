use std::sync::Arc;
#[cfg(test)]
use std::sync::RwLock;
use dash_spv_crypto::network::ChainType;
use dash_spv_crypto::crypto::byte_util::{UInt256, UInt768};
#[cfg(feature = "test-helpers")]
use dash_spv_masternode_processor::block_store::MerkleBlock;
use dash_spv_masternode_processor::models;
use dash_spv_masternode_processor::models::{snapshot::LLMQSnapshot, masternode_list::MasternodeList};
use dash_spv_masternode_processor::processing::core_provider::{CoreProvider, CoreProviderError};
use dash_spv_masternode_processor::processing::processing_error::ProcessingError;
#[cfg(test)]
use dash_spv_masternode_processor::processing::MasternodeProcessor;
#[cfg(feature = "test-helpers")]
use dash_spv_masternode_processor::tests::FFIContext;

#[ferment_macro::opaque]
pub struct FFICoreProvider {
    /// External Masternode Manager Diff Message Context
    pub opaque_context: *const std::ffi::c_void,
    pub chain_type: ChainType,
    pub get_block_height_by_hash: Arc<dyn Fn(UInt256) -> u32>,
    pub get_merkle_root_by_hash: Arc<dyn Fn(UInt256) -> Result<UInt256, CoreProviderError>>,
    pub get_block_hash_by_height: Arc<dyn Fn(u32) -> Result<UInt256, CoreProviderError>>,
    pub get_llmq_snapshot_by_block_hash: Arc<dyn Fn(UInt256) -> Result<LLMQSnapshot, CoreProviderError>>,
    pub get_cl_signature_by_block_hash: Arc<dyn Fn(UInt256) -> Result<UInt768, CoreProviderError>>,
    pub save_llmq_snapshot: Arc<dyn Fn(UInt256, LLMQSnapshot) -> bool>,
    pub save_cl_signature: Arc<dyn Fn(UInt256, UInt768) -> bool>,
    pub get_masternode_list_by_block_hash: Arc<dyn Fn(UInt256) -> Result<MasternodeList, CoreProviderError>>,
    pub save_masternode_list: Arc<dyn Fn(UInt256, MasternodeList) -> bool>,
    pub destroy_masternode_list: Arc<dyn Fn(MasternodeList)>,
    pub add_insight: Arc<dyn Fn(UInt256)>,
    pub destroy_hash: Arc<dyn Fn(UInt256)>,
    pub destroy_snapshot: Arc<dyn Fn(LLMQSnapshot)>,
    pub should_process_diff_with_range: Arc<dyn Fn(UInt256, UInt256) -> ProcessingError>,
}

impl std::fmt::Debug for FFICoreProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FFICoreProvider")
            .field("chain", &self.chain_type)
            .field("context", &self.opaque_context)
            .finish()
    }
}

impl CoreProvider for FFICoreProvider {
    fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Result<UInt256, CoreProviderError> {
        (self.get_merkle_root_by_hash)(block_hash)
    }

    fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<MasternodeList, CoreProviderError> {
        (self.get_masternode_list_by_block_hash)(block_hash)
    }

    fn lookup_cl_signature_by_block_hash(&self, block_hash: UInt256) -> Result<UInt768, CoreProviderError> {
        (self.get_cl_signature_by_block_hash)(block_hash)
    }

    fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<models::LLMQSnapshot, CoreProviderError> {
        (self.get_llmq_snapshot_by_block_hash)(block_hash)
    }

    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<UInt256, CoreProviderError> {
        (self.get_block_hash_by_height)(block_height)
    }

    fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32 {
        (self.get_block_height_by_hash)(block_hash)
    }

    fn add_insight(&self, block_hash: UInt256) {
        (self.add_insight)(block_hash)
    }

    fn should_process_diff_with_range(
        &self,
        base_block_hash: UInt256,
        block_hash: UInt256,
    ) -> Result<u8, ProcessingError> {
        let result = (self.should_process_diff_with_range)(base_block_hash, block_hash);
        match result {
            ProcessingError::None => Ok(0),
            _ => Err(result)
        }
    }

    fn save_snapshot(&self, block_hash: UInt256, snapshot: models::LLMQSnapshot) -> bool {
        (self.save_llmq_snapshot)(block_hash, snapshot)
    }
    fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &models::MasternodeList) -> bool {
        (self.save_masternode_list)(block_hash, masternode_list.clone())
    }
}

#[cfg(test)]
impl FFICoreProvider {
    pub fn register_default(context: &Arc<RwLock<FFIContext>>, chain_type: ChainType) -> Self {


        Self {
            opaque_context: Arc::as_ptr(context) as *const std::ffi::c_void,
            // opaque_context: &context as *const _ as *const std::ffi::c_void,
            chain_type,
            get_merkle_root_by_hash: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash| {
                    let context = context.read().unwrap();
                    Ok(context.block_for_hash(block_hash)
                        .map(MerkleBlock::merkle_root_reversed)
                        .unwrap_or(UInt256::MIN))
                })
            },
            get_block_height_by_hash: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash| {
                    let context = context.read().unwrap();
                    context.block_height_for_hash(block_hash)
                })
            },
            get_block_hash_by_height: {
                let context = Arc::clone(context);
                Arc::new(move |block_height| {
                    let context = context.read().unwrap();
                    context.block_hash_for_height(block_height)
                })
            },
            get_llmq_snapshot_by_block_hash: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash| {
                    let context = context.read().unwrap();
                    context.cache
                        .llmq_snapshots
                        .get(&block_hash)
                        .cloned()
                        .ok_or(CoreProviderError::BadBlockHash(block_hash))
                })
            },
            get_cl_signature_by_block_hash: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash| {
                    let context = context.read().unwrap();
                    context.
                        cache
                        .cl_signatures
                        .get(&block_hash)
                        .cloned()
                        .ok_or(CoreProviderError::BadBlockHash(block_hash))
                })
            },
            save_llmq_snapshot: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash, snapshot| {
                    let mut context = context.write().unwrap();
                    context.cache.add_snapshot(block_hash, snapshot);
                    true
                })
            },
            save_cl_signature: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash, sig| {
                    let mut context = context.write().unwrap();
                    context.cache.add_cl_signature(block_hash, sig);
                    true
                })
            },
            get_masternode_list_by_block_hash: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash| {
                    let context = context.read().unwrap();
                    context.cache
                        .mn_lists
                        .get(&block_hash)
                        .cloned()
                        .ok_or(CoreProviderError::NoMasternodeList)
                })
            },
            save_masternode_list: {
                let context = Arc::clone(context);
                Arc::new(move |block_hash, list| {
                    let mut context = context.write().unwrap();
                    context.cache.mn_lists.insert(block_hash, list);
                    true
                })
            },
            destroy_masternode_list: Arc::new(|_| {}),
            add_insight: Arc::new(|_| {}),
            destroy_hash: Arc::new(|_| {}),
            destroy_snapshot: Arc::new(|_| {}),
            should_process_diff_with_range: Arc::new(|_, _| ProcessingError::None),
        }
    }
    pub fn default_processor(context: &Arc<RwLock<FFIContext>>, chain_type: ChainType) -> MasternodeProcessor {
            MasternodeProcessor::new(Box::new(Self::register_default(context, chain_type)))
    }
}
