use std::collections::BTreeMap;
use std::sync::Arc;
use dash_spv_crypto::network::ChainType;
#[cfg(test)]
use dash_spv_masternode_processor::block_store::MerkleBlock;
use dash_spv_masternode_processor::common::block::Block;
use dash_spv_masternode_processor::models::{masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};
use dash_spv_masternode_processor::processing::core_provider::{CoreProvider, CoreProviderError};
#[cfg(test)]
use dash_spv_masternode_processor::processing::MasternodeProcessor;
#[cfg(test)]
use dash_spv_masternode_processor::processing::MasternodeProcessorCache;
#[cfg(test)]
use dash_spv_masternode_processor::tests::FFIContext;

#[ferment_macro::opaque]
pub struct FFICoreProvider {
    /// External Masternode Manager Diff Message Context
    pub context: *const std::ffi::c_void,
    // pub context: Arc<FFIThreadSafeContext>,
    pub chain_type: ChainType,
    pub get_block_height_by_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>,
    pub get_merkle_root_by_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<[u8; 32], CoreProviderError>>,
    pub get_block_hash_by_height: Arc<dyn Fn(*const std::os::raw::c_void, u32) -> Result<[u8; 32], CoreProviderError>>,
    pub get_block_by_height_or_last_terminal: Arc<dyn Fn(*const std::os::raw::c_void, u32) -> Result<Block, CoreProviderError>>,
    pub add_insight: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32])>,
    pub persist_in_retrieval_queue: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32], bool) -> bool>,

    pub load_masternode_list_from_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<Arc<MasternodeList>, CoreProviderError>>,
    pub save_masternode_list_into_db: Arc<dyn Fn(*const std::os::raw::c_void, Arc<MasternodeList>, BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError>>,

    pub load_llmq_snapshot_from_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<LLMQSnapshot, CoreProviderError>>,
    pub save_llmq_snapshot_into_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32], LLMQSnapshot) -> Result<bool, CoreProviderError>>,
    pub update_address_usage_of_masternodes: Arc<dyn Fn(*const std::os::raw::c_void, Vec<MasternodeEntry>)>,
    pub first_in_retrieval_queue: Arc<dyn Fn(*const std::os::raw::c_void, bool) -> Option<[u8; 32]>>,
    pub remove_request_in_retrieval: Arc<dyn Fn(*const std::os::raw::c_void, bool, [u8; 32], [u8; 32]) -> bool>,
    pub remove_from_retrieval_queue: Arc<dyn Fn(*const std::os::raw::c_void, bool, [u8; 32])>,
    pub issue_with_masternode_list_from_peer: Arc<dyn Fn(*const std::os::raw::c_void, bool, *const std::os::raw::c_void)>
}

impl std::fmt::Debug for FFICoreProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FFICoreProvider")
            .field("chain", &self.chain_type)
            .field("context", &self.context)
            .finish()
    }
}

impl CoreProvider for FFICoreProvider {
    fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    fn lookup_merkle_root_by_hash(&self, block_hash: [u8; 32]) -> Result<[u8; 32], CoreProviderError> {
        (self.get_merkle_root_by_hash)(self.context, block_hash)
    }

    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<[u8; 32], CoreProviderError> {
        (self.get_block_hash_by_height)(self.context, block_height)
    }

    fn lookup_block_height_by_hash(&self, block_hash: [u8; 32]) -> u32 {
        (self.get_block_height_by_hash)(self.context, block_hash)
    }

    fn lookup_block_by_height_or_last_terminal(&self, block_height: u32) -> Result<Block, CoreProviderError> {
        (self.get_block_by_height_or_last_terminal)(self.context, block_height)
    }

    fn add_insight(&self, block_hash: [u8; 32]) {
        (self.add_insight)(self.context, block_hash)
    }

    fn remove_request_in_retrieval(&self, is_dip24: bool, base_block_hash: [u8; 32], block_hash: [u8; 32]) -> bool {
        (self.remove_request_in_retrieval)(self.context, is_dip24, base_block_hash, block_hash)
    }

    fn remove_from_retrieval_queue(&self, is_dip24: bool, block_hash: [u8; 32]) {
        (self.remove_from_retrieval_queue)(self.context, is_dip24, block_hash)
    }
    fn first_in_retrieval_queue(&self, is_dip24: bool) -> Option<[u8; 32]> {
        (self.first_in_retrieval_queue)(self.context, is_dip24)
    }
    fn persist_in_retrieval_queue(&self, block_hash: [u8; 32], is_dip24: bool) -> bool {
        (self.persist_in_retrieval_queue)(self.context, block_hash, is_dip24)
    }
    fn load_masternode_list_from_db(&self, block_hash: [u8; 32]) -> Result<Arc<MasternodeList>, CoreProviderError> {
        (self.load_masternode_list_from_db)(self.context, block_hash)
    }
    fn save_masternode_list_into_db(&self, masternode_list: Arc<MasternodeList>, modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError> {
        (self.save_masternode_list_into_db)(self.context, masternode_list, modified_masternodes)
    }
    fn load_llmq_snapshot_from_db(&self, block_hash: [u8; 32]) -> Result<LLMQSnapshot, CoreProviderError> {
        (self.load_llmq_snapshot_from_db)(self.context, block_hash)
    }

    fn save_llmq_snapshot_into_db(&self, block_hash: [u8; 32], llmq_snapshot: LLMQSnapshot) -> Result<bool, CoreProviderError> {
        (self.save_llmq_snapshot_into_db)(self.context, block_hash, llmq_snapshot)
    }

    fn update_address_usage_of_masternodes(&self, masternodes: Vec<MasternodeEntry>) {
        (self.update_address_usage_of_masternodes)(self.context, masternodes)
    }

    fn issue_with_masternode_list_from_peer(&self, is_dip24: bool, peer: *const std::os::raw::c_void) {
        (self.issue_with_masternode_list_from_peer)(self.context, is_dip24, peer)
    }
}

#[ferment_macro::export]
impl FFICoreProvider  {
    pub fn new<
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
        context: *const std::os::raw::c_void,
    ) -> Self {
        Self {
            chain_type,
            context,
            get_block_height_by_hash: Arc::new(get_block_height_by_hash),
            get_block_hash_by_height: Arc::new(get_block_hash_by_height),
            get_block_by_height_or_last_terminal: Arc::new(get_block_by_height_or_last_terminal),
            get_merkle_root_by_hash: Arc::new(get_merkle_root_by_hash),
            add_insight: Arc::new(add_insight),
            persist_in_retrieval_queue: Arc::new(persist_in_retrieval_queue),
            load_masternode_list_from_db: Arc::new(load_masternode_list_from_db),
            save_masternode_list_into_db: Arc::new(save_masternode_list_into_db),
            load_llmq_snapshot_from_db: Arc::new(load_llmq_snapshot_from_db),
            save_llmq_snapshot_into_db: Arc::new(save_llmq_snapshot_into_db),
            update_address_usage_of_masternodes: Arc::new(update_address_usage_of_masternodes),
            first_in_retrieval_queue: Arc::new(first_in_retrieval_queue),
            remove_request_in_retrieval: Arc::new(remove_request_in_retrieval),
            remove_from_retrieval_queue: Arc::new(remove_from_retrieval_queue),
            issue_with_masternode_list_from_peer: Arc::new(issue_with_masternode_list_from_peer),
        }
    }
}

#[cfg(test)]
impl FFICoreProvider {
    pub fn register_default(context: Arc<FFIContext>, chain_type: ChainType) -> Self {
        let context_raw = Arc::into_raw(context.clone()) as *const std::ffi::c_void;
        Self {
            context: context_raw,
            chain_type,
            get_merkle_root_by_hash: {
                Arc::new(move |context, block_hash| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_for_hash(block_hash)
                        .map(MerkleBlock::merkle_root_reversed)
                        .unwrap_or([0u8; 32]);
                    std::mem::forget(context);
                    Ok(result)
                })
            },
            get_block_height_by_hash: {
                Arc::new(move |context, block_hash| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_height_for_hash(block_hash);
                    std::mem::forget(context);
                    result
                })
            },
            get_block_hash_by_height: {
                Arc::new(move |context, block_height| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_hash_for_height(block_height);
                    std::mem::forget(context);
                    result
                })
            },
            get_block_by_height_or_last_terminal: Arc::new(move |context, block_height| unsafe {
                let context = Arc::from_raw(context as *const FFIContext);
                let result = context.block_for_height(block_height)
                    .map(Block::from)
                    .ok_or(CoreProviderError::NullResult);
                std::mem::forget(context);
                result
            }),
            add_insight: Arc::new(|context, block_hash| {}),
            persist_in_retrieval_queue: Arc::new(|context, block_hash, is_dip24| true),
            load_masternode_list_from_db: Arc::new(|context, block_hash| Err(CoreProviderError::NoMasternodeList)),
            save_masternode_list_into_db: Arc::new(|context, list, modified_masternodes| Ok(true)),
            load_llmq_snapshot_from_db: Arc::new(|context, block_hash| Err(CoreProviderError::NoMasternodeList)),
            save_llmq_snapshot_into_db: Arc::new(|context, block_hash, snapshot| Ok(true)),
            update_address_usage_of_masternodes: Arc::new(|context, modified_masternodes| {}),
            first_in_retrieval_queue: Arc::new(|context, is_dip24| None),
            remove_request_in_retrieval: Arc::new(|context, is_dip24, base_block_hash, block_hash| true),
            remove_from_retrieval_queue: Arc::new(|context, is_dip24, block_hash| {}),
            issue_with_masternode_list_from_peer: Arc::new(|context, is_dip24, peer| {}),
        }
    }
    pub fn default_processor(context: Arc<FFIContext>, chain_type: ChainType) -> MasternodeProcessor {
        MasternodeProcessor::new(Arc::new(Self::register_default(context, chain_type)), Arc::new(MasternodeProcessorCache::default()))
    }
}
