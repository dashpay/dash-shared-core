use std::collections::BTreeMap;
use std::sync::Arc;
#[cfg(test)]
use std::sync::RwLock;
use dash_spv_crypto::network::ChainType;
#[cfg(test)]
use dash_spv_masternode_processor::block_store::MerkleBlock;
use dash_spv_masternode_processor::common::block::Block;
use dash_spv_masternode_processor::models::{masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};
use dash_spv_masternode_processor::processing::core_provider::{CoreProvider, CoreProviderError};
use dash_spv_masternode_processor::processing::processing_error::ProcessingError;
#[cfg(test)]
use dash_spv_masternode_processor::processing::MasternodeProcessor;
#[cfg(test)]
use dash_spv_masternode_processor::tests::FFIContext;

#[ferment_macro::opaque]
pub struct FFICoreProvider {
    /// External Masternode Manager Diff Message Context
    pub context: *const std::ffi::c_void,
    // pub context: Arc<FFIThreadSafeContext>,
    // pub get_quorum_public_key: Arc<dyn Fn(*const c_void, u32, [u8; 32], u32) -> Result<[u8; 48], ContextProviderError> + Send + Sync>,
    pub chain_type: ChainType,
    pub get_block_height_by_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>,
    pub get_merkle_root_by_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<[u8; 32], CoreProviderError>>,
    pub get_block_hash_by_height: Arc<dyn Fn(*const std::os::raw::c_void, u32) -> Result<[u8; 32], CoreProviderError>>,
    pub get_block_by_height_or_last_terminal: Arc<dyn Fn(*const std::os::raw::c_void, u32) -> Result<Block, CoreProviderError>>,
    // pub get_llmq_snapshot_by_block_hash: Arc<dyn Fn(UInt256) -> Result<LLMQSnapshot, CoreProviderError>>,
    // pub get_cl_signature_by_block_hash: Arc<dyn Fn(UInt256) -> Result<UInt768, CoreProviderError>>,
    // pub save_llmq_snapshot: Arc<dyn Fn(UInt256, LLMQSnapshot) -> bool>,
    // pub save_cl_signature: Arc<dyn Fn(UInt256, UInt768) -> bool>,
    // pub get_masternode_list_by_block_hash: Arc<dyn Fn(UInt256) -> Result<MasternodeList, CoreProviderError>>,
    // pub save_masternode_list: Arc<dyn Fn(UInt256, MasternodeList) -> bool>,
    // pub destroy_masternode_list: Arc<dyn Fn(MasternodeList)>,
    pub add_insight: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32])>,
    // pub destroy_hash: Arc<dyn Fn(UInt256)>,
    // pub destroy_snapshot: Arc<dyn Fn(LLMQSnapshot)>,
    pub should_process_diff_with_range: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32], [u8; 32]) -> ProcessingError>,
    pub persist_in_retrieval_queue: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> bool>,

    pub load_masternode_list_from_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MasternodeList, CoreProviderError>>,
    pub save_masternode_list_into_db: Arc<dyn Fn(*const std::os::raw::c_void, MasternodeList, BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError>>,

    pub load_llmq_snapshot_from_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<LLMQSnapshot, CoreProviderError>>,
    pub save_llmq_snapshot_into_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32], LLMQSnapshot) -> Result<bool, CoreProviderError>>,
    pub update_address_usage_of_masternodes: Arc<dyn Fn(*const std::os::raw::c_void, Vec<MasternodeEntry>)>,
    pub first_in_mn_diff_queue: Arc<dyn Fn(*const std::os::raw::c_void) -> Option<[u8; 32]>>,
    pub first_in_qr_info_queue: Arc<dyn Fn(*const std::os::raw::c_void) -> Option<[u8; 32]>>,

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

    // fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<MasternodeList, CoreProviderError> {
    //     (self.get_masternode_list_by_block_hash)(block_hash)
    // }
    //
    // fn lookup_cl_signature_by_block_hash(&self, block_hash: UInt256) -> Result<UInt768, CoreProviderError> {
    //     (self.get_cl_signature_by_block_hash)(block_hash)
    // }
    //
    // fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<models::LLMQSnapshot, CoreProviderError> {
    //     (self.get_llmq_snapshot_by_block_hash)(block_hash)
    // }

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

    fn should_process_diff_with_range(
        &self,
        base_block_hash: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<u8, ProcessingError> {
        let result = (self.should_process_diff_with_range)(self.context, base_block_hash, block_hash);
        match result {
            ProcessingError::None => Ok(0),
            _ => Err(result)
        }
    }
    fn persist_in_retrieval_queue(&self, block_hash: [u8; 32]) -> bool {
        (self.persist_in_retrieval_queue)(self.context, block_hash)
    }

    fn load_masternode_list_from_db(&self, block_hash: [u8; 32]) -> Result<MasternodeList, CoreProviderError> {
        (self.load_masternode_list_from_db)(self.context, block_hash)
    }
    fn save_masternode_list_into_db(&self, masternode_list: MasternodeList, modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError> {
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
    // fn masternode_list_updated(&self, list: MasternodeList) {
    //     (self.masternode_list_updated)(self.context, list)
    // }

    fn first_in_mn_diff_queue(&self) -> Option<[u8; 32]> {
        (self.first_in_mn_diff_queue)(self.context)
    }

    fn first_in_qr_info_queue(&self) -> Option<[u8; 32]> {
        (self.first_in_qr_info_queue)(self.context)
    }
    //
    // fn save_snapshot(&self, block_hash: UInt256, snapshot: models::LLMQSnapshot) -> bool {
    //     (self.save_llmq_snapshot)(block_hash, snapshot)
    // }
    // fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &models::MasternodeList) -> bool {
    //     (self.save_masternode_list)(block_hash, masternode_list.clone())
    // }
}

#[ferment_macro::export]
impl FFICoreProvider  {
    pub fn new<
        // merkle_root
        BHT: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        BHH: Fn(*const std::os::raw::c_void, u32) -> Result<[u8; 32], CoreProviderError> + Send + Sync + 'static,
        BORLT: Fn(*const std::os::raw::c_void, u32) -> Result<Block, CoreProviderError> + Send + Sync + 'static,
        MR: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<[u8; 32], CoreProviderError> + Send + Sync + 'static,
        SP: Fn(*const std::os::raw::c_void, [u8; 32], [u8; 32]) -> ProcessingError + Send + Sync + 'static,
        INS: Fn(*const std::os::raw::c_void, [u8; 32]) + Send + Sync + 'static,
        PIRQ: Fn(*const std::os::raw::c_void, [u8; 32]) -> bool + Send + Sync + 'static,
        SML: Fn(*const std::os::raw::c_void, MasternodeList, BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        LML: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MasternodeList, CoreProviderError> + Send + Sync + 'static,
        SLS: Fn(*const std::os::raw::c_void, [u8; 32], LLMQSnapshot) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        LLS: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<LLMQSnapshot, CoreProviderError> + Send + Sync + 'static,
        UMU: Fn(*const std::os::raw::c_void, Vec<MasternodeEntry>) + Send + Sync + 'static,
        MDQ: Fn(*const std::os::raw::c_void) -> Option<[u8; 32]> + Send + Sync + 'static,
        QIQ: Fn(*const std::os::raw::c_void) -> Option<[u8; 32]> + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        get_block_height_by_hash: BHT,
        get_block_hash_by_height: BHH,
        get_block_by_height_or_last_terminal: BORLT,
        get_merkle_root_by_hash: MR,
        should_process_diff_with_range: SP,
        add_insight: INS,
        persist_in_retrieval_queue: PIRQ,
        load_masternode_list_from_db: LML,
        save_masternode_list_into_db: SML,
        load_llmq_snapshot_from_db: LLS,
        save_llmq_snapshot_into_db: SLS,
        update_address_usage_of_masternodes: UMU,
        first_in_mn_diff_queue: MDQ,
        first_in_qr_info_queue: QIQ,
        context: *const std::os::raw::c_void,
    ) -> Self {
        Self {
            chain_type,
            context,
            get_block_height_by_hash: Arc::new(get_block_height_by_hash),
            get_block_hash_by_height: Arc::new(get_block_hash_by_height),
            get_block_by_height_or_last_terminal: Arc::new(get_block_by_height_or_last_terminal),
            get_merkle_root_by_hash: Arc::new(get_merkle_root_by_hash),
            should_process_diff_with_range: Arc::new(should_process_diff_with_range),
            add_insight: Arc::new(add_insight),
            persist_in_retrieval_queue: Arc::new(persist_in_retrieval_queue),
            load_masternode_list_from_db: Arc::new(load_masternode_list_from_db),
            save_masternode_list_into_db: Arc::new(save_masternode_list_into_db),
            load_llmq_snapshot_from_db: Arc::new(load_llmq_snapshot_from_db),
            save_llmq_snapshot_into_db: Arc::new(save_llmq_snapshot_into_db),
            update_address_usage_of_masternodes: Arc::new(update_address_usage_of_masternodes),
            // masternode_list_updated: Arc::new(masternode_list_updated),
            first_in_mn_diff_queue: Arc::new(first_in_mn_diff_queue),
            first_in_qr_info_queue: Arc::new(first_in_qr_info_queue),
        }
    }
}

#[cfg(test)]
impl FFICoreProvider {
    pub fn register_default(context: &Arc<RwLock<FFIContext>>, chain_type: ChainType) -> Self {


        Self {
            // context: Arc::clone(context),
            context: &context as *const _ as *const std::ffi::c_void,
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
            // get_llmq_snapshot_by_block_hash: {
            //     let context = Arc::clone(context);
            //     Arc::new(move |block_hash| {
            //         let context = context.read().unwrap();
            //         let lock = context.cache.llmq_snapshots.read().unwrap();
            //         let maybe_result = lock.get(&block_hash).cloned();
            //         drop(lock);
            //         maybe_result.ok_or(CoreProviderError::BadBlockHash(block_hash))
            //     })
            // },
            // get_cl_signature_by_block_hash: {
            //     let context = Arc::clone(context);
            //     Arc::new(move |block_hash| {
            //         let context = context.read().unwrap();
            //         let lock = context.cache.cl_signatures.read().unwrap();
            //         let maybe_result = lock.get(&block_hash).cloned();
            //         drop(lock);
            //         maybe_result.ok_or(CoreProviderError::BadBlockHash(block_hash))
            //     })
            // },
            // save_llmq_snapshot: {
            //     let context = Arc::clone(context);
            //     Arc::new(move |block_hash, snapshot| {
            //         let mut context = context.write().unwrap();
            //         context.cache.add_snapshot(block_hash, snapshot);
            //         true
            //     })
            // },
            // save_cl_signature: {
            //     let context = Arc::clone(context);
            //     Arc::new(move |block_hash, sig| {
            //         let mut context = context.write().unwrap();
            //         context.cache.add_cl_signature(block_hash, sig);
            //         true
            //     })
            // },
            // get_masternode_list_by_block_hash: {
            //     let context = Arc::clone(context);
            //     Arc::new(move |block_hash| {
            //         let context = context.read().unwrap();
            //         let lock = context.cache.mn_lists.read().unwrap();
            //         let maybe_result = lock.get(&block_hash).cloned();
            //         drop(lock);
            //         maybe_result.ok_or(CoreProviderError::NoMasternodeList)
            //     })
            // },
            // save_masternode_list: {
            //     let context = Arc::clone(context);
            //     Arc::new(move |block_hash, list| {
            //         let context = context.write().unwrap();
            //         let mut lock = context.cache.mn_lists.write().unwrap();
            //         lock.insert(block_hash, list);
            //         true
            //     })
            // },
            // destroy_masternode_list: Arc::new(|_| {}),
            add_insight: Arc::new(|_| {}),
            // destroy_hash: Arc::new(|_| {}),
            // destroy_snapshot: Arc::new(|_| {}),
            should_process_diff_with_range: Arc::new(|_, _| ProcessingError::None),
        }
    }
    pub fn default_processor(context: &Arc<RwLock<FFIContext>>, cache: Arc<MasternodeProcessorCache>, chain_type: ChainType) -> MasternodeProcessor {
        MasternodeProcessor::new(Arc::new(Self::register_default(context, chain_type)), cache)
    }
}
