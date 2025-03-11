use std::sync::Arc;
#[cfg(test)]
use dashcore::secp256k1::hashes::hex::DisplayHex;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dash_spv_crypto::network::ChainType;
use dash_spv_masternode_processor::common::block::{Block, MBlock};
use dash_spv_masternode_processor::processing::core_provider::{CoreProvider, CoreProviderError};
#[cfg(test)]
use dash_spv_masternode_processor::{processing::MasternodeProcessor, tests::FFIContext};
use dash_spv_masternode_processor::models::sync_state::CacheState;

#[ferment_macro::opaque]
pub struct FFICoreProvider {
    pub context: *const std::ffi::c_void,
    // pub context: Arc<FFIThreadSafeContext>,
    pub chain_type: ChainType,

    pub get_block_height_by_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>,
    pub block_by_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MBlock, CoreProviderError>>,
    pub last_block_for_block_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32], *const std::os::raw::c_void) -> Result<MBlock, CoreProviderError>>,
    pub get_block_hash_by_height: Arc<dyn Fn(*const std::os::raw::c_void, u32) -> Option<[u8; 32]>>,
    pub get_tip_height: Arc<dyn Fn(*const std::os::raw::c_void) -> u32>,
    pub get_block_by_height_or_last_terminal: Arc<dyn Fn(*const std::os::raw::c_void, u32) -> Result<Block, CoreProviderError>>,
    pub add_insight: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32])>,
    pub get_cl_signature_by_block_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<[u8; 96], CoreProviderError>>,
    // pub load_masternode_list_from_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MasternodeList, CoreProviderError>>,
    // pub save_masternode_list_into_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32], BTreeMap<[u8; 32], QualifiedMasternodeListEntry>) -> Result<bool, CoreProviderError>>,
    // pub load_llmq_snapshot_from_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<QuorumSnapshot, CoreProviderError>>,
    // pub save_llmq_snapshot_into_db: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32], QuorumSnapshot) -> Result<bool, CoreProviderError>>,
    pub update_address_usage_of_masternodes: Arc<dyn Fn(*const std::os::raw::c_void, Vec<QualifiedMasternodeListEntry>)>,
    pub remove_request_in_retrieval: Arc<dyn Fn(*const std::os::raw::c_void, bool, [u8; 32], [u8; 32]) -> bool>,
    pub issue_with_masternode_list_from_peer: Arc<dyn Fn(*const std::os::raw::c_void, bool, *const std::os::raw::c_void)>,
    pub notify_sync_state: Arc<dyn Fn(*const std::os::raw::c_void, CacheState)>,
    pub dequeue_masternode_list: Arc<dyn Fn(*const std::os::raw::c_void, bool)>
}

unsafe impl Send for FFICoreProvider {}
unsafe impl Sync for FFICoreProvider {}

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
        self.chain_type.clone()
    }
    fn lookup_block_hash_by_height(&self, block_height: u32) -> Option<[u8; 32]> {
        (self.get_block_hash_by_height)(self.context, block_height)
    }

    fn lookup_block_height_by_hash(&self, block_hash: [u8; 32]) -> u32 {
        (self.get_block_height_by_hash)(self.context, block_hash)
    }

    fn lookup_block_by_height_or_last_terminal(&self, block_height: u32) -> Result<Block, CoreProviderError> {
        (self.get_block_by_height_or_last_terminal)(self.context, block_height)
    }

    fn get_tip_height(&self) -> u32 {
        (self.get_tip_height)(self.context)
    }

    fn add_insight(&self, block_hash: [u8; 32]) {
        (self.add_insight)(self.context, block_hash)
    }

    fn remove_request_in_retrieval(&self, is_dip24: bool, base_block_hash: [u8; 32], block_hash: [u8; 32]) -> bool {
        (self.remove_request_in_retrieval)(self.context, is_dip24, base_block_hash, block_hash)
    }
    // fn load_masternode_list_from_db(&self, block_hash: [u8; 32]) -> Result<MasternodeList, CoreProviderError> {
    //     (self.load_masternode_list_from_db)(self.context, block_hash)
    // }
    // fn save_masternode_list_into_db(&self, list_block_hash: [u8; 32], modified_masternodes: BTreeMap<[u8; 32], QualifiedMasternodeListEntry>) -> Result<bool, CoreProviderError> {
    //     (self.save_masternode_list_into_db)(self.context, list_block_hash, modified_masternodes)
    // }
    // fn load_llmq_snapshot_from_db(&self, block_hash: [u8; 32]) -> Result<QuorumSnapshot, CoreProviderError> {
    //     (self.load_llmq_snapshot_from_db)(self.context, block_hash)
    // }
    //
    // fn save_llmq_snapshot_into_db(&self, block_hash: [u8; 32], llmq_snapshot: QuorumSnapshot) -> Result<bool, CoreProviderError> {
    //     (self.save_llmq_snapshot_into_db)(self.context, block_hash, llmq_snapshot)
    // }

    fn update_address_usage_of_masternodes(&self, masternodes: Vec<QualifiedMasternodeListEntry>) {
        (self.update_address_usage_of_masternodes)(self.context, masternodes)
    }

    fn issue_with_masternode_list_from_peer(&self, is_dip24: bool, peer: *const std::os::raw::c_void) {
        (self.issue_with_masternode_list_from_peer)(self.context, is_dip24, peer)
    }

    fn block_by_hash(&self, block_hash: [u8; 32]) -> Result<MBlock, CoreProviderError> {
        (self.block_by_hash)(self.context, block_hash)
    }

    fn last_block_for_block_hash(&self, block_hash: [u8; 32], peer: *const std::os::raw::c_void) -> Result<MBlock, CoreProviderError> {
        (self.last_block_for_block_hash)(self.context, block_hash, peer)
    }

    fn lookup_cl_signature_by_block_hash(&self, block_hash: [u8; 32]) -> Result<[u8; 96], CoreProviderError> {
        (self.get_cl_signature_by_block_hash)(self.context, block_hash)
    }
    fn notify_sync_state(&self, state: CacheState) {
        (self.notify_sync_state)(self.context, state)
    }
    fn dequeue_masternode_list(&self, is_dip24: bool) {
        (self.dequeue_masternode_list)(self.context, is_dip24)
    }
}

#[ferment_macro::export]
impl FFICoreProvider  {
    pub fn new<
        BHT: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        BHH: Fn(*const std::os::raw::c_void, u32) -> Option<[u8; 32]> + Send + Sync + 'static,
        TIPBH: Fn(*const std::os::raw::c_void) -> u32 + Send + Sync + 'static,
        BORLT: Fn(*const std::os::raw::c_void, u32) -> Result<Block, CoreProviderError> + Send + Sync + 'static,
        BBH: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MBlock, CoreProviderError> + Send + Sync + 'static,
        LBBBH: Fn(*const std::os::raw::c_void, [u8; 32], *const std::os::raw::c_void) -> Result<MBlock, CoreProviderError> + Send + Sync + 'static,
        INS: Fn(*const std::os::raw::c_void, [u8; 32]) + Send + Sync + 'static,
        CLSBH: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<[u8; 96], CoreProviderError> + Send + Sync + 'static,
        // SML: Fn(*const std::os::raw::c_void, [u8; 32], BTreeMap<[u8; 32], QualifiedMasternodeListEntry>) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        // LML: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<MasternodeList, CoreProviderError> + Send + Sync + 'static,
        // SLS: Fn(*const std::os::raw::c_void, [u8; 32], QuorumSnapshot) -> Result<bool, CoreProviderError> + Send + Sync + 'static,
        // LLS: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<QuorumSnapshot, CoreProviderError> + Send + Sync + 'static,
        UMU: Fn(*const std::os::raw::c_void, Vec<QualifiedMasternodeListEntry>) + Send + Sync + 'static,
        RRIR: Fn(*const std::os::raw::c_void, bool, [u8; 32], [u8; 32]) -> bool + Send + Sync + 'static,
        IWMLFP: Fn(*const std::os::raw::c_void, bool, *const std::os::raw::c_void) + Send + Sync + 'static,
        NSS: Fn(*const std::os::raw::c_void, CacheState) + Send + Sync + 'static,
        DML: Fn(*const std::os::raw::c_void, bool) + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        get_block_height_by_hash: BHT,
        get_block_hash_by_height: BHH,
        get_block_by_height_or_last_terminal: BORLT,
        block_by_hash: BBH,
        last_block_for_block_hash: LBBBH,
        get_tip_height: TIPBH,
        add_insight: INS,
        get_cl_signature_by_block_hash: CLSBH,
        // load_masternode_list_from_db: LML,
        // save_masternode_list_into_db: SML,
        // load_llmq_snapshot_from_db: LLS,
        // save_llmq_snapshot_into_db: SLS,
        update_address_usage_of_masternodes: UMU,
        remove_request_in_retrieval: RRIR,
        issue_with_masternode_list_from_peer: IWMLFP,
        notify_sync_state: NSS,
        dequeue_masternode_list: DML,
        context: *const std::os::raw::c_void,
    ) -> Self {
        Self {
            chain_type,
            context,
            get_block_height_by_hash: Arc::new(get_block_height_by_hash),
            get_block_hash_by_height: Arc::new(get_block_hash_by_height),
            get_block_by_height_or_last_terminal: Arc::new(get_block_by_height_or_last_terminal),
            block_by_hash: Arc::new(block_by_hash),
            get_tip_height: Arc::new(get_tip_height),
            last_block_for_block_hash: Arc::new(last_block_for_block_hash),
            add_insight: Arc::new(add_insight),
            get_cl_signature_by_block_hash: Arc::new(get_cl_signature_by_block_hash),
            // load_masternode_list_from_db: Arc::new(load_masternode_list_from_db),
            // save_masternode_list_into_db: Arc::new(save_masternode_list_into_db),
            // load_llmq_snapshot_from_db: Arc::new(load_llmq_snapshot_from_db),
            // save_llmq_snapshot_into_db: Arc::new(save_llmq_snapshot_into_db),
            update_address_usage_of_masternodes: Arc::new(update_address_usage_of_masternodes),
            remove_request_in_retrieval: Arc::new(remove_request_in_retrieval),
            issue_with_masternode_list_from_peer: Arc::new(issue_with_masternode_list_from_peer),
            notify_sync_state: Arc::new(notify_sync_state),
            dequeue_masternode_list: Arc::new(dequeue_masternode_list),
        }
    }
}

#[cfg(test)]
impl FFICoreProvider {
    pub fn register_default(context: Arc<FFIContext>, chain_type: ChainType) -> Self {
        use dash_spv_crypto::crypto::byte_util::Reversed;
        let context_raw = Arc::into_raw(context.clone()) as *const std::ffi::c_void;
        Self {
            context: context_raw,
            chain_type: chain_type.clone(),
            block_by_hash: {
                let clone_chain = chain_type.clone();
                Arc::new(move |context, block_hash| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_for_hash(block_hash)
                        .map(MBlock::from)
                        .ok_or(CoreProviderError::NullResult(format!("Block for block_hash: {} ({}) not found", block_hash.to_lower_hex_string(), block_hash.reversed().to_lower_hex_string())));
                    std::mem::forget(context);
                    #[cfg(feature = "use_serde")]
                    if result.is_err() {
                        return clone_chain.insight_url()
                            .ok_or(CoreProviderError::NullResult(format!("No insight for chain {:?}", clone_chain)))
                            .and_then(|url| dash_spv_masternode_processor::util::insight::insight_block_by_block_hash(url, &dash_spv_crypto::crypto::byte_util::Reversed::reversed(&block_hash))
                            .map(MBlock::from)
                            .map_err(|e| CoreProviderError::NullResult(format!("Block for block_hash: {} ({}) not found", block_hash.to_lower_hex_string(), block_hash.reversed().to_lower_hex_string()))));
                    }
                    result
                })
            },
            get_tip_height: {
                let clone_chain = chain_type.clone();
                Arc::new(move |context| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.get_tip_height();
                    std::mem::forget(context);
                    result
                })

            },
            last_block_for_block_hash: {
                let clone_chain = chain_type.clone();
                Arc::new(move |context, block_hash, peer| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_for_hash(block_hash)
                        .map(MBlock::from)
                        .ok_or(CoreProviderError::NullResult(format!("Last block for block_hash: {} ({}) not found", block_hash.to_lower_hex_string(), block_hash.reversed().to_lower_hex_string())));
                    std::mem::forget(context);
                    #[cfg(feature = "use_serde")]
                    if result.is_err() {
                        return clone_chain.insight_url()
                            .ok_or(CoreProviderError::NullResult(format!("No insight for chain {:?}", clone_chain)))
                            .and_then(|url| dash_spv_masternode_processor::util::insight::insight_block_by_block_hash(url, &block_hash.reversed())
                                .map(MBlock::from)
                                .map_err(|e| CoreProviderError::NullResult(e.to_string())));
                    }
                    result
                })
            },
            get_block_height_by_hash: {
                let clone_chain = chain_type.clone();
                Arc::new(move |context, block_hash| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_height_for_hash(block_hash);
                    std::mem::forget(context);
                    #[cfg(feature = "use_serde")]
                    if result == u32::MAX {
                        return clone_chain.insight_url()
                            .and_then(|url| dash_spv_masternode_processor::util::insight::insight_block_by_block_hash(url, &block_hash.reversed())
                                .ok()
                                .map(|b| MBlock::from(b).height))
                            .unwrap_or(u32::MAX);
                    }
                    result
                })
            },
            get_block_hash_by_height: {
                let clone_chain = chain_type.clone();
                Arc::new(move |context, block_height| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_hash_for_height(block_height);
                    std::mem::forget(context);
                    #[cfg(feature = "use_serde")]
                    if result.is_err() {
                        return clone_chain.insight_url()
                            .ok_or(CoreProviderError::NullResult(format!("No insight for chain {:?}", clone_chain)))
                            .and_then(|url| dash_spv_masternode_processor::util::insight::insight_block_by_block_height(url, block_height)
                                .map(|b| MBlock::from(b).hash)
                                .map_err(|e| CoreProviderError::NullResult(e.to_string())))
                            .ok()
                    }

                    result.ok()
                })
            },
            get_block_by_height_or_last_terminal: {
                let clone_chain = chain_type.clone();
                Arc::new(move |context, block_height| unsafe {
                    let context = Arc::from_raw(context as *const FFIContext);
                    let result = context.block_for_height(block_height)
                        .map(Block::from)
                        .ok_or(CoreProviderError::NullResult(format!("No block or last terminal by height {} ", block_height)));
                    std::mem::forget(context);
                    #[cfg(feature = "use_serde")]
                    if result.is_err() {
                        return clone_chain.insight_url()
                            .ok_or(CoreProviderError::NullResult(format!("No insight for chain {:?}", clone_chain)))
                            .and_then(|url| dash_spv_masternode_processor::util::insight::insight_block_by_block_height(url, block_height)
                                .map(|b| Block::from(b))
                                .map_err(|e| CoreProviderError::NullResult(e.to_string())));
                    }
                    result
                })
            },
            get_cl_signature_by_block_hash: Arc::new(move |context, block_hash| unsafe {
                let context = Arc::from_raw(context as *const FFIContext);
                let result = context.cl_signature_by_block_hash(&block_hash)
                    .cloned()
                    .ok_or(CoreProviderError::NullResult(format!("No cl signature by block_hash {} ({})", block_hash.to_lower_hex_string(), block_hash.reversed().to_lower_hex_string())));
                std::mem::forget(context);
                result
            }),
            add_insight: Arc::new(|context, block_hash| {}),
            // load_masternode_list_from_db: Arc::new(|context, block_hash| Err(CoreProviderError::MissedMasternodeListAt(block_hash))),
            // save_masternode_list_into_db: Arc::new(|context, list_block_hash, modified_masternodes| Ok(true)),
            // load_llmq_snapshot_from_db: Arc::new(|context, block_hash| Err(CoreProviderError::MissedMasternodeListAt(block_hash))),
            // save_llmq_snapshot_into_db: Arc::new(|context, block_hash, snapshot| Ok(true)),
            update_address_usage_of_masternodes: Arc::new(|context, modified_masternodes| {}),
            remove_request_in_retrieval: Arc::new(|context, is_dip24, base_block_hash, block_hash| true),
            issue_with_masternode_list_from_peer: Arc::new(|context, is_dip24, peer| {}),
            notify_sync_state: Arc::new(|context, state| {}),
            dequeue_masternode_list: Arc::new(|context, is_dip24| {}),
        }
    }
    pub fn default_processor(context: Arc<FFIContext>, chain_type: ChainType) -> MasternodeProcessor {
        let network = dashcore::Network::from(chain_type.clone());
        let provider = Arc::new(Self::register_default(context, chain_type));
        MasternodeProcessor::new(provider.clone(), network)
    }
}
