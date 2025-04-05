use std::sync::Arc;
use dashcore::bls_sig_utils::BLSSignature;
#[cfg(test)]
use dashcore::secp256k1::hashes::hex::DisplayHex;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dash_spv_crypto::network::ChainType;
#[cfg(all(test, feature = "use_serde"))]
use dash_spv_masternode_processor::common::block::MBlock;
use dash_spv_masternode_processor::processing::core_provider::{CoreProvider, CoreProviderError};
#[cfg(test)]
use dash_spv_masternode_processor::processing::MasternodeProcessor;
#[cfg(test)]
use dash_spv_masternode_processor::tests::FFIContext;
use dash_spv_masternode_processor::models::sync_state::CacheState;

#[ferment_macro::opaque]
pub struct FFICoreProvider {
    pub context: *const std::ffi::c_void,
    // pub context: Arc<FFIThreadSafeContext>,
    pub chain_type: ChainType,

    pub get_block_height_by_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>,
    pub get_block_hash_by_height: Arc<dyn Fn(*const std::os::raw::c_void, u32) -> Option<[u8; 32]>>,
    pub get_cl_signature_by_block_hash: Arc<dyn Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<BLSSignature, CoreProviderError>>,
    pub update_address_usage_of_masternodes: Arc<dyn Fn(*const std::os::raw::c_void, Vec<QualifiedMasternodeListEntry>)>,
    pub issue_with_masternode_list_from_peer: Arc<dyn Fn(*const std::os::raw::c_void, bool, *const std::os::raw::c_void)>,
    pub notify_sync_state: Arc<dyn Fn(*const std::os::raw::c_void, CacheState)>,
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
    fn lookup_cl_signature_by_block_hash(&self, block_hash: [u8; 32]) -> Result<BLSSignature, CoreProviderError> {
        (self.get_cl_signature_by_block_hash)(self.context, block_hash)
    }

    fn lookup_block_hash_by_height(&self, block_height: u32) -> Option<[u8; 32]> {
        (self.get_block_hash_by_height)(self.context, block_height)
    }

    fn lookup_block_height_by_hash(&self, block_hash: [u8; 32]) -> u32 {
        (self.get_block_height_by_hash)(self.context, block_hash)
    }

    fn update_address_usage_of_masternodes(&self, masternodes: Vec<QualifiedMasternodeListEntry>) {
        (self.update_address_usage_of_masternodes)(self.context, masternodes)
    }

    fn issue_with_masternode_list_from_peer(&self, is_dip24: bool, peer: *const std::os::raw::c_void) {
        (self.issue_with_masternode_list_from_peer)(self.context, is_dip24, peer)
    }
    fn notify_sync_state(&self, state: CacheState) {
        (self.notify_sync_state)(self.context, state)
    }
}

#[ferment_macro::export]
impl FFICoreProvider  {
    pub fn new<
        BHT: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        BHH: Fn(*const std::os::raw::c_void, u32) -> Option<[u8; 32]> + Send + Sync + 'static,
        CLSBH: Fn(*const std::os::raw::c_void, [u8; 32]) -> Result<BLSSignature, CoreProviderError> + Send + Sync + 'static,
        UMU: Fn(*const std::os::raw::c_void, Vec<QualifiedMasternodeListEntry>) + Send + Sync + 'static,
        IWMLFP: Fn(*const std::os::raw::c_void, bool, *const std::os::raw::c_void) + Send + Sync + 'static,
        NSS: Fn(*const std::os::raw::c_void, CacheState) + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        get_block_height_by_hash: BHT,
        get_block_hash_by_height: BHH,
        get_cl_signature_by_block_hash: CLSBH,
        update_address_usage_of_masternodes: UMU,
        issue_with_masternode_list_from_peer: IWMLFP,
        notify_sync_state: NSS,
        context: *const std::os::raw::c_void,
    ) -> Self {
        Self {
            chain_type,
            context,
            get_block_height_by_hash: Arc::new(get_block_height_by_hash),
            get_block_hash_by_height: Arc::new(get_block_hash_by_height),
            get_cl_signature_by_block_hash: Arc::new(get_cl_signature_by_block_hash),
            update_address_usage_of_masternodes: Arc::new(update_address_usage_of_masternodes),
            issue_with_masternode_list_from_peer: Arc::new(issue_with_masternode_list_from_peer),
            notify_sync_state: Arc::new(notify_sync_state),
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
            get_cl_signature_by_block_hash: Arc::new(move |context, block_hash| unsafe {
                let context = Arc::from_raw(context as *const FFIContext);
                let result = context.cl_signature_by_block_hash(&block_hash)
                    .map(|sig| BLSSignature::from(sig))
                    .ok_or(CoreProviderError::NullResult(format!("No cl signature by block_hash {} ({})", block_hash.to_lower_hex_string(), block_hash.reversed().to_lower_hex_string())));
                std::mem::forget(context);
                result
            }),
            update_address_usage_of_masternodes: Arc::new(|context, modified_masternodes| {}),
            issue_with_masternode_list_from_peer: Arc::new(|context, is_dip24, peer| {}),
            notify_sync_state: Arc::new(|context, state| {}),
        }
    }
    pub fn default_processor(context: Arc<FFIContext>, chain_type: ChainType) -> MasternodeProcessor {
        let network = dashcore::Network::from(chain_type.clone());
        let provider = Arc::new(Self::register_default(context, chain_type));
        MasternodeProcessor::new(provider.clone(), network)
    }
}
