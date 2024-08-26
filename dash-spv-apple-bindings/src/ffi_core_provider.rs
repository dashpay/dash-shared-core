use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::crypto::byte_util::{UInt256, UInt768};
use dash_spv_masternode_processor::models;
use dash_spv_masternode_processor::models::{LLMQSnapshot, MasternodeList};
use dash_spv_masternode_processor::processing::core_provider::CoreProvider;
use dash_spv_masternode_processor::processing::{CoreProviderError, ProcessingError};
// use crate::ffi::callbacks::{AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash, GetCLSignatureByBlockHash, GetLLMQSnapshotByBlockHash, HashDestroy, LLMQSnapshotDestroy, MasternodeListDestroy, MasternodeListLookup, MasternodeListSave, MerkleRootLookup, SaveCLSignature, SaveLLMQSnapshot, ShouldProcessDiffWithRange};
// use crate::ffi::from::FromFFI;
// use crate::ffi::to::ToFFI;
// use crate::types;

// #[ferment_macro::opaque]
// pub struct FFICoreProvider {
//     /// External Masternode Manager Diff Message Context
//     pub opaque_context: *const std::ffi::c_void,
//     pub chain_type: ChainType,
//     pub get_block_height_by_hash: GetBlockHeightByHash,
//     pub get_merkle_root_by_hash: MerkleRootLookup,
//     pub get_block_hash_by_height: GetBlockHashByHeight,
//     pub get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
//     pub get_cl_signature_by_block_hash: GetCLSignatureByBlockHash,
//     pub save_llmq_snapshot: SaveLLMQSnapshot,
//     pub save_cl_signature: SaveCLSignature,
//     pub get_masternode_list_by_block_hash: MasternodeListLookup,
//     pub save_masternode_list: MasternodeListSave,
//     pub destroy_masternode_list: MasternodeListDestroy,
//     pub add_insight: AddInsightBlockingLookup,
//     pub destroy_hash: HashDestroy,
//     pub destroy_snapshot: LLMQSnapshotDestroy,
//     pub should_process_diff_with_range: ShouldProcessDiffWithRange,
// }
// #[ferment_macro::export]
#[ferment_macro::opaque]
pub struct FFICoreProvider {
    /// External Masternode Manager Diff Message Context
    pub opaque_context: *const std::ffi::c_void,
    pub chain_type: ChainType,
    pub get_block_height_by_hash: Box<dyn Fn(UInt256) -> u32>,
    pub get_merkle_root_by_hash: Box<dyn Fn(UInt256) -> Result<UInt256, CoreProviderError>>,
    pub get_block_hash_by_height: Box<dyn Fn(u32) -> Result<UInt256, CoreProviderError>>,
    pub get_llmq_snapshot_by_block_hash: Box<dyn Fn(UInt256) -> Result<LLMQSnapshot, CoreProviderError>>,
    pub get_cl_signature_by_block_hash: Box<dyn Fn(UInt256) -> Result<UInt768, CoreProviderError>>,
    pub save_llmq_snapshot: Box<dyn Fn(UInt256, LLMQSnapshot) -> bool>,
    pub save_cl_signature: Box<dyn Fn(UInt256, UInt768) -> bool>,
    pub get_masternode_list_by_block_hash: Box<dyn Fn(UInt256) -> Result<MasternodeList, CoreProviderError>>,
    pub save_masternode_list: Box<dyn Fn(UInt256, MasternodeList) -> bool>,
    pub destroy_masternode_list: Box<dyn Fn(MasternodeList)>,
    pub add_insight: Box<dyn Fn(UInt256)>,
    pub destroy_hash: Box<dyn Fn(UInt256)>,
    pub destroy_snapshot: Box<dyn Fn(LLMQSnapshot)>,
    pub should_process_diff_with_range: Box<dyn Fn(UInt256, UInt256) -> ProcessingError>,
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
// impl CoreProvider for FFICoreProvider {
//     fn chain_type(&self) -> ChainType {
//         self.chain_type
//     }
//
//     fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Result<UInt256, CoreProviderError> {
//         lookup_merkle_root_by_hash_callback(
//             block_hash,
//             |h: UInt256| unsafe { (self.get_merkle_root_by_hash)(ferment_interfaces::boxed(h.0), self.opaque_context) },
//             |hash: *mut u8| unsafe { (self.destroy_hash)(hash) },
//         )
//     }
//
//     fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<models::MasternodeList, CoreProviderError> {
//         // First look at the local cache
//         lookup_masternode_list_callback(
//             block_hash,
//             |h| unsafe { (self.get_masternode_list_by_block_hash)(ferment_interfaces::boxed(h.0), self.opaque_context) },
//             |list: *mut types::MasternodeList| unsafe { (self.destroy_masternode_list)(list) },
//         )
//     }
//
//     fn lookup_cl_signature_by_block_hash(&self, block_hash: UInt256) -> Result<UInt768, CoreProviderError> {
//         lookup_cl_signature_by_block_hash_callback(
//             block_hash,
//             |h: UInt256| unsafe { (self.get_cl_signature_by_block_hash)(ferment_interfaces::boxed(h.0), self.opaque_context) },
//             |obj: *mut u8| unsafe { (self.destroy_hash)(obj) }
//         )
//     }
//
//     fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<models::LLMQSnapshot, CoreProviderError> {
//         lookup_snapshot_by_block_hash_callback(
//             block_hash,
//             |h: UInt256| unsafe { (self.get_llmq_snapshot_by_block_hash)(ferment_interfaces::boxed(h.0), self.opaque_context) },
//             |snapshot: *mut types::LLMQSnapshot| unsafe { (self.destroy_snapshot)(snapshot) },
//         )
//     }
//
//     fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<UInt256, CoreProviderError> {
//         lookup_block_hash_by_height_callback(
//             block_height,
//             |h: u32| unsafe { (self.get_block_hash_by_height)(h, self.opaque_context) },
//             |hash: *mut u8| unsafe { (self.destroy_hash)(hash) },
//         )
//     }
//
//     fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32 {
//         unsafe { (self.get_block_height_by_hash)(ferment_interfaces::boxed(block_hash.0), self.opaque_context) }
//     }
//
//     fn add_insight(&self, block_hash: UInt256) {
//         unsafe { (self.add_insight)(ferment_interfaces::boxed(block_hash.0), self.opaque_context) }
//     }
//
//     fn should_process_diff_with_range(
//         &self,
//         base_block_hash: UInt256,
//         block_hash: UInt256,
//     ) -> Result<u8, ProcessingError> {
//         unsafe {
//             match (self.should_process_diff_with_range)(
//                 ferment_interfaces::boxed(base_block_hash.0),
//                 ferment_interfaces::boxed(block_hash.0),
//                 self.opaque_context,
//             ) {
//                 ProcessingError::None => Ok(0),
//                 err => Err(err)
//             }
//         }
//     }
//
//     fn save_snapshot(&self, block_hash: UInt256, snapshot: models::LLMQSnapshot) -> bool {
//         unsafe {
//             (self.save_llmq_snapshot)(
//                 ferment_interfaces::boxed(block_hash.0),
//                 ferment_interfaces::boxed(snapshot.encode()),
//                 self.opaque_context,
//             )
//         }
//     }
//     fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &models::MasternodeList) -> bool {
//         unsafe {
//             (self.save_masternode_list)(
//                 ferment_interfaces::boxed(block_hash.0),
//                 ferment_interfaces::boxed(masternode_list.encode()),
//                 self.opaque_context,
//             )
//         }
//     }
// }



// impl FFICoreProvider {
//     #[allow(clippy::too_many_arguments)]
//     pub fn new(
//         get_merkle_root_by_hash: MerkleRootLookup,
//         get_block_height_by_hash: GetBlockHeightByHash,
//         get_block_hash_by_height: GetBlockHashByHeight,
//         get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
//         get_cl_signature_by_block_hash: GetCLSignatureByBlockHash,
//         save_llmq_snapshot: SaveLLMQSnapshot,
//         save_cl_signature: SaveCLSignature,
//         get_masternode_list_by_block_hash: MasternodeListLookup,
//         save_masternode_list: MasternodeListSave,
//         destroy_masternode_list: MasternodeListDestroy,
//         add_insight: AddInsightBlockingLookup,
//         destroy_hash: HashDestroy,
//         destroy_snapshot: LLMQSnapshotDestroy,
//         should_process_diff_with_range: ShouldProcessDiffWithRange,
//         opaque_context: *const std::ffi::c_void,
//         chain_type: ChainType,
//     ) -> Self {
//         Self {
//             get_merkle_root_by_hash,
//             get_block_height_by_hash,
//             get_block_hash_by_height,
//             get_llmq_snapshot_by_block_hash,
//             get_cl_signature_by_block_hash,
//             save_llmq_snapshot,
//             save_cl_signature,
//             get_masternode_list_by_block_hash,
//             save_masternode_list,
//             destroy_masternode_list,
//             add_insight,
//             destroy_hash,
//             destroy_snapshot,
//             should_process_diff_with_range,
//             opaque_context,
//             chain_type,
//         }
//     }
// }
//
// pub fn lookup_masternode_list_callback<L, D>(
//     block_hash: UInt256,
//     masternode_list_lookup: L,
//     masternode_list_destroy: D
// ) -> Result<models::MasternodeList, CoreProviderError>
//     where
//         L: Fn(UInt256) -> *mut types::MasternodeList + Copy,
//         D: Fn(*mut types::MasternodeList) {
//     lookup(
//         block_hash,
//         masternode_list_lookup,
//         masternode_list_destroy,
//         |result| Ok(unsafe { (&*result).decode() }))
// }
//
// pub fn lookup_cl_signature_by_block_hash_callback<L, D>(
//     block_hash: UInt256,
//     lookup_callback: L,
//     destroy_callback: D,
// ) -> Result<UInt768, CoreProviderError>
//     where
//         L: Fn(UInt256) -> *mut u8 + Copy,
//         D: Fn(*mut u8) {
//     lookup(
//         block_hash,
//         lookup_callback,
//         destroy_callback,
//         |result| UInt768::from_mut(result).map_err(CoreProviderError::from))
// }
//
// pub fn lookup_snapshot_by_block_hash_callback<L, D>(
//     block_hash: UInt256,
//     snapshot_lookup: L,
//     snapshot_destroy: D,
// ) -> Result<models::LLMQSnapshot, CoreProviderError>
//     where
//         L: Fn(UInt256) -> *mut types::LLMQSnapshot + Copy,
//         D: Fn(*mut types::LLMQSnapshot) {
//     lookup(
//         block_hash,
//         snapshot_lookup,
//         snapshot_destroy,
//         |result| Ok(unsafe { (*result).decode() }))
// }
//
// pub fn lookup_block_hash_by_height_callback<L, D>(
//     block_height: u32,
//     lookup_hash: L,
//     destroy_hash: D,
// ) -> Result<UInt256, CoreProviderError>
//     where
//         L: Fn(u32) -> *mut u8 + Copy,
//         D: Fn(*mut u8) {
//     lookup(
//         block_height,
//         lookup_hash,
//         destroy_hash,
//         |result| UInt256::from_mut(result).map_err(CoreProviderError::from))
// }
//
// pub fn lookup_merkle_root_by_hash_callback<L, D>(
//     block_hash: UInt256,
//     lookup_hash: L,
//     destroy_hash: D,
// ) -> Result<UInt256, CoreProviderError>
//     where
//         L: Fn(UInt256) -> *mut u8 + Copy,
//         D: Fn(*mut u8) {
//     lookup(
//         block_hash,
//         lookup_hash,
//         destroy_hash,
//         |k| UInt256::from_mut(k).map_err(CoreProviderError::from))
// }
//
// fn lookup<P, L, D, R, FR, FROM>(params: P, lookup_callback: L, destroy_callback: D, from_conversion: FROM) -> Result<R, CoreProviderError> where
//     FROM: Fn(*mut FR) -> Result<R, CoreProviderError>,
//     L: Fn(P) -> *mut FR + Copy,
//     D: Fn(*mut FR) {
//     let result = lookup_callback(params);
//     if !result.is_null() {
//         let data = from_conversion(result);
//         destroy_callback(result);
//         data
//     } else {
//         Err(CoreProviderError::NullResult)
//     }
// }
