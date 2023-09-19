use std::collections::BTreeMap;
use std::fmt::Debug;
use rs_ffi_interfaces::boxed;
use crate::chain::common::{ChainType, IHaveChainSettings};
use crate::crypto::UInt256;
use crate::ffi::callbacks::{AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash, GetLLMQSnapshotByBlockHash, HashDestroy, LLMQSnapshotDestroy, MasternodeListDestroy, MasternodeListLookup, MasternodeListSave, MerkleRootLookup, SaveLLMQSnapshot, ShouldProcessDiffWithRange};
use crate::{models, types};
use crate::crypto::byte_util::{MutDecodable, Zeroable};
use crate::ffi::from::FromFFI;
use crate::ffi::to::ToFFI;
use crate::processing::ProcessingError;

pub trait CoreProvider: Debug {
    fn chain_type(&self) -> ChainType;
    fn find_masternode_list(&self, block_hash: UInt256, cached_lists: &BTreeMap<UInt256, models::MasternodeList>, unknown_lists: &mut Vec<UInt256>) -> Result<models::MasternodeList, CoreProviderError>;
    fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Result<UInt256, CoreProviderError>;
    fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<models::MasternodeList, CoreProviderError>;
    fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<models::LLMQSnapshot, CoreProviderError>;
    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<UInt256, CoreProviderError>;
    fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32;
    fn add_insight(&self, block_hash: UInt256);
    fn should_process_diff_with_range(&self, base_block_hash: UInt256, block_hash: UInt256) -> Result<(), ProcessingError>;
    fn save_snapshot(&self, block_hash: UInt256, snapshot: models::LLMQSnapshot) -> bool;
    fn find_snapshot(&self, block_hash: UInt256, cached_snapshots: &BTreeMap<UInt256, models::LLMQSnapshot>) -> Result<models::LLMQSnapshot, CoreProviderError>;
    fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &models::MasternodeList) -> bool;
    fn masternode_info_for_height(&self, work_block_height: u32, cached_lists: &BTreeMap<UInt256, models::MasternodeList>, cached_snapshots: &BTreeMap<UInt256, models::LLMQSnapshot>, unknown_lists: &mut Vec<UInt256>) -> Result<(models::MasternodeList, models::LLMQSnapshot, UInt256), CoreProviderError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[rs_ffi_macro_derive::impl_ffi_conv]
pub enum CoreProviderError {
    NullResult,
    ByteError(byte::Error),
    BadBlockHash(UInt256),
    NoMasternodeList,
}
impl std::fmt::Display for CoreProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for CoreProviderError {}

impl From<byte::Error> for CoreProviderError {
    fn from(value: byte::Error) -> Self {
        CoreProviderError::ByteError(value)
    }
}

pub struct FFICoreProvider {
    /// External Masternode Manager Diff Message Context
    pub opaque_context: *const std::ffi::c_void,
    pub chain_type: ChainType,
    pub get_block_height_by_hash: GetBlockHeightByHash,
    pub get_merkle_root_by_hash: MerkleRootLookup,
    get_block_hash_by_height: GetBlockHashByHeight,
    get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
    save_llmq_snapshot: SaveLLMQSnapshot,
    get_masternode_list_by_block_hash: MasternodeListLookup,
    save_masternode_list: MasternodeListSave,
    destroy_masternode_list: MasternodeListDestroy,
    add_insight: AddInsightBlockingLookup,
    destroy_hash: HashDestroy,
    destroy_snapshot: LLMQSnapshotDestroy,
    should_process_diff_with_range: ShouldProcessDiffWithRange,
}

impl std::fmt::Debug for FFICoreProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreProvider")
            .field("chain", &self.chain_type)
            .field("context", &self.opaque_context)
            .finish()
    }
}

impl CoreProvider for FFICoreProvider {
    fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    fn find_masternode_list(&self, block_hash: UInt256, cached_lists: &BTreeMap<UInt256, models::MasternodeList>, unknown_lists: &mut Vec<UInt256>) -> Result<models::MasternodeList, CoreProviderError> {
        let genesis_hash = self.chain_type().genesis_hash();
        if block_hash.is_zero() {
            // If it's a zero block we don't expect models list here
            // println!("find {}: {} EMPTY BLOCK HASH -> None", self.lookup_block_height_by_hash(block_hash), block_hash);
            Err(CoreProviderError::BadBlockHash(block_hash))
        } else if block_hash.eq(&genesis_hash) {
            // If it's a genesis block we don't expect models list here
            // println!("find {}: {} It's a genesis -> Some(EMPTY MNL)", self.lookup_block_height_by_hash(block_hash), block_hash);
            Ok(models::MasternodeList::new(BTreeMap::default(), BTreeMap::default(), block_hash, self.lookup_block_height_by_hash(block_hash), false))
            // None
        } else if let Some(cached) = cached_lists.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            // println!("find_masternode_list (cache) {}: {} -> Some({:?})", self.lookup_block_height_by_hash(block_hash), block_hash, cached);
            Ok(cached.clone())
        } else if let Ok(looked) = self.lookup_masternode_list(block_hash) {
            // Getting it from FFI directly
            // println!("find_masternode_list {}: {} (ffi) -> Some({:?})", self.lookup_block_height_by_hash(block_hash), block_hash, looked);
            Ok(looked)
        } else {
            // println!("find {}: {} Unknown -> None", self.lookup_block_height_by_hash(block_hash), block_hash);
            if self.lookup_block_height_by_hash(block_hash) != u32::MAX {
                unknown_lists.push(block_hash);
            } else if !self.chain_type().is_mainnet() {
                self.add_insight(block_hash);
                if self.lookup_block_height_by_hash(block_hash) != u32::MAX {
                    unknown_lists.push(block_hash);
                }
            }
            Err(CoreProviderError::NoMasternodeList)
        }
    }

    fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<models::MasternodeList, CoreProviderError> {
        // First look at the local cache
        Self::lookup_masternode_list_callback(
            block_hash,
            |h| unsafe { (self.get_masternode_list_by_block_hash)(boxed(h.0), self.opaque_context) },
            |list: *mut types::MasternodeList| unsafe { (self.destroy_masternode_list)(list) },
        )
    }

    fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32 {
        unsafe { (self.get_block_height_by_hash)(boxed(block_hash.0), self.opaque_context) }
    }

    fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Result<UInt256, CoreProviderError> {
        Self::lookup_merkle_root_by_hash_callback(
            block_hash,
            |h: UInt256| unsafe { (self.get_merkle_root_by_hash)(boxed(h.0), self.opaque_context) },
            |hash: *mut u8| unsafe { (self.destroy_hash)(hash) },
        )
    }

    fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<models::LLMQSnapshot, CoreProviderError> {
        Self::lookup_snapshot_by_block_hash_callback(
            block_hash,
            |h: UInt256| unsafe {
                (self.get_llmq_snapshot_by_block_hash)(boxed(h.0), self.opaque_context)
            },
            |snapshot: *mut types::LLMQSnapshot| unsafe { (self.destroy_snapshot)(snapshot) },
        )
    }

    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<UInt256, CoreProviderError> {
        Self::lookup_block_hash_by_height_callback(
            block_height,
            |h: u32| unsafe { (self.get_block_hash_by_height)(h, self.opaque_context) },
            |hash: *mut u8| unsafe { (self.destroy_hash)(hash) },
        )
    }

    fn add_insight(&self, block_hash: UInt256) {
        unsafe { (self.add_insight)(boxed(block_hash.0), self.opaque_context) }
    }

    fn should_process_diff_with_range(
        &self,
        base_block_hash: UInt256,
        block_hash: UInt256,
    ) -> Result<(), ProcessingError> {
        unsafe {
            match (self.should_process_diff_with_range)(
                boxed(base_block_hash.0),
                boxed(block_hash.0),
                self.opaque_context,
            ) {
                ProcessingError::None => Ok(()),
                err => Err(err)
            }
        }
    }

    fn find_snapshot(&self, block_hash: UInt256, cached_snapshots: &BTreeMap<UInt256, models::LLMQSnapshot>) -> Result<models::LLMQSnapshot, CoreProviderError> {
        if let Some(cached) = cached_snapshots.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            Ok(cached.clone())
        } else {
            self.lookup_snapshot_by_block_hash(block_hash)
        }
    }
    fn save_snapshot(&self, block_hash: UInt256, snapshot: models::LLMQSnapshot) -> bool {
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(&snapshot, self.lookup_block_height_by_hash(block_hash));
        unsafe {
            (self.save_llmq_snapshot)(
                boxed(block_hash.0),
                boxed(snapshot.encode()),
                self.opaque_context,
            )
        }
    }
    fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &models::MasternodeList) -> bool {
        unsafe {
            (self.save_masternode_list)(
                boxed(block_hash.0),
                boxed(masternode_list.encode()),
                self.opaque_context,
            )
        }
    }
    fn masternode_info_for_height(&self, work_block_height: u32, cached_lists: &BTreeMap<UInt256, models::MasternodeList>, cached_snapshots: &BTreeMap<UInt256, models::LLMQSnapshot>, unknown_lists: &mut Vec<UInt256>) -> Result<(models::MasternodeList, models::LLMQSnapshot, UInt256), CoreProviderError> {
        self.lookup_block_hash_by_height(work_block_height)
            .map_err(|err| panic!("MISSING: block for height: {}: error: {}", work_block_height, err))
            .and_then(|work_block_hash| self.find_masternode_list(work_block_hash, cached_lists, unknown_lists)
                .and_then(|masternode_list| self.find_snapshot(work_block_hash, cached_snapshots)
                    .map(|snapshot| (masternode_list, snapshot, work_block_hash))))
            // .ok_or(CoreProviderError::NullResult)
    }
}



impl FFICoreProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        get_merkle_root_by_hash: MerkleRootLookup,
        get_block_height_by_hash: GetBlockHeightByHash,
        get_block_hash_by_height: GetBlockHashByHeight,
        get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
        save_llmq_snapshot: SaveLLMQSnapshot,
        get_masternode_list_by_block_hash: MasternodeListLookup,
        save_masternode_list: MasternodeListSave,
        destroy_masternode_list: MasternodeListDestroy,
        add_insight: AddInsightBlockingLookup,
        destroy_hash: HashDestroy,
        destroy_snapshot: LLMQSnapshotDestroy,
        should_process_diff_with_range: ShouldProcessDiffWithRange,
        opaque_context: *const std::ffi::c_void,
        chain_type: ChainType,
    ) -> Self {
        Self {
            get_merkle_root_by_hash,
            get_block_height_by_hash,
            get_block_hash_by_height,
            get_llmq_snapshot_by_block_hash,
            save_llmq_snapshot,
            get_masternode_list_by_block_hash,
            save_masternode_list,
            destroy_masternode_list,
            add_insight,
            destroy_hash,
            destroy_snapshot,
            should_process_diff_with_range,
            opaque_context,
            chain_type,
        }
    }
}

impl FFICoreProvider {
    fn lookup<P, L, D, R, FR, FROM>(params: P, lookup_callback: L, destroy_callback: D, from_conversion: FROM) -> Result<R, CoreProviderError> where
        FROM: Fn(*mut FR) -> Result<R, CoreProviderError>,
        L: Fn(P) -> *mut FR + Copy,
        D: Fn(*mut FR) {
        let result = lookup_callback(params);
        if !result.is_null() {
            let data = from_conversion(result);
            destroy_callback(result);
            data
        } else {
            Err(CoreProviderError::NullResult)
        }
    }

    pub fn lookup_masternode_list_callback<MNL, MND>(block_hash: UInt256, masternode_list_lookup: MNL, masternode_list_destroy: MND) -> Result<models::MasternodeList, CoreProviderError>
        where
            MNL: Fn(UInt256) -> *mut types::MasternodeList + Copy,
            MND: Fn(*mut types::MasternodeList),
    {
        Self::lookup(block_hash, masternode_list_lookup, masternode_list_destroy, |result| Ok(unsafe { (&*result).decode() }))
        // let lookup_result = masternode_list_lookup(block_hash);
        // if !lookup_result.is_null() {
        //     let data = unsafe { (*lookup_result).decode() };
        //     masternode_list_destroy(lookup_result);
        //     Some(data)
        // } else {
        //     None
        // }
    }

    fn destroy_masternode_list(&self, block_hash: UInt256) {

    }

    pub fn lookup_block_hash_by_height_callback<BL, DH>(
        block_height: u32,
        lookup_hash: BL,
        destroy_hash: DH,
    ) -> Result<UInt256, CoreProviderError>
        where
            BL: Fn(u32) -> *mut u8 + Copy,
            DH: Fn(*mut u8),
    {
        Self::lookup(block_height, lookup_hash, destroy_hash, |result| UInt256::from_mut(result).map_err(CoreProviderError::from))

        // let lookup_result = lookup(block_height);
        // if !lookup_result.is_null() {
        //     let hash = UInt256::from_mut(lookup_result);
        //     destroy_hash(lookup_result);
        //     hash
        // } else {
        //     None
        // }
    }

    pub fn lookup_merkle_root_by_hash_callback<MRL, DH>(
        block_hash: UInt256,
        lookup_hash: MRL,
        destroy_hash: DH,
    ) -> Result<UInt256, CoreProviderError>
        where MRL: Fn(UInt256) -> *mut u8 + Copy, DH: Fn(*mut u8) {
        Self::lookup(block_hash, lookup_hash, destroy_hash, |k| UInt256::from_mut(k).map_err(CoreProviderError::from))
    }

    pub fn lookup_snapshot_by_block_hash_callback<SL, SD>(
        block_hash: UInt256,
        snapshot_lookup: SL,
        snapshot_destroy: SD,
    ) -> Result<models::LLMQSnapshot, CoreProviderError>
        where
            SL: Fn(UInt256) -> *mut types::LLMQSnapshot + Copy,
            SD: Fn(*mut types::LLMQSnapshot),
    {
        let lookup_result = snapshot_lookup(block_hash);
        if !lookup_result.is_null() {
            let data = unsafe { (*lookup_result).decode() };
            snapshot_destroy(lookup_result);
            Ok(data)
        } else {
            Err(CoreProviderError::NullResult)
        }
    }


}