use std::collections::BTreeMap;
use crate::chain::common::{ChainType, IHaveChainSettings};
use crate::crypto::byte_util::Zeroable;
use crate::crypto::UInt256;
use crate::models;
use crate::processing::ProcessingError;


pub trait CoreProvider: std::fmt::Debug {
    fn chain_type(&self) -> ChainType;
    fn find_masternode_list(&self, block_hash: UInt256, cached_lists: &BTreeMap<UInt256, models::MasternodeList>, unknown_lists: &mut Vec<UInt256>) -> Result<models::MasternodeList, CoreProviderError> {
        let genesis_hash = self.chain_type().genesis_hash();
        if block_hash.is_zero() {
            // If it's a zero block we don't expect models list here
            // println!("find {}: {} EMPTY BLOCK HASH -> None", self.lookup_block_height_by_hash(block_hash), block_hash);
            Err(CoreProviderError::BadBlockHash(block_hash))
        } else if block_hash.eq(&genesis_hash) {
            // If it's a genesis block we don't expect models list here
            // println!("find {}: {} It's a genesis -> Ok(EMPTY MNL)", self.lookup_block_height_by_hash(block_hash), block_hash);
            Ok(models::MasternodeList::new(BTreeMap::default(), BTreeMap::default(), block_hash, self.lookup_block_height_by_hash(block_hash), false))
            // None
        } else if let Some(cached) = cached_lists.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            // println!("find_masternode_list (cache) {}: {} -> Ok({:?})", self.lookup_block_height_by_hash(block_hash), block_hash, cached);
            Ok(cached.clone())
        } else if let Ok(looked) = self.lookup_masternode_list(block_hash) {
            // Getting it from FFI directly
            // println!("find_masternode_list {}: {} (ffi) -> Ok({:?})", self.lookup_block_height_by_hash(block_hash), block_hash, looked);
            Ok(looked)
        } else {
            // println!("find {}: {} Unknown -> Err", self.lookup_block_height_by_hash(block_hash), block_hash);
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
    fn find_snapshot(&self, block_hash: UInt256, cached_snapshots: &BTreeMap<UInt256, models::LLMQSnapshot>) -> Result<models::LLMQSnapshot, CoreProviderError> {
        if let Some(cached) = cached_snapshots.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            Ok(cached.clone())
        } else {
            self.lookup_snapshot_by_block_hash(block_hash)
        }
    }

    fn masternode_list_info_for_height(&self, work_block_height: u32, cached_lists: &BTreeMap<UInt256, models::MasternodeList>, cached_snapshots: &BTreeMap<UInt256, models::LLMQSnapshot>, unknown_lists: &mut Vec<UInt256>) -> Result<(models::MasternodeList, models::LLMQSnapshot, UInt256), CoreProviderError> {
        self.lookup_block_hash_by_height(work_block_height)
            .map_err(|err| panic!("MISSING: block for height: {}: error: {}", work_block_height, err))
            .and_then(|work_block_hash| self.find_masternode_list(work_block_hash, cached_lists, unknown_lists)
                .and_then(|masternode_list| self.find_snapshot(work_block_hash, cached_snapshots)
                    .map(|snapshot| (masternode_list, snapshot, work_block_hash))))
        // .ok_or(CoreProviderError::NullResult)
    }

    fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Result<UInt256, CoreProviderError>;
    fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<models::MasternodeList, CoreProviderError>;
    fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<models::LLMQSnapshot, CoreProviderError>;
    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<UInt256, CoreProviderError>;
    fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32;

    fn add_insight(&self, block_hash: UInt256);
    fn should_process_diff_with_range(&self, base_block_hash: UInt256, block_hash: UInt256) -> Result<(), ProcessingError>;

    fn save_snapshot(&self, block_hash: UInt256, snapshot: models::LLMQSnapshot) -> bool;
    fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &models::MasternodeList) -> bool;
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
