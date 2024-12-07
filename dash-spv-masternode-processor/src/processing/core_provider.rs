use std::collections::BTreeMap;
use std::sync::Arc;
use hashes::hex::ToHex;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings};
use dash_spv_crypto::crypto::byte_util::Zeroable;
use crate::common::Block;
use crate::models::masternode_list::MasternodeList;
use crate::models::masternode_entry::MasternodeEntry;
use crate::models::snapshot::LLMQSnapshot;
use crate::processing::MasternodeProcessorCache;

#[ferment_macro::opaque]
pub trait CoreProvider: std::fmt::Debug {
    fn chain_type(&self) -> ChainType;
    fn find_masternode_list(&self, block_hash: [u8; 32], cache: &Arc<MasternodeProcessorCache>) -> Result<Arc<MasternodeList>, CoreProviderError> {
        let genesis_hash = self.chain_type().genesis_hash();
        if block_hash.is_zero() {
            // If it's a zero block we don't expect models list here
            // println!("find {}: {} EMPTY BLOCK HASH -> None", self.lookup_block_height_by_hash(block_hash), block_hash);
            return Err(CoreProviderError::BadBlockHash(block_hash))
        }
        if block_hash.eq(&genesis_hash) {
            // If it's a genesis block we don't expect models list here
            // println!("find {}: {} It's a genesis -> Ok(EMPTY MNL)", self.lookup_block_height_by_hash(block_hash), block_hash);
            return Ok(Arc::new(MasternodeList::empty(block_hash, self.lookup_block_height_by_hash(block_hash), false)))
        }
        let mn_lists_lock = cache.mn_lists.read().unwrap();
        let maybe_cached_list = mn_lists_lock.get(&block_hash).cloned();
        drop(mn_lists_lock);
        // Getting it from local cache stored as opaque in FFI context
        if let Some(cached) = maybe_cached_list {
            return Ok(cached)
        }
        // Getting it from FFI directly
        // if let Ok(looked) = self.lookup_masternode_list(block_hash) {
        //     return Ok(looked)
        // }
        // println!("find {}: {} Unknown -> Err", self.lookup_block_height_by_hash(block_hash), block_hash);
        if self.lookup_block_height_by_hash(block_hash) != u32::MAX {
            // let mut needed_masternode_lists_lock = cache.needed_masternode_lists.write().unwrap();
            // needed_masternode_lists_lock.push(block_hash);
            // drop(needed_masternode_lists_lock);
            return Err(CoreProviderError::MissedMasternodeListAt(block_hash))
        } else if !self.chain_type().is_mainnet() {
            self.add_insight(block_hash);
            if self.lookup_block_height_by_hash(block_hash) != u32::MAX {
                return Err(CoreProviderError::MissedMasternodeListAt(block_hash))
                // let mut needed_masternode_lists_lock = cache.needed_masternode_lists.write().unwrap();
                // needed_masternode_lists_lock.push(block_hash);
                // drop(needed_masternode_lists_lock);
            }
        }
        Err(CoreProviderError::NoMasternodeList)
    }

    // fn find_cl_signature(
    //     &self,
    //     block_hash: UInt256,
    //     cache: &Arc<MasternodeProcessorCache>
    //     // cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
    // ) -> Result<UInt768, CoreProviderError> {
    //     let lock = cache.cl_signatures.read().unwrap();
    //     let maybe_list = lock.get(&block_hash).cloned();
    //     drop(lock);
    //     if let Some(cached) = maybe_list {
    //         Ok(cached)
    //     } else {
    //         self.lookup_cl_signature_by_block_hash(block_hash)
    //     }
    // }
    //
    // fn find_snapshot(&self, block_hash: UInt256, cache: &Arc<MasternodeProcessorCache>) -> Result<LLMQSnapshot, CoreProviderError> {
    //     let lock = cache.llmq_snapshots.read().unwrap();
    //     let maybe_snapshot = lock.get(&block_hash).cloned();
    //     drop(lock);
    //     if let Some(cached) = maybe_snapshot {
    //         // Getting it from local cache stored as opaque in FFI context
    //         Ok(cached)
    //     } else {
    //         self.lookup_snapshot_by_block_hash(block_hash)
    //     }
    // }

    fn lookup_merkle_root_by_hash(&self, block_hash: [u8; 32]) -> Result<[u8; 32], CoreProviderError>;
    // fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<MasternodeList, CoreProviderError>;
    // fn lookup_cl_signature_by_block_hash(&self, block_hash: UInt256) -> Result<UInt768, CoreProviderError>;
    // fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<LLMQSnapshot, CoreProviderError>;
    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<[u8; 32], CoreProviderError>;
    fn lookup_block_height_by_hash(&self, block_hash: [u8; 32]) -> u32;
    fn lookup_block_by_height_or_last_terminal(&self, block_height: u32) -> Result<Block, CoreProviderError>;
    fn add_insight(&self, block_hash: [u8; 32]);
    // fn should_process_diff_with_range(&self, is_dip24: bool, base_block_hash: [u8; 32], block_hash: [u8; 32]) -> Result<u8, ProcessingError>;
    fn remove_request_in_retrieval(&self, is_dip24: bool, base_block_hash: [u8; 32], block_hash: [u8; 32]) -> bool;
    fn remove_from_retrieval_queue(&self, is_dip24: bool, block_hash: [u8; 32]);
    fn first_in_retrieval_queue(&self, is_dip24: bool) -> Option<[u8; 32]>;

    fn persist_in_retrieval_queue(&self, block_hash: [u8; 32], is_dip24: bool) -> bool;
    fn load_masternode_list_from_db(&self, block_hash: [u8; 32]) -> Result<Arc<MasternodeList>, CoreProviderError>;
    fn save_masternode_list_into_db(&self, masternode_list: Arc<MasternodeList>, modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry>) -> Result<bool, CoreProviderError>;
    fn load_llmq_snapshot_from_db(&self, block_hash: [u8; 32]) -> Result<LLMQSnapshot, CoreProviderError>;
    fn save_llmq_snapshot_into_db(&self, block_hash: [u8; 32], masternode_list: LLMQSnapshot) -> Result<bool, CoreProviderError>;
    fn update_address_usage_of_masternodes(&self, masternodes: Vec<MasternodeEntry>);
    fn issue_with_masternode_list_from_peer(&self, is_dip24: bool, peer: *const std::os::raw::c_void);
    // fn masternode_list_updated(&self, list: MasternodeList);

    // fn first_in_qr_info_queue(&self) -> Option<[u8; 32]>;
    // fn save_snapshot(&self, block_hash: UInt256, snapshot: LLMQSnapshot) -> bool;
    // fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &MasternodeList) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[ferment_macro::export]
pub enum CoreProviderError {
    NullResult,
    ByteError(byte::Error),
    BadBlockHash([u8; 32]),
    BlockHashNotFoundAt(u32),
    NoMasternodeList,
    NoSnapshot,
    HexError(hashes::hex::Error),
    MissedMasternodeListAt([u8; 32]),
    MissedMasternodeListsAt(Vec<[u8; 32]>),
}
impl std::fmt::Display for CoreProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            CoreProviderError::NullResult => "CoreProviderError::NullResult".to_string(),
            CoreProviderError::ByteError(err) => format!("CoreProviderError::ByteError({err:?})"),
            CoreProviderError::BadBlockHash(h) => format!("CoreProviderError::BadBlockHash({})", h.to_hex()),
            CoreProviderError::BlockHashNotFoundAt(h) => format!("CoreProviderError::BlockHashNotFound({h})"),
            CoreProviderError::NoMasternodeList => "CoreProviderError::NoMasternodeList".to_string(),
            CoreProviderError::HexError(err) => "CoreProviderError::HexError".to_string(),
            CoreProviderError::NoSnapshot => "CoreProviderError::NoSnapshot".to_string(),
            CoreProviderError::MissedMasternodeListAt(block_hash) => format!("CoreProviderError::MissedMasternodeListAt({})", block_hash.to_hex()),
            CoreProviderError::MissedMasternodeListsAt(block_hashes) => format!("CoreProviderError::MissedMasternodeListsAt({})", block_hashes.len()),
        })
    }
}

impl std::error::Error for CoreProviderError {}

impl From<byte::Error> for CoreProviderError {
    fn from(value: byte::Error) -> Self {
        CoreProviderError::ByteError(value)
    }
}


