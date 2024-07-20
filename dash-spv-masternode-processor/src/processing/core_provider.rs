use std::collections::BTreeMap;
use crate::chain::common::{ChainType, IHaveChainSettings};
use crate::crypto::byte_util::{UInt256, UInt768, Zeroable};
use crate::models::{snapshot::LLMQSnapshot, masternode_list::MasternodeList};
use crate::processing::ProcessingError;

#[ferment_macro::opaque]
pub trait CoreProvider: std::fmt::Debug {
    fn chain_type(&self) -> ChainType;
    fn find_masternode_list(&self, block_hash: UInt256, cached_mn_lists: &BTreeMap<UInt256, MasternodeList>, unknown_mn_lists: &mut Vec<UInt256>) -> Result<MasternodeList, CoreProviderError> {
        let genesis_hash = self.chain_type().genesis_hash();
        if block_hash.is_zero() {
            // If it's a zero block we don't expect models list here
            // println!("find {}: {} EMPTY BLOCK HASH -> None", self.lookup_block_height_by_hash(block_hash), block_hash);
            Err(CoreProviderError::BadBlockHash(block_hash))
        } else if block_hash.eq(&genesis_hash) {
            // If it's a genesis block we don't expect models list here
            // println!("find {}: {} It's a genesis -> Ok(EMPTY MNL)", self.lookup_block_height_by_hash(block_hash), block_hash);
            Ok(MasternodeList::empty(block_hash, self.lookup_block_height_by_hash(block_hash), false))
            // None
        } else if let Some(cached) = cached_mn_lists.get(&block_hash) {
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
                unknown_mn_lists.push(block_hash);
            } else if !self.chain_type().is_mainnet() {
                self.add_insight(block_hash);
                if self.lookup_block_height_by_hash(block_hash) != u32::MAX {
                    unknown_mn_lists.push(block_hash);
                }
            }
            Err(CoreProviderError::NoMasternodeList)
        }
    }

    fn find_cl_signature(
        &self,
        block_hash: UInt256,
        cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
    ) -> Result<UInt768, CoreProviderError> {
        if let Some(cached) = cached_cl_signatures.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            Ok(cached.clone())
        } else {
            self.lookup_cl_signature_by_block_hash(block_hash)
        }
    }

    fn find_snapshot(&self, block_hash: UInt256, cached_llmq_snapshots: &BTreeMap<UInt256, LLMQSnapshot>) -> Result<LLMQSnapshot, CoreProviderError> {
        if let Some(cached) = cached_llmq_snapshots.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            Ok(cached.clone())
        } else {
            self.lookup_snapshot_by_block_hash(block_hash)
        }
    }

    fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Result<UInt256, CoreProviderError>;
    fn lookup_masternode_list(&self, block_hash: UInt256) -> Result<MasternodeList, CoreProviderError>;
    fn lookup_cl_signature_by_block_hash(&self, block_hash: UInt256) -> Result<UInt768, CoreProviderError>;
    fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<LLMQSnapshot, CoreProviderError>;
    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<UInt256, CoreProviderError>;
    fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32;

    fn add_insight(&self, block_hash: UInt256);
    fn should_process_diff_with_range(&self, base_block_hash: UInt256, block_hash: UInt256) -> Result<u8, ProcessingError>;

    fn save_snapshot(&self, block_hash: UInt256, snapshot: LLMQSnapshot) -> bool;
    fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &MasternodeList) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[ferment_macro::export]
pub enum CoreProviderError {
    NullResult,
    ByteError(byte::Error),
    BadBlockHash(UInt256),
    BlockHashNotFoundAt(u32),
    NoMasternodeList,
}
impl std::fmt::Display for CoreProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            CoreProviderError::NullResult => "CoreProviderError::NullResult".to_string(),
            CoreProviderError::ByteError(err) => format!("CoreProviderError::ByteError({err:?})"),
            CoreProviderError::BadBlockHash(h) => format!("CoreProviderError::BadBlockHash({h})"),
            CoreProviderError::BlockHashNotFoundAt(h) => format!("CoreProviderError::BlockHashNotFound({h})"),
            CoreProviderError::NoMasternodeList => "CoreProviderError::NoMasternodeList".to_string(),
        })
    }
}

impl std::error::Error for CoreProviderError {}

impl From<byte::Error> for CoreProviderError {
    fn from(value: byte::Error) -> Self {
        CoreProviderError::ByteError(value)
    }
}


#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(byte::Error)]
pub enum byte_Error_FFI {
    Incomplete,
    BadOffset(usize),
    BadInput { err: *mut std::os::raw::c_char },
}

impl ferment_interfaces::FFIConversion<byte::Error> for byte_Error_FFI {
    unsafe fn ffi_from_const(ffi: *const byte_Error_FFI) -> byte::Error {
        let ffi_ref = &*ffi;
        match ffi_ref {
            byte_Error_FFI::Incomplete =>
                byte::Error::Incomplete,
            byte_Error_FFI::BadOffset(o_0) => byte::Error::BadOffset(*o_0),
            byte_Error_FFI::BadInput { err} =>
                byte::Error::BadInput { err: ferment_interfaces::FFIConversion::ffi_from_const(*err) },
        }
    }
    unsafe fn ffi_to_const(obj: byte::Error) -> *const byte_Error_FFI {
        ferment_interfaces::boxed(match obj {
            byte::Error::Incomplete => byte_Error_FFI::Incomplete,
            byte::Error::BadOffset(o_0) => byte_Error_FFI::BadOffset(o_0),
            byte::Error::BadInput { err } => byte_Error_FFI::BadInput { err: ferment_interfaces::FFIConversion::ffi_to(err) },
        })
    }
    unsafe fn destroy(ffi: *mut byte_Error_FFI) {
        ferment_interfaces::unbox_any(ffi);
    }
}
impl Drop for byte_Error_FFI {
    fn drop(&mut self) {
        unsafe {
            match self {
                byte_Error_FFI::BadInput { err } =>
                    <std::os::raw::c_char as ferment_interfaces::FFIConversion<&str>>::destroy(*err),
                _ => {},
            }
        }
    }
}