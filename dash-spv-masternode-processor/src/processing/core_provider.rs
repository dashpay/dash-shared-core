use std::collections::BTreeMap;
use crate::chain::common::{ChainType, IHaveChainSettings};
use crate::crypto::byte_util::Zeroable;
use crate::crypto::{UInt256, UInt768};
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
    fn lookup_cl_signature_by_block_hash(&self, block_hash: UInt256) -> Result<UInt768, CoreProviderError>;
    fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Result<models::LLMQSnapshot, CoreProviderError>;
    fn lookup_block_hash_by_height(&self, block_height: u32) -> Result<UInt256, CoreProviderError>;
    fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32;

    fn add_insight(&self, block_hash: UInt256);
    fn should_process_diff_with_range(&self, base_block_hash: UInt256, block_hash: UInt256) -> Result<(), ProcessingError>;

    fn save_snapshot(&self, block_hash: UInt256, snapshot: models::LLMQSnapshot) -> bool;
    fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &models::MasternodeList) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// #[ferment_macro::export]
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


#[allow(non_camel_case_types)]
#[derive(Clone)]
pub enum byte_Error_FFI {
    Incomplete,
    BadOffset(usize),
    BadInput { err: *mut std::os::raw::c_char },
}

#[allow(non_camel_case_types)]
#[derive(Clone)]
pub enum CoreProviderError_FFI {
    NullResult,
    ByteError(*mut byte_Error_FFI),
    BadBlockHash(*mut [u8; 32]),
    NoMasternodeList,
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

impl ferment_interfaces::FFIConversion<CoreProviderError> for CoreProviderError_FFI {
    unsafe fn ffi_from_const(ffi: *const CoreProviderError_FFI) -> CoreProviderError {
        let ffi_ref = &*ffi;
        match ffi_ref {
            CoreProviderError_FFI::NullResult =>
                CoreProviderError::NullResult,
            CoreProviderError_FFI::ByteError(o_0) =>
                CoreProviderError::ByteError(ferment_interfaces::FFIConversion::ffi_from_const(*o_0)),
            CoreProviderError_FFI::BadBlockHash(o_0) =>
                CoreProviderError::BadBlockHash(ferment_interfaces::FFIConversion::ffi_from_const(*o_0)),
            CoreProviderError_FFI::NoMasternodeList =>
                CoreProviderError::NoMasternodeList,
        }
    }
    unsafe fn ffi_to_const(obj: CoreProviderError) -> *const CoreProviderError_FFI {
        ferment_interfaces::boxed(match obj {
            CoreProviderError::NullResult => CoreProviderError_FFI::NullResult,
            CoreProviderError::ByteError(o_0) => CoreProviderError_FFI::ByteError(ferment_interfaces::FFIConversion::ffi_to(o_0)),
            CoreProviderError::BadBlockHash(o_0) => CoreProviderError_FFI::BadBlockHash(ferment_interfaces::FFIConversion::ffi_to(o_0)),
            CoreProviderError::NoMasternodeList => CoreProviderError_FFI::NoMasternodeList,
        })
    }
    unsafe fn destroy(ffi: *mut CoreProviderError_FFI) {
        ferment_interfaces::unbox_any(ffi);
    }
}
impl Drop for CoreProviderError_FFI {
    fn drop(&mut self) {
        unsafe {
            match self {
                CoreProviderError_FFI::ByteError(o_0) =>
                    <byte_Error_FFI as ferment_interfaces::FFIConversion<byte::Error>>::destroy(o_0.to_owned()),
                CoreProviderError_FFI::BadBlockHash(o_0) =>
                    <[u8; 32] as ferment_interfaces::FFIConversion<UInt256>>::destroy(o_0.to_owned()),
                _ => {},
            }
        }
    }
}