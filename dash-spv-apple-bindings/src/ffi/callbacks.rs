use std::ffi::c_void;
use dash_spv_masternode_processor::processing::processing_error::ProcessingError;
use crate::types;

#[ferment_macro::opaque]
pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
#[ferment_macro::opaque]
pub type ShouldProcessDiffWithRange = unsafe extern "C" fn(base_block_hash: *mut [u8; 32], block_hash: *mut [u8; 32], context: *const c_void) -> ProcessingError;
#[ferment_macro::opaque]
pub type GetBlockHeightByHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
#[ferment_macro::opaque]
pub type MerkleRootLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut u8; // UIn256
#[ferment_macro::opaque]
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut types::MasternodeList;
#[ferment_macro::opaque]
pub type MasternodeListDestroy = unsafe extern "C" fn(masternode_list: *mut types::MasternodeList);
#[ferment_macro::opaque]
pub type MasternodeListSave = unsafe extern "C" fn(block_hash: *mut [u8; 32], masternode_list: *mut types::MasternodeList, context: *const c_void) -> bool;
#[ferment_macro::opaque]
pub type GetBlockHashByHeight = unsafe extern "C" fn(block_height: u32, context: *const c_void) -> *mut u8; // UIn256
#[ferment_macro::opaque]
pub type GetLLMQSnapshotByBlockHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut types::LLMQSnapshot;
#[ferment_macro::opaque]
pub type GetCLSignatureByBlockHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut u8;
#[ferment_macro::opaque]
pub type SaveLLMQSnapshot = unsafe extern "C" fn(block_hash: *mut [u8; 32], snapshot: *mut types::LLMQSnapshot, context: *const c_void) -> bool;
#[ferment_macro::opaque]
pub type SaveCLSignature = unsafe extern "C" fn(block_hash: *mut [u8; 32], cl_signature: *mut [u8; 96], context: *const c_void) -> bool;
#[ferment_macro::opaque]
pub type HashDestroy = unsafe extern "C" fn(hash: *mut u8);
#[ferment_macro::opaque]
pub type LLMQSnapshotDestroy = unsafe extern "C" fn(snapshot: *mut types::LLMQSnapshot);
