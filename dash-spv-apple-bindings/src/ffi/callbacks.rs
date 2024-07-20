use std::ffi::c_void;
use dash_spv_masternode_processor::processing::processing_error::ProcessingError;
use crate::types;

// #[ferment_macro::export]
// pub type AddInsightCallback = fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext);
//
// #[ferment_macro::export]
// pub type ShouldProcessDiffWithRangeCallback = fn(base_block_hash: UInt256, block_hash: UInt256, context: ferment_interfaces::OpaqueContext) -> ProcessingError;
//
// #[ferment_macro::export]
// pub type GetBlockHeightByHashCallback = fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext) -> u32;
//
// #[ferment_macro::export]
// pub type GetBlockHashByHeightCallback = fn(block_height: u32, context: ferment_interfaces::OpaqueContext) -> UInt256;
//
// #[ferment_macro::export]
// pub type GetMerkleRootCallback = fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext) -> UInt256;
//
// #[ferment_macro::export]
// pub type GetMasternodeListCallback = fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext) -> MasternodeList;
//
// #[ferment_macro::export]
// pub type DestroyMasternodeListCallback = fn(masternode_list: MasternodeList);
//
// #[ferment_macro::export]
// pub type SaveMasternodeListCallback = fn(block_hash: UInt256, masternode_list: MasternodeList, context: ferment_interfaces::OpaqueContext) -> bool;
//
// #[ferment_macro::export]
// pub type GetLLMQSnapshotByBlockHashCallback = fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext) -> LLMQSnapshot;
//
// #[ferment_macro::export]
// pub type GetCLSignatureByBlockHashCallback = fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext) -> UInt768;
//
// #[ferment_macro::export]
// pub type SaveLLMQSnapshotCallback = fn(block_hash: UInt256, snapshot: LLMQSnapshot, context: ferment_interfaces::OpaqueContext) -> bool;
//
// #[ferment_macro::export]
// pub type SaveCLSignatureCallback = fn(block_hash: UInt256, cl_signature: UInt768, context: ferment_interfaces::OpaqueContext) -> bool;
//
// #[ferment_macro::export]
// pub type DestroyHashCallback = fn(hash: UInt256);
//
// #[ferment_macro::export]
// pub type DestroyLLMQSnapshotCallback = fn(snapshot: LLMQSnapshot);


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
