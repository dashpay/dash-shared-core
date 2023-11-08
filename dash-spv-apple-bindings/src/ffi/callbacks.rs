use std::ffi::c_void;
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::models::masternode_list::MasternodeList;
use dash_spv_masternode_processor::models::snapshot::LLMQSnapshot;
use dash_spv_masternode_processor::processing::processing_error::ProcessingError;
use crate::types;

#[ferment_macro::export]
pub type AddInsightCallback =
    fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext);

#[ferment_macro::export]
pub type ShouldProcessDiffWithRangeCallback =
    fn(base_block_hash: UInt256, block_hash: UInt256, context: ferment_interfaces::OpaqueContext)
        -> ProcessingError;

#[ferment_macro::export]
pub type GetBlockHeightByHashCallback =
    fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext)
        -> u32;

#[ferment_macro::export]
pub type GetBlockHashByHeightCallback =
    fn(block_height: u32, context: ferment_interfaces::OpaqueContext)
       -> UInt256;

#[ferment_macro::export]
pub type GetMerkleRootCallback =
    fn(block_hash: UInt256, context: ferment_interfaces::OpaqueContext)
       -> UInt256;

#[ferment_macro::export]
pub type GetMasternodeListCallback = fn(
    block_hash: UInt256,
    context: ferment_interfaces::OpaqueContext
) -> MasternodeList;

#[ferment_macro::export]
pub type DestroyMasternodeListCallback = fn(
    masternode_list: MasternodeList
);

#[ferment_macro::export]
pub type SaveMasternodeListCallback = fn(
    block_hash: UInt256,
    masternode_list: MasternodeList,
    context: ferment_interfaces::OpaqueContext
) -> bool;

#[ferment_macro::export]
pub type GetLLMQSnapshotByBlockHashCallback = fn(
    block_hash: UInt256,
    context: ferment_interfaces::OpaqueContext
) -> LLMQSnapshot;

#[ferment_macro::export]
pub type SaveLLMQSnapshotCallback = fn(
    block_hash: UInt256,
    snapshot: LLMQSnapshot,
    context: ferment_interfaces::OpaqueContext
) -> bool;

#[ferment_macro::export]
pub type DestroyHashCallback = fn(hash: UInt256);

#[ferment_macro::export]
pub type DestroyLLMQSnapshotCallback = fn(snapshot: LLMQSnapshot);


pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
pub type ShouldProcessDiffWithRange = unsafe extern "C" fn(base_block_hash: *mut [u8; 32], block_hash: *mut [u8; 32], context: *const c_void) -> ProcessingError;
pub type GetBlockHeightByHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
pub type MerkleRootLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut u8; // UIn256
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut types::MasternodeList;
pub type MasternodeListDestroy = unsafe extern "C" fn(masternode_list: *mut types::MasternodeList);
pub type MasternodeListSave = unsafe extern "C" fn(block_hash: *mut [u8; 32], masternode_list: *mut types::MasternodeList, context: *const c_void) -> bool;
pub type GetBlockHashByHeight = unsafe extern "C" fn(block_height: u32, context: *const c_void) -> *mut u8; // UIn256
pub type GetLLMQSnapshotByBlockHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut types::LLMQSnapshot;
pub type SaveLLMQSnapshot = unsafe extern "C" fn(block_hash: *mut [u8; 32], snapshot: *mut types::LLMQSnapshot, context: *const c_void) -> bool;
pub type HashDestroy = unsafe extern "C" fn(hash: *mut u8);
pub type LLMQSnapshotDestroy = unsafe extern "C" fn(snapshot: *mut types::LLMQSnapshot);
