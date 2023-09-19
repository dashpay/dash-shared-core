extern crate libc;
use std::ffi::c_void;
use crate::crypto::UInt256;
use crate::types;
use crate::processing::ProcessingError;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type AddInsightCallback =
    fn(block_hash: UInt256, context: rs_ffi_interfaces::OpaqueContext);

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type ShouldProcessDiffWithRangeCallback =
    fn(base_block_hash: UInt256, block_hash: UInt256, context: rs_ffi_interfaces::OpaqueContext)
        -> crate::processing::processing_error::ProcessingError;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type GetBlockHeightByHashCallback =
    fn(block_hash: UInt256, context: rs_ffi_interfaces::OpaqueContext)
        -> u32;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type GetBlockHashByHeightCallback =
    fn(block_height: u32, context: rs_ffi_interfaces::OpaqueContext)
       -> UInt256;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type GetMerkleRootCallback =
    fn(block_hash: UInt256, context: rs_ffi_interfaces::OpaqueContext)
       -> UInt256;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type GetMasternodeListCallback =
    fn(block_hash: UInt256, context: rs_ffi_interfaces::OpaqueContext)
       -> crate::models::masternode_list::MasternodeList;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type DestroyMasternodeListCallback =
    fn(masternode_list: crate::models::masternode_list::MasternodeList);

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type SaveMasternodeListCallback =
    fn(block_hash: UInt256, masternode_list: crate::models::masternode_list::MasternodeList, context: rs_ffi_interfaces::OpaqueContext)
        -> bool;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type GetLLMQSnapshotByBlockHashCallback =
    fn(block_hash: UInt256, context: rs_ffi_interfaces::OpaqueContext)
        -> crate::models::snapshot::LLMQSnapshot;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type SaveLLMQSnapshotCallback =
    fn(block_hash: UInt256, snapshot: crate::models::snapshot::LLMQSnapshot, context: rs_ffi_interfaces::OpaqueContext)
       -> bool;

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type DestroyHashCallback = fn(hash: UInt256);

#[rs_ffi_macro_derive::impl_ffi_ty_conv]
pub type DestroyLLMQSnapshotCallback = fn(snapshot: crate::models::snapshot::LLMQSnapshot);


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
