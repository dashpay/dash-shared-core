extern crate libc;
use std::ffi::c_void;
use crate::{models, types};
use crate::crypto::{byte_util::MutDecodable, UInt256};
use crate::ffi::from::FromFFI;
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



pub type AddInsightBlockingLookup =
    unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
pub type ShouldProcessDiffWithRange = unsafe extern "C" fn(
    base_block_hash: *mut [u8; 32],
    block_hash: *mut [u8; 32],
    context: *const c_void,
) -> ProcessingError;

pub type GetBlockHeightByHash =
    unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
pub type MerkleRootLookup =
    unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut u8; // UIn256
pub type MasternodeListLookup = unsafe extern "C" fn(
    block_hash: *mut [u8; 32],
    context: *const c_void,
) -> *mut types::MasternodeList;
pub type MasternodeListDestroy = unsafe extern "C" fn(masternode_list: *mut types::MasternodeList);
pub type MasternodeListSave = unsafe extern "C" fn(
    block_hash: *mut [u8; 32],
    masternode_list: *mut types::MasternodeList,
    context: *const c_void,
) -> bool;

pub type GetBlockHashByHeight =
    unsafe extern "C" fn(block_height: u32, context: *const c_void) -> *mut u8; // UIn256
pub type GetLLMQSnapshotByBlockHash = unsafe extern "C" fn(
    block_hash: *mut [u8; 32],
    context: *const c_void,
) -> *mut types::LLMQSnapshot;
pub type SaveLLMQSnapshot = unsafe extern "C" fn(
    block_hash: *mut [u8; 32],
    snapshot: *mut types::LLMQSnapshot,
    context: *const c_void,
) -> bool;
pub type HashDestroy = unsafe extern "C" fn(hash: *mut u8);
pub type LLMQSnapshotDestroy = unsafe extern "C" fn(snapshot: *mut types::LLMQSnapshot);


fn lookup<P, L, D, R, FR, FROM>(params: P, lookup_callback: L, destroy_callback: D, from_conversion: FROM) -> Option<R> where
    FROM: Fn(*mut FR) -> Option<R>,
    L: Fn(P) -> *mut FR + Copy,
    D: Fn(*mut FR) {
    let result = lookup_callback(params);
    if !result.is_null() {
        let data = from_conversion(result);
        destroy_callback(result);
        if data.is_some() {
            data
        } else {
            None
        }
        // Some(data)
    } else {
        None
    }
}

pub fn lookup_masternode_list<MNL, MND>(
    block_hash: UInt256,
    masternode_list_lookup: MNL,
    masternode_list_destroy: MND,
) -> Option<models::MasternodeList>
where
    MNL: Fn(UInt256) -> *mut types::MasternodeList + Copy,
    MND: Fn(*mut types::MasternodeList),
{
    lookup(block_hash, masternode_list_lookup, masternode_list_destroy, |result| Some(unsafe { (*result).decode() }))
    // let lookup_result = masternode_list_lookup(block_hash);
    // if !lookup_result.is_null() {
    //     let data = unsafe { (*lookup_result).decode() };
    //     masternode_list_destroy(lookup_result);
    //     Some(data)
    // } else {
    //     None
    // }
}

pub fn lookup_block_hash_by_height<BL, DH>(
    block_height: u32,
    lookup_hash: BL,
    destroy_hash: DH,
) -> Option<UInt256>
where
    BL: Fn(u32) -> *mut u8 + Copy,
    DH: Fn(*mut u8),
{
    lookup(block_height, lookup_hash, destroy_hash, |result| { UInt256::from_mut(result) } )

    // let lookup_result = lookup(block_height);
    // if !lookup_result.is_null() {
    //     let hash = UInt256::from_mut(lookup_result);
    //     destroy_hash(lookup_result);
    //     hash
    // } else {
    //     None
    // }
}

pub fn lookup_merkle_root_by_hash<MRL, DH>(
    block_hash: UInt256,
    lookup_hash: MRL,
    destroy_hash: DH,
) -> Option<UInt256>
where
    MRL: Fn(UInt256) -> *mut u8 + Copy,
    DH: Fn(*mut u8),
{
    lookup(block_hash, lookup_hash, destroy_hash, UInt256::from_mut)

    // let lookup_result = lookup(block_hash);
    // if !lookup_result.is_null() {
    //     let hash = UInt256::from_mut(lookup_result);
    //     destroy_hash(lookup_result);
    //     hash
    // } else {
    //     None
    // }

}

pub fn lookup_snapshot_by_block_hash<SL, SD>(
    block_hash: UInt256,
    snapshot_lookup: SL,
    snapshot_destroy: SD,
) -> Option<models::LLMQSnapshot>
where
    SL: Fn(UInt256) -> *mut types::LLMQSnapshot + Copy,
    SD: Fn(*mut types::LLMQSnapshot),
{
    let lookup_result = snapshot_lookup(block_hash);
    if !lookup_result.is_null() {
        let data = unsafe { (*lookup_result).decode() };
        snapshot_destroy(lookup_result);
        Some(data)
    } else {
        None
    }
}
