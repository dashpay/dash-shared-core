
use std::sync::Arc;

use ferment::{boxed, destroy_opt_primitive, unbox_any};
use tokio::runtime::Runtime;
use dash_spv_coinjoin::coinjoin_client_manager::CoinJoinClientManager;
use dash_spv_masternode_processor::processing::MasternodeProcessor;
use dash_spv_platform::contract::manager::ContractsManager;
use dash_spv_platform::document::contact_request::ContactRequestManager;
use dash_spv_platform::document::manager::DocumentsManager;
use dash_spv_platform::document::salted_domain_hashes::SaltedDomainHashesManager;
use dash_spv_platform::document::usernames::UsernamesManager;
use dash_spv_platform::identity::manager::IdentitiesManager;
use dash_spv_platform::PlatformSDK;
use crate::custom::dashcore::{dashcore_hash_types_BlockHash, dashcore_hash_types_ConfirmedHash, dashcore_hash_types_ConfirmedHashHashedWithProRegTx, dashcore_hash_types_CycleHash, dashcore_hash_types_InputsHash, dashcore_hash_types_MerkleRootMasternodeList, dashcore_hash_types_MerkleRootQuorums, dashcore_hash_types_ProTxHash, dashcore_hash_types_PubkeyHash, dashcore_hash_types_QuorumCommitmentHash, dashcore_hash_types_QuorumEntryHash, dashcore_hash_types_QuorumHash, dashcore_hash_types_QuorumSigningRequestId, dashcore_hash_types_QuorumVVecHash, dashcore_hash_types_ScriptHash, dashcore_hash_types_Sha256dHash, dashcore_hash_types_SpecialTransactionPayloadHash, dashcore_hash_types_TxMerkleNode, dashcore_hash_types_Txid};
use crate::custom::{to_ffi_bytes, to_ffi_hash};
use crate::custom::std::SocketAddr;
use crate::DashSPVCore;
use crate::fermented::generics::{Arr_u8_20, Arr_u8_32};

# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_runtime(self_: *mut DashSPVCore) -> *const Runtime {
    let arc = &(&*self_).platform.runtime;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_masternode_processor(self_: *mut DashSPVCore) -> *const MasternodeProcessor {
    let arc = &(&*self_).processor;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_platform(self_: *mut DashSPVCore) -> *const PlatformSDK {
    let arc = &(&*self_).platform;
    Arc::into_raw(Arc::clone(arc))
}

# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_identities_manager(self_: *mut DashSPVCore) -> *const IdentitiesManager {
    let arc = &(&*self_).platform.identity_manager;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_contract_manager(self_: *mut DashSPVCore) -> *const ContractsManager {
    let arc = &(&*self_).platform.contract_manager;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_contact_requests_manager(self_: *mut DashSPVCore) -> *const ContactRequestManager {
    let arc = &(&*self_).platform.contact_requests;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_salted_domain_hashes_manager(self_: *mut DashSPVCore) -> *const SaltedDomainHashesManager {
    let arc = &(&*self_).platform.salted_domain_hashes;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_usernames_manager(self_: *mut DashSPVCore) -> *const UsernamesManager {
    let arc = &(&*self_).platform.usernames;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn DashSPVCore_documents_manager(self_: *mut DashSPVCore) -> *const DocumentsManager {
    let arc = &(&*self_).platform.doc_manager;
    Arc::into_raw(Arc::clone(arc))
}
# [no_mangle]
pub unsafe extern "C" fn runtime_destroy(self_: *const Runtime) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn masternode_processor_destroy(self_: *const MasternodeProcessor) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn platform_destroy(self_: *const PlatformSDK) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn identities_manager_destroy(self_: *const IdentitiesManager) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn contracts_manager_destroy(self_: *const ContractsManager) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn contact_request_manager_destroy(self_: *const ContactRequestManager) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn salted_domain_hashes_manager_destroy(self_: *const SaltedDomainHashesManager) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn usernames_manager_destroy(self_: *const UsernamesManager) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn documents_manager_destroy(self_: *const DocumentsManager) {
    if !self_.is_null() {
        drop(Arc::from_raw(self_));
    }
}
# [no_mangle]
pub unsafe extern "C" fn SocketAddr_destroy(self_: *mut SocketAddr) {
    unbox_any(self_);
}
# [no_mangle]
pub unsafe extern "C" fn dash_spv_apple_bindings_DashSPVCore_destroy(self_: *mut DashSPVCore) {
    unbox_any(self_);
}
# [no_mangle]
pub unsafe extern "C" fn dash_spv_platform_identity_model_IdentityModel_destroy(self_: *mut dash_spv_platform::identity::model::IdentityModel) {
    unbox_any(self_);
}
# [no_mangle]
pub unsafe extern "C" fn dash_spv_platform_identity_callback_IdentityController_destroy(self_: *mut dash_spv_platform::identity::callback::IdentityController) {
    unbox_any(self_);
}
#[no_mangle]
pub unsafe extern "C" fn identity_controller_get_model(controller: *mut dash_spv_platform::identity::callback::IdentityController) -> *const dash_spv_platform::identity::model::IdentityModel {
    &(*controller).model as *const dash_spv_platform::identity::model::IdentityModel
}

#[no_mangle]
pub unsafe extern "C" fn identity_controller_get_model_mut(controller: *mut dash_spv_platform::identity::callback::IdentityController) -> *mut dash_spv_platform::identity::model::IdentityModel {
    &mut (*controller).model as *mut dash_spv_platform::identity::model::IdentityModel
}
# [no_mangle]
pub unsafe extern "C" fn dash_spv_coinjoin_coinjoin_client_manager_CoinJoinClientManager_destroy(self_: *mut CoinJoinClientManager) {
    unbox_any(self_);
}

#[no_mangle] pub unsafe extern "C" fn u64_ctor(self_: u64) -> *mut u64 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn u64_destroy(self_: *mut u64) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn i64_ctor(self_: i64) -> *mut i64 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn i64_destroy(self_: *mut i64) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn u32_ctor(self_: u32) -> *mut u32 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn u32_destroy(self_: *mut u32) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn i32_ctor(self_: i32) -> *mut i32 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn i32_destroy(self_: *mut i32) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn u16_ctor(self_: u16) -> *mut u16 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn u16_destroy(self_: *mut u16) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn i16_ctor(self_: i16) -> *mut i16 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn i16_destroy(self_: *mut i16) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn u8_ctor(self_: u8) -> *mut u8 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn u8_destroy(self_: *mut u8) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn i8_ctor(self_: i8) -> *mut i8 { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn i8_destroy(self_: *mut i8) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn usize_ctor(self_: usize) -> *mut usize { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn usize_destroy(self_: *mut usize) { destroy_opt_primitive(self_); }
#[no_mangle] pub unsafe extern "C" fn isize_ctor(self_: isize) -> *mut isize { boxed(self_) }
#[no_mangle] pub unsafe extern "C" fn isize_destroy(self_: *mut isize) { destroy_opt_primitive(self_); }

/// [u8; 32]
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_BlockHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_BlockHash {
    to_ffi_hash::<dashcore::hash_types::BlockHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_BlockHash_destroy(ptr: *mut dashcore_hash_types_BlockHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_BlockHash_inner(ptr: *mut dashcore_hash_types_BlockHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::BlockHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_CycleHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_CycleHash {
    to_ffi_hash::<dashcore::hash_types::CycleHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_CycleHash_destroy(ptr: *mut dashcore_hash_types_CycleHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_CycleHash_inner(ptr: *mut dashcore_hash_types_CycleHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::CycleHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Txid_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_Txid {
    to_ffi_hash::<dashcore::hash_types::Txid, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Txid_destroy(ptr: *mut dashcore_hash_types_Txid) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Txid_inner(ptr: *mut dashcore_hash_types_Txid) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::Txid, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_TxMerkleNode_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_TxMerkleNode {
    to_ffi_hash::<dashcore::hash_types::TxMerkleNode, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_TxMerkleNode_destroy(ptr: *mut dashcore_hash_types_TxMerkleNode) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_TxMerkleNode_inner(ptr: *mut dashcore_hash_types_TxMerkleNode) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::TxMerkleNode, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_SpecialTransactionPayloadHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_SpecialTransactionPayloadHash {
    to_ffi_hash::<dashcore::hash_types::SpecialTransactionPayloadHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_SpecialTransactionPayloadHash_destroy(ptr: *mut dashcore_hash_types_SpecialTransactionPayloadHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_SpecialTransactionPayloadHash_inner(ptr: *mut dashcore_hash_types_SpecialTransactionPayloadHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::SpecialTransactionPayloadHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_InputsHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_InputsHash {
    to_ffi_hash::<dashcore::hash_types::InputsHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_InputsHash_destroy(ptr: *mut dashcore_hash_types_InputsHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_InputsHash_inner(ptr: *mut dashcore_hash_types_InputsHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::InputsHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_QuorumHash {
    to_ffi_hash::<dashcore::hash_types::QuorumHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumHash_destroy(ptr: *mut dashcore_hash_types_QuorumHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumHash_inner(ptr: *mut dashcore_hash_types_QuorumHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::QuorumHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumVVecHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_QuorumVVecHash {
    to_ffi_hash::<dashcore::hash_types::QuorumVVecHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumVVecHash_destroy(ptr: *mut dashcore_hash_types_QuorumVVecHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumVVecHash_inner(ptr: *mut dashcore_hash_types_QuorumVVecHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::QuorumVVecHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumSigningRequestId_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_QuorumSigningRequestId {
    to_ffi_hash::<dashcore::hash_types::QuorumSigningRequestId, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumSigningRequestId_destroy(ptr: *mut dashcore_hash_types_QuorumSigningRequestId) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumSigningRequestId_inner(ptr: *mut dashcore_hash_types_QuorumSigningRequestId) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::QuorumSigningRequestId, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ProTxHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_ProTxHash {
    to_ffi_hash::<dashcore::hash_types::ProTxHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ProTxHash_destroy(ptr: *mut dashcore_hash_types_ProTxHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ProTxHash_inner(ptr: *mut dashcore_hash_types_ProTxHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::ProTxHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootMasternodeList_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_MerkleRootMasternodeList {
    to_ffi_hash::<dashcore::hash_types::MerkleRootMasternodeList, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootMasternodeList_destroy(ptr: *mut dashcore_hash_types_MerkleRootMasternodeList) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootMasternodeList_inner(ptr: *mut dashcore_hash_types_MerkleRootMasternodeList) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::MerkleRootMasternodeList, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootQuorums_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_MerkleRootQuorums {
    to_ffi_hash::<dashcore::hash_types::MerkleRootQuorums, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootQuorums_destroy(ptr: *mut dashcore_hash_types_MerkleRootQuorums) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootQuorums_inner(ptr: *mut dashcore_hash_types_MerkleRootQuorums) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::MerkleRootQuorums, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumEntryHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_QuorumEntryHash {
    to_ffi_hash::<dashcore::hash_types::QuorumEntryHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumEntryHash_destroy(ptr: *mut dashcore_hash_types_QuorumEntryHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumEntryHash_inner(ptr: *mut dashcore_hash_types_QuorumEntryHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::QuorumEntryHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHashHashedWithProRegTx_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_ConfirmedHashHashedWithProRegTx {
    to_ffi_hash::<dashcore::hash_types::ConfirmedHashHashedWithProRegTx, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHashHashedWithProRegTx_destroy(ptr: *mut dashcore_hash_types_ConfirmedHashHashedWithProRegTx) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHashHashedWithProRegTx_inner(ptr: *mut dashcore_hash_types_ConfirmedHashHashedWithProRegTx) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::ConfirmedHashHashedWithProRegTx, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_ConfirmedHash {
    to_ffi_hash::<dashcore::hash_types::ConfirmedHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHash_destroy(ptr: *mut dashcore_hash_types_ConfirmedHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHash_inner(ptr: *mut dashcore_hash_types_ConfirmedHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::ConfirmedHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumCommitmentHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_QuorumCommitmentHash {
    to_ffi_hash::<dashcore::hash_types::QuorumCommitmentHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumCommitmentHash_destroy(ptr: *mut dashcore_hash_types_QuorumCommitmentHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumCommitmentHash_inner(ptr: *mut dashcore_hash_types_QuorumCommitmentHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::QuorumCommitmentHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Sha256dHash_ctor(hash: *mut Arr_u8_32) -> *mut dashcore_hash_types_Sha256dHash {
    to_ffi_hash::<dashcore::hash_types::Sha256dHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Sha256dHash_destroy(ptr: *mut dashcore_hash_types_Sha256dHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Sha256dHash_inner(ptr: *mut dashcore_hash_types_Sha256dHash) -> *mut Arr_u8_32 {
    to_ffi_bytes::<dashcore::hash_types::Sha256dHash, _, _>(ptr)
}
/// [u8; 20]
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_PubkeyHash_ctor(hash: *mut Arr_u8_20) -> *mut dashcore_hash_types_PubkeyHash {
    to_ffi_hash::<dashcore::hash_types::PubkeyHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_PubkeyHash_destroy(ptr: *mut dashcore_hash_types_PubkeyHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_PubkeyHash_inner(ptr: *mut dashcore_hash_types_PubkeyHash) -> *mut Arr_u8_20 {
    to_ffi_bytes::<dashcore::hash_types::PubkeyHash, _, _>(ptr)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ScriptHash_ctor(hash: *mut Arr_u8_20) -> *mut dashcore_hash_types_ScriptHash {
    to_ffi_hash::<dashcore::hash_types::ScriptHash, _, _>(hash)
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ScriptHash_destroy(ptr: *mut dashcore_hash_types_ScriptHash) {
    unbox_any(ptr);
}
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ScriptHash_inner(ptr: *mut dashcore_hash_types_ScriptHash) -> *mut Arr_u8_20 {
    to_ffi_bytes::<dashcore::hash_types::ScriptHash, _, _>(ptr)
}

