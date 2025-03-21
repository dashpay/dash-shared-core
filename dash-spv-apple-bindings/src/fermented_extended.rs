use std::sync::Arc;
use ferment::unbox_any;
use tokio::runtime::Runtime;
use dash_spv_coinjoin::coinjoin_client_manager::CoinJoinClientManager;
use crate::custom::dashcore::{dashcore_hash_types_BlockHash, dashcore_hash_types_ConfirmedHash, dashcore_hash_types_ConfirmedHashHashedWithProRegTx, dashcore_hash_types_CycleHash, dashcore_hash_types_InputsHash, dashcore_hash_types_MerkleRootMasternodeList, dashcore_hash_types_MerkleRootQuorums, dashcore_hash_types_ProTxHash, dashcore_hash_types_PubkeyHash, dashcore_hash_types_QuorumCommitmentHash, dashcore_hash_types_QuorumEntryHash, dashcore_hash_types_QuorumHash, dashcore_hash_types_QuorumSigningRequestId, dashcore_hash_types_QuorumVVecHash, dashcore_hash_types_ScriptHash, dashcore_hash_types_Sha256dHash, dashcore_hash_types_SpecialTransactionPayloadHash, dashcore_hash_types_TxMerkleNode, dashcore_hash_types_Txid};
use crate::custom::{to_ffi_bytes, to_ffi_hash};
use crate::DashSPVCore;
use crate::fermented::generics::{Arr_u8_20, Arr_u8_32};


// //TODO: this is a tmp additional setup
//
#[repr(C)]
pub struct TokioRuntime(*const Runtime);
# [no_mangle]
pub unsafe extern "C" fn dash_spv_apple_bindings_DashSPVCore_tokio_runtime(self_: *mut DashSPVCore) -> *mut TokioRuntime {
    ferment::boxed(TokioRuntime(Arc::as_ptr(&(&*self_).platform.runtime)))
}
# [no_mangle]
pub unsafe extern "C" fn dash_spv_apple_bindings_DashSPVCore_runtime(self_: *mut DashSPVCore) -> *mut Runtime {
    Arc::as_ptr(&(&*self_).platform.runtime) as *mut _
}
# [no_mangle]
pub unsafe extern "C" fn dash_spv_apple_bindings_DashSPVCore_destroy(self_: *mut DashSPVCore) {
    ferment::unbox_any(self_);
}

# [no_mangle]
pub unsafe extern "C" fn dash_spv_coinjoin_coinjoin_client_manager_CoinJoinClientManager_destroy(self_: *mut CoinJoinClientManager) {
    ferment::unbox_any(self_);
}
// #[no_mangle]
// pub unsafe extern "C" fn masternode_list_map_by_key(
//     self_: *mut std_collections_Map_keys_u8_arr_32_values_dash_spv_masternode_processor_models_masternode_list_MasternodeList,
//     key: *mut Arr_u8_32,
// ) -> *mut dash_spv_masternode_processor_models_masternode_list_MasternodeList {
//     let self_ = FFIConversionFrom::<BTreeMap<[u8; 32], MasternodeList>>::ffi_from(self_);
//     let key = FFIConversionFrom::<[u8; 32]>::ffi_from(key);
//     let result = self_.get(&key).cloned();
//     FFIConversionTo::<MasternodeList>::ffi_to_opt(result)
// }
// #[no_mangle]
// pub unsafe extern "C" fn masternode_by_pro_reg_tx_hash(
//     self_: *mut std_collections_Map_keys_u8_arr_32_values_dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry,
//     pro_reg_tx_hash: *mut Arr_u8_32,
// ) -> *mut dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry {
//     let self_ = FFIConversionFrom::<BTreeMap<[u8; 32], MasternodeEntry>>::ffi_from(self_);
//     let key = FFIConversionFrom::<[u8; 32]>::ffi_from(pro_reg_tx_hash);
//     let result = self_.get(&key).cloned();
//     FFIConversionTo::<MasternodeEntry>::ffi_to_opt(result)
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn llmq_by_type_and_hash(
//     self_: *mut std_collections_Map_keys_dash_spv_crypto_network_llmq_type_LLMQType_values_std_collections_Map_keys_u8_arr_32_values_dash_spv_crypto_llmq_entry_LLMQEntry,
//     llmq_type: *mut dash_spv_crypto_network_llmq_type_LLMQType,
//     llmq_hash: *mut Arr_u8_32,
// ) -> *mut dash_spv_crypto_llmq_entry_LLMQEntry {
//     let self_ = FFIConversionFrom::<BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>>::ffi_from(self_);
//     let llmq_type = FFIConversionFrom::<LLMQType>::ffi_from(llmq_type);
//     let llmq_hash = FFIConversionFrom::<[u8; 32]>::ffi_from(llmq_hash);
//     let result = self_.get(&llmq_type).and_then(|q| q.get(&llmq_hash)).cloned();
//     FFIConversionTo::<LLMQEntry>::ffi_to_opt(result)
// }
//

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

