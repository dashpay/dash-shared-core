use std::sync::Arc;
use tokio::runtime::Runtime;
use crate::custom::dashcore::{dashcore_hash_types_BlockHash, dashcore_hash_types_ConfirmedHash, dashcore_hash_types_ConfirmedHashHashedWithProRegTx, dashcore_hash_types_CycleHash, dashcore_hash_types_InputsHash, dashcore_hash_types_MerkleRootMasternodeList, dashcore_hash_types_MerkleRootQuorums, dashcore_hash_types_ProTxHash, dashcore_hash_types_PubkeyHash, dashcore_hash_types_QuorumCommitmentHash, dashcore_hash_types_QuorumEntryHash, dashcore_hash_types_QuorumHash, dashcore_hash_types_QuorumSigningRequestId, dashcore_hash_types_QuorumVVecHash, dashcore_hash_types_ScriptHash, dashcore_hash_types_Sha256dHash, dashcore_hash_types_SpecialTransactionPayloadHash, dashcore_hash_types_TxMerkleNode, dashcore_hash_types_Txid};
use crate::DashSPVCore;

// use std::collections::BTreeMap;
// use std::sync::Arc;
// use ferment::{FFIConversionFrom, FFIConversionTo};
// use tokio::runtime::Runtime;
// use dash_spv_crypto::llmq::LLMQEntry;
// use dash_spv_crypto::network::LLMQType;
// use dash_spv_masternode_processor::models::{MasternodeEntry, MasternodeList};
// use crate::DashSPVCore;
// use crate::fermented::generics::{std_collections_Map_keys_dash_spv_crypto_network_llmq_type_LLMQType_values_std_collections_Map_keys_u8_arr_32_values_dash_spv_crypto_llmq_entry_LLMQEntry, std_collections_Map_keys_u8_arr_32_values_dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry, std_collections_Map_keys_u8_arr_32_values_dash_spv_masternode_processor_models_masternode_list_MasternodeList, Arr_u8_32};
// use crate::fermented::types::dash_spv_crypto::llmq::entry::dash_spv_crypto_llmq_entry_LLMQEntry;
// use crate::fermented::types::dash_spv_crypto::network::llmq_type::dash_spv_crypto_network_llmq_type_LLMQType;
// use crate::fermented::types::dash_spv_masternode_processor::models::masternode_entry::dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry;
// use crate::fermented::types::dash_spv_masternode_processor::models::masternode_list::dash_spv_masternode_processor_models_masternode_list_MasternodeList;
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


#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_BlockHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_BlockHash { ferment::boxed(dashcore_hash_types_BlockHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_BlockHash_destroy(ptr: *mut dashcore_hash_types_BlockHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_BlockHash_inner(ptr: *mut dashcore_hash_types_BlockHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_CycleHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_CycleHash { ferment::boxed(dashcore_hash_types_CycleHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_CycleHash_destroy(ptr: *mut dashcore_hash_types_CycleHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_CycleHash_inner(ptr: *mut dashcore_hash_types_CycleHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Txid_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_Txid { ferment::boxed(dashcore_hash_types_Txid(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Txid_destroy(ptr: *mut dashcore_hash_types_Txid) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Txid_inner(ptr: *mut dashcore_hash_types_Txid) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_PubkeyHash_ctor(hash: *mut [u8; 20]) -> *mut dashcore_hash_types_PubkeyHash { ferment::boxed(dashcore_hash_types_PubkeyHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_PubkeyHash_destroy(ptr: *mut dashcore_hash_types_PubkeyHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_PubkeyHash_inner(ptr: *mut dashcore_hash_types_PubkeyHash) -> *mut [u8; 20] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_TxMerkleNode_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_TxMerkleNode { ferment::boxed(dashcore_hash_types_TxMerkleNode(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_TxMerkleNode_destroy(ptr: *mut dashcore_hash_types_TxMerkleNode) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_TxMerkleNode_inner(ptr: *mut dashcore_hash_types_TxMerkleNode) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_SpecialTransactionPayloadHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_SpecialTransactionPayloadHash { ferment::boxed(dashcore_hash_types_SpecialTransactionPayloadHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_SpecialTransactionPayloadHash_destroy(ptr: *mut dashcore_hash_types_SpecialTransactionPayloadHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_SpecialTransactionPayloadHash_inner(ptr: *mut dashcore_hash_types_SpecialTransactionPayloadHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_InputsHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_InputsHash { ferment::boxed(dashcore_hash_types_InputsHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_InputsHash_destroy(ptr: *mut dashcore_hash_types_InputsHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_InputsHash_inner(ptr: *mut dashcore_hash_types_InputsHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_QuorumHash { ferment::boxed(dashcore_hash_types_QuorumHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumHash_destroy(ptr: *mut dashcore_hash_types_QuorumHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumHash_inner(ptr: *mut dashcore_hash_types_QuorumHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumVVecHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_QuorumVVecHash { ferment::boxed(dashcore_hash_types_QuorumVVecHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumVVecHash_destroy(ptr: *mut dashcore_hash_types_QuorumVVecHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumVVecHash_inner(ptr: *mut dashcore_hash_types_QuorumVVecHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumSigningRequestId_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_QuorumSigningRequestId { ferment::boxed(dashcore_hash_types_QuorumSigningRequestId(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumSigningRequestId_destroy(ptr: *mut dashcore_hash_types_QuorumSigningRequestId) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumSigningRequestId_inner(ptr: *mut dashcore_hash_types_QuorumSigningRequestId) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ProTxHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_ProTxHash { ferment::boxed(dashcore_hash_types_ProTxHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ProTxHash_destroy(ptr: *mut dashcore_hash_types_ProTxHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ProTxHash_inner(ptr: *mut dashcore_hash_types_ProTxHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootMasternodeList_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_MerkleRootMasternodeList { ferment::boxed(dashcore_hash_types_MerkleRootMasternodeList(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootMasternodeList_destroy(ptr: *mut dashcore_hash_types_MerkleRootMasternodeList) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootMasternodeList_inner(ptr: *mut dashcore_hash_types_MerkleRootMasternodeList) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootQuorums_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_MerkleRootQuorums { ferment::boxed(dashcore_hash_types_MerkleRootQuorums(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootQuorums_destroy(ptr: *mut dashcore_hash_types_MerkleRootQuorums) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_MerkleRootQuorums_inner(ptr: *mut dashcore_hash_types_MerkleRootQuorums) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumEntryHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_QuorumEntryHash { ferment::boxed(dashcore_hash_types_QuorumEntryHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumEntryHash_destroy(ptr: *mut dashcore_hash_types_QuorumEntryHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumEntryHash_inner(ptr: *mut dashcore_hash_types_QuorumEntryHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHashHashedWithProRegTx_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_ConfirmedHashHashedWithProRegTx { ferment::boxed(dashcore_hash_types_ConfirmedHashHashedWithProRegTx(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHashHashedWithProRegTx_destroy(ptr: *mut dashcore_hash_types_ConfirmedHashHashedWithProRegTx) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHashHashedWithProRegTx_inner(ptr: *mut dashcore_hash_types_ConfirmedHashHashedWithProRegTx) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_ConfirmedHash { ferment::boxed(dashcore_hash_types_ConfirmedHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHash_destroy(ptr: *mut dashcore_hash_types_ConfirmedHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ConfirmedHash_inner(ptr: *mut dashcore_hash_types_ConfirmedHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumCommitmentHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_QuorumCommitmentHash { ferment::boxed(dashcore_hash_types_QuorumCommitmentHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumCommitmentHash_destroy(ptr: *mut dashcore_hash_types_QuorumCommitmentHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_QuorumCommitmentHash_inner(ptr: *mut dashcore_hash_types_QuorumCommitmentHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Sha256dHash_ctor(hash: *mut [u8; 32]) -> *mut dashcore_hash_types_Sha256dHash { ferment::boxed(dashcore_hash_types_Sha256dHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Sha256dHash_destroy(ptr: *mut dashcore_hash_types_Sha256dHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_Sha256dHash_inner(ptr: *mut dashcore_hash_types_Sha256dHash) -> *mut [u8; 32] { (&*ptr).0 }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ScriptHash_ctor(hash: *mut [u8; 20]) -> *mut dashcore_hash_types_ScriptHash { ferment::boxed(dashcore_hash_types_ScriptHash(hash)) }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ScriptHash_destroy(ptr: *mut dashcore_hash_types_ScriptHash) { ferment::unbox_any(ptr); }
#[no_mangle] pub unsafe extern "C" fn dashcore_hash_types_ScriptHash_inner(ptr: *mut dashcore_hash_types_ScriptHash) -> *mut [u8; 20] { (&*ptr).0 }

