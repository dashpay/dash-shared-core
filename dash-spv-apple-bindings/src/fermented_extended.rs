use std::collections::BTreeMap;
use std::sync::Arc;
use ferment::{FFIConversionFrom, FFIConversionTo};
use dash_spv_crypto::llmq::LLMQEntry;
use dash_spv_crypto::network::LLMQType;
use dash_spv_masternode_processor::models::{MasternodeEntry, MasternodeList};
use crate::fermented::generics::{std_collections_Map_keys_dash_spv_crypto_network_llmq_type_LLMQType_values_std_collections_Map_keys_u8_arr_32_values_dash_spv_crypto_llmq_entry_LLMQEntry, std_collections_Map_keys_u8_arr_32_values_dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry, std_collections_Map_keys_u8_arr_32_values_std_sync_Arc_dash_spv_masternode_processor_models_masternode_list_MasternodeList, std_sync_Arc_dash_spv_masternode_processor_models_masternode_list_MasternodeList, Arr_u8_32};
use crate::fermented::types::dash_spv_crypto::llmq::entry::dash_spv_crypto_llmq_entry_LLMQEntry;
use crate::fermented::types::dash_spv_crypto::network::llmq_type::dash_spv_crypto_network_llmq_type_LLMQType;
use crate::fermented::types::dash_spv_masternode_processor::models::masternode_entry::dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry;

//TODO: this is a tmp additional setup
#[no_mangle]
pub unsafe extern "C" fn masternode_list_map_by_key(
    self_: *mut std_collections_Map_keys_u8_arr_32_values_std_sync_Arc_dash_spv_masternode_processor_models_masternode_list_MasternodeList,
    key: *mut Arr_u8_32,
) -> *mut std_sync_Arc_dash_spv_masternode_processor_models_masternode_list_MasternodeList {
    let self_ = FFIConversionFrom::<BTreeMap<[u8; 32], Arc<MasternodeList>>>::ffi_from(self_);
    let key = FFIConversionFrom::<[u8; 32]>::ffi_from(key);
    let result = self_.get(&key).cloned();
    FFIConversionTo::<Arc<MasternodeList>>::ffi_to_opt(result)
}
#[no_mangle]
pub unsafe extern "C" fn masternode_by_pro_reg_tx_hash(
    self_: *mut std_collections_Map_keys_u8_arr_32_values_dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry,
    pro_reg_tx_hash: *mut Arr_u8_32,
) -> *mut dash_spv_masternode_processor_models_masternode_entry_MasternodeEntry {
    let self_ = FFIConversionFrom::<BTreeMap<[u8; 32], MasternodeEntry>>::ffi_from(self_);
    let key = FFIConversionFrom::<[u8; 32]>::ffi_from(pro_reg_tx_hash);
    let result = self_.get(&key).cloned();
    FFIConversionTo::<MasternodeEntry>::ffi_to_opt(result)
}

#[no_mangle]
pub unsafe extern "C" fn llmq_by_type_and_hash(
    self_: *mut std_collections_Map_keys_dash_spv_crypto_network_llmq_type_LLMQType_values_std_collections_Map_keys_u8_arr_32_values_dash_spv_crypto_llmq_entry_LLMQEntry,
    llmq_type: *mut dash_spv_crypto_network_llmq_type_LLMQType,
    llmq_hash: *mut Arr_u8_32,
) -> *mut dash_spv_crypto_llmq_entry_LLMQEntry {
    let self_ = FFIConversionFrom::<BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>>::ffi_from(self_);
    let llmq_type = FFIConversionFrom::<LLMQType>::ffi_from(llmq_type);
    let llmq_hash = FFIConversionFrom::<[u8; 32]>::ffi_from(llmq_hash);
    let result = self_.get(&llmq_type).and_then(|q| q.get(&llmq_hash)).cloned();
    FFIConversionTo::<LLMQEntry>::ffi_to_opt(result)
}

