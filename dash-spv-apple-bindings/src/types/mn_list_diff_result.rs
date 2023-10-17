use dash_spv_masternode_processor::processing;
use std::ptr::null_mut;
use crate::ffi::to::{encode_masternodes_map, encode_quorums_map, ToFFI};
use crate::types;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct MNListDiffResult {
    // pub error_status: ProcessingError,
    pub base_block_hash: *mut [u8; 32],
    pub block_hash: *mut [u8; 32],
    pub has_found_coinbase: bool,       //1 byte
    pub has_valid_coinbase: bool,       //1 byte
    pub has_valid_mn_list_root: bool,   //1 byte
    pub has_valid_llmq_list_root: bool, //1 byte
    pub has_valid_quorums: bool,        //1 byte
    pub masternode_list: *mut types::MasternodeList,
    pub added_masternodes: *mut *mut types::MasternodeEntry,
    pub added_masternodes_count: usize,
    pub modified_masternodes: *mut *mut types::MasternodeEntry,
    pub modified_masternodes_count: usize,
    pub added_llmq_type_maps: *mut *mut types::LLMQMap,
    pub added_llmq_type_maps_count: usize,
    pub needed_masternode_lists: *mut *mut [u8; 32],
    pub needed_masternode_lists_count: usize,
    pub quorums_cl_sigs: *mut *mut types::QuorumsCLSigsObject,
    pub quorums_cl_sigs_count: usize,
}

impl Default for MNListDiffResult {
    fn default() -> Self {
        MNListDiffResult {
            // error_status: ProcessingError::None,
            base_block_hash: null_mut(),
            block_hash: null_mut(),
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_llmq_list_root: false,
            has_valid_quorums: false,
            masternode_list: null_mut(),
            added_masternodes: null_mut(),
            added_masternodes_count: 0,
            modified_masternodes: null_mut(),
            modified_masternodes_count: 0,
            added_llmq_type_maps: null_mut(),
            added_llmq_type_maps_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0,
            quorums_cl_sigs: null_mut(),
            quorums_cl_sigs_count: 0,
        }
    }
}

impl From<processing::MNListDiffResult> for MNListDiffResult {
    fn from(value: processing::MNListDiffResult) -> Self {
        MNListDiffResult {
            base_block_hash: ferment_interfaces::boxed(value.base_block_hash.0),
            block_hash: ferment_interfaces::boxed(value.block_hash.0),
            has_found_coinbase: value.has_found_coinbase,
            has_valid_coinbase: value.has_valid_coinbase,
            has_valid_mn_list_root: value.has_valid_mn_list_root,
            has_valid_llmq_list_root: value.has_valid_llmq_list_root,
            has_valid_quorums: value.has_valid_quorums,
            masternode_list: ferment_interfaces::boxed(value.masternode_list.encode()),
            added_masternodes: encode_masternodes_map(&value.added_masternodes),
            added_masternodes_count: value.added_masternodes.len(),
            modified_masternodes: encode_masternodes_map(&value.modified_masternodes),
            modified_masternodes_count: value.modified_masternodes.len(),
            added_llmq_type_maps: encode_quorums_map(&value.added_quorums),
            added_llmq_type_maps_count: value.added_quorums.len(),
            needed_masternode_lists: ferment_interfaces::boxed_vec(
                value.needed_masternode_lists
                    .iter()
                    .map(|h| ferment_interfaces::boxed(h.0))
                    .collect(),
            ),
            needed_masternode_lists_count: value.needed_masternode_lists.len(),
            quorums_cl_sigs_count: value.quorums_cl_sigs.len(),
            quorums_cl_sigs: ferment_interfaces::boxed_vec(
                value.quorums_cl_sigs
                    .iter()
                    .map(|h| ferment_interfaces::boxed(h.encode()))
                    .collect(),
            ),
        }
    }
}

impl MNListDiffResult {
    pub fn is_valid(&self) -> bool {
        self.has_found_coinbase
            && self.has_valid_quorums
            && self.has_valid_mn_list_root
            && self.has_valid_llmq_list_root
    }
}

impl Drop for MNListDiffResult {
    fn drop(&mut self) {
        unsafe {
            if !self.base_block_hash.is_null() {
                ferment_interfaces::unbox_any(self.base_block_hash);
            }
            if !self.block_hash.is_null() {
                ferment_interfaces::unbox_any(self.block_hash);
            }
            if !self.masternode_list.is_null() {
                ferment_interfaces::unbox_any(self.masternode_list);
            }
            if !self.needed_masternode_lists.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.needed_masternode_lists,
                    self.needed_masternode_lists_count,
                );
            }
            if !self.added_masternodes.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.added_masternodes,
                    self.added_masternodes_count,
                );
            }
            if !self.modified_masternodes.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.modified_masternodes,
                    self.modified_masternodes_count,
                );
            }
            if !self.added_llmq_type_maps.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.added_llmq_type_maps,
                    self.added_llmq_type_maps_count,
                );
            }
            if !self.quorums_cl_sigs.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.quorums_cl_sigs,
                    self.quorums_cl_sigs_count,
                );
                ferment_interfaces::unbox_any_vec_ptr(
                    self.quorums_cl_sigs,
                    self.quorums_cl_sigs_count,
                );
            }
        }
    }
}