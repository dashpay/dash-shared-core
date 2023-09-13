use crate::types;
use std::ptr::null_mut;
use crate::processing::ProcessingError;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct MNListDiffResult {
    pub error_status: ProcessingError,
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
impl MNListDiffResult {
    pub fn default_with_error(error: ProcessingError) -> Self {
        Self { error_status: error, ..Default::default() }
    }
}

impl Default for MNListDiffResult {
    fn default() -> Self {
        MNListDiffResult {
            error_status: ProcessingError::None,
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
                rs_ffi_interfaces::unbox_any(self.base_block_hash);
            }
            if !self.block_hash.is_null() {
                rs_ffi_interfaces::unbox_any(self.block_hash);
            }
            if !self.masternode_list.is_null() {
                rs_ffi_interfaces::unbox_any(self.masternode_list);
            }
            if !self.needed_masternode_lists.is_null() {
                rs_ffi_interfaces::unbox_any_vec_ptr(
                    self.needed_masternode_lists,
                    self.needed_masternode_lists_count,
                );
            }
            if !self.added_masternodes.is_null() {
                rs_ffi_interfaces::unbox_any_vec_ptr(
                    self.added_masternodes,
                    self.added_masternodes_count,
                );
            }
            if !self.modified_masternodes.is_null() {
                rs_ffi_interfaces::unbox_any_vec_ptr(
                    self.modified_masternodes,
                    self.modified_masternodes_count,
                );
            }
            if !self.added_llmq_type_maps.is_null() {
                rs_ffi_interfaces::unbox_any_vec_ptr(
                    self.added_llmq_type_maps,
                    self.added_llmq_type_maps_count,
                );
            }
            if !self.quorums_cl_sigs.is_null() {
                rs_ffi_interfaces::unbox_any_vec_ptr(
                    self.quorums_cl_sigs,
                    self.quorums_cl_sigs_count,
                );
                rs_ffi_interfaces::unbox_any_vec_ptr(
                    self.quorums_cl_sigs,
                    self.quorums_cl_sigs_count,
                );
            }
        }
    }
}