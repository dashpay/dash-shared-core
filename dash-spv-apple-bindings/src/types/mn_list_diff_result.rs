use dash_spv_masternode_processor::processing;
use std::ptr::null_mut;
use ferment_interfaces::{boxed, boxed_vec, unbox_any, unbox_any_vec_ptr};
use crate::ffi::to::{encode_masternodes_map, ToFFI};
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
    pub added_quorums: *mut *mut types::LLMQEntry,
    pub added_quorums_count: usize,
    pub needed_masternode_lists: *mut *mut [u8; 32],
    pub needed_masternode_lists_count: usize,
    pub quorums_cl_signatures_hashes: *mut *mut [u8; 32],
    pub quorums_cl_signatures: *mut *mut [u8; 96],
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
            added_quorums: null_mut(),
            added_quorums_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0,
            quorums_cl_signatures_hashes: null_mut(),
            quorums_cl_signatures: null_mut(),
            quorums_cl_sigs_count: 0,
        }
    }
}

impl From<processing::MNListDiffResult> for MNListDiffResult {
    fn from(value: processing::MNListDiffResult) -> Self {
        MNListDiffResult {
            // error_status: value.error_status.into(),
            base_block_hash: boxed(value.base_block_hash.0),
            block_hash: boxed(value.block_hash.0),
            has_found_coinbase: value.has_found_coinbase,
            has_valid_coinbase: value.has_valid_coinbase,
            has_valid_mn_list_root: value.has_valid_mn_list_root,
            has_valid_llmq_list_root: value.has_valid_llmq_list_root,
            has_valid_quorums: value.has_valid_quorums,
            masternode_list: boxed(value.masternode_list.encode()),
            added_masternodes: encode_masternodes_map(&value.added_masternodes),
            added_masternodes_count: value.added_masternodes.len(),
            modified_masternodes: encode_masternodes_map(&value.modified_masternodes),
            modified_masternodes_count: value.modified_masternodes.len(),
            added_quorums_count: value.added_quorums.len(),
            added_quorums: boxed_vec(value.added_quorums
                .iter()
                .map(|quorum| boxed(quorum.encode()))
                .collect()),
            needed_masternode_lists: boxed_vec(
                value.needed_masternode_lists
                    .iter()
                    .map(|h| boxed(h.0))
                    .collect(),
            ),
            needed_masternode_lists_count: value.needed_masternode_lists.len(),
            quorums_cl_sigs_count: value.cl_signatures.len(),
            quorums_cl_signatures_hashes: boxed_vec(
                value.cl_signatures
                    .keys()
                    .map(|h| boxed(h.0))
                    .collect()),
            quorums_cl_signatures: boxed_vec(
                value.cl_signatures
                    .values()
                    .map(|h| boxed(h.0))
                    .collect())
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
                unbox_any(self.base_block_hash);
            }
            if !self.block_hash.is_null() {
                unbox_any(self.block_hash);
            }
            if !self.masternode_list.is_null() {
                unbox_any(self.masternode_list);
            }
            if !self.needed_masternode_lists.is_null() {
                unbox_any_vec_ptr(self.needed_masternode_lists, self.needed_masternode_lists_count);
            }
            if !self.added_masternodes.is_null() {
                unbox_any_vec_ptr(self.added_masternodes, self.added_masternodes_count);
            }
            if !self.modified_masternodes.is_null() {
                unbox_any_vec_ptr(self.modified_masternodes, self.modified_masternodes_count);
            }
            if !self.added_quorums.is_null() {
                unbox_any_vec_ptr(self.added_quorums, self.added_quorums_count);
            }
            if !self.quorums_cl_signatures_hashes.is_null() {
                unbox_any_vec_ptr(self.quorums_cl_signatures_hashes, self.quorums_cl_sigs_count);
            }
            if !self.quorums_cl_signatures.is_null() {
                unbox_any_vec_ptr(self.quorums_cl_signatures, self.quorums_cl_sigs_count);
            }
        }
    }
}
