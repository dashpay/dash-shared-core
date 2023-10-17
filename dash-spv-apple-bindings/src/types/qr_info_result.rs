use std::ptr::null_mut;
use dash_spv_masternode_processor::processing::ProcessingError;
use crate::types;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct QRInfoResult {
    pub error_status: ProcessingError,
    pub result_at_tip: *mut types::MNListDiffResult,
    pub result_at_h: *mut types::MNListDiffResult,
    pub result_at_h_c: *mut types::MNListDiffResult,
    pub result_at_h_2c: *mut types::MNListDiffResult,
    pub result_at_h_3c: *mut types::MNListDiffResult,
    pub result_at_h_4c: *mut types::MNListDiffResult,

    pub snapshot_at_h_c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_2c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_3c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_4c: *mut types::LLMQSnapshot,
    pub extra_share: bool,
    pub last_quorum_per_index: *mut *mut types::LLMQEntry,
    pub last_quorum_per_index_count: usize,
    pub quorum_snapshot_list: *mut *mut types::LLMQSnapshot,
    pub quorum_snapshot_list_count: usize,
    pub mn_list_diff_list: *mut *mut types::MNListDiffResult,
    pub mn_list_diff_list_count: usize,
}

impl Default for QRInfoResult {
    fn default() -> Self {
        Self {
            error_status: ProcessingError::None,
            result_at_tip: null_mut(),
            result_at_h: null_mut(),
            result_at_h_c: null_mut(),
            result_at_h_2c: null_mut(),
            result_at_h_3c: null_mut(),
            result_at_h_4c: null_mut(),
            snapshot_at_h_c: null_mut(),
            snapshot_at_h_2c: null_mut(),
            snapshot_at_h_3c: null_mut(),
            snapshot_at_h_4c: null_mut(),
            extra_share: false,
            last_quorum_per_index_count: 0,
            last_quorum_per_index: null_mut(),
            quorum_snapshot_list_count: 0,
            quorum_snapshot_list: null_mut(),
            mn_list_diff_list_count: 0,
            mn_list_diff_list: null_mut(),
        }
    }
}

impl Drop for QRInfoResult {
    fn drop(&mut self) {
        unsafe {
            if !self.result_at_tip.is_null() {
                ferment_interfaces::unbox_any(self.result_at_tip);
            }
            if !self.result_at_h.is_null() {
                ferment_interfaces::unbox_any(self.result_at_h);
            }
            if !self.result_at_h_c.is_null() {
                ferment_interfaces::unbox_any(self.result_at_h_c);
            }
            if !self.result_at_h_2c.is_null() {
                ferment_interfaces::unbox_any(self.result_at_h_2c);
            }
            if !self.result_at_h_3c.is_null() {
                ferment_interfaces::unbox_any(self.result_at_h_3c);
            }
            if !self.snapshot_at_h_c.is_null() {
                ferment_interfaces::unbox_any(self.snapshot_at_h_c);
            }
            if !self.snapshot_at_h_2c.is_null() {
                ferment_interfaces::unbox_any(self.snapshot_at_h_2c);
            }
            if !self.snapshot_at_h_3c.is_null() {
                ferment_interfaces::unbox_any(self.snapshot_at_h_3c);
            }
            if self.extra_share {
                if !self.result_at_h_4c.is_null() {
                    ferment_interfaces::unbox_any(self.result_at_h_4c);
                }
                if !self.snapshot_at_h_4c.is_null() {
                    ferment_interfaces::unbox_any(self.snapshot_at_h_4c);
                }
            }
            if !self.last_quorum_per_index.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.last_quorum_per_index,
                    self.last_quorum_per_index_count,
                );
            }
            if !self.quorum_snapshot_list.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.quorum_snapshot_list,
                    self.quorum_snapshot_list_count,
                );
            }
            if !self.mn_list_diff_list.is_null() {
                ferment_interfaces::unbox_any_vec_ptr(
                    self.mn_list_diff_list,
                    self.mn_list_diff_list_count,
                );
            }
        }
    }
}