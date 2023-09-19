use crate::types;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct MasternodeList {
    pub block_hash: *mut [u8; 32],
    pub known_height: u32,
    pub masternode_merkle_root: *mut [u8; 32], // nullable
    pub llmq_merkle_root: *mut [u8; 32],       // nullable
    pub masternodes: *mut *mut types::MasternodeEntry,
    pub masternodes_count: usize,
    pub llmq_type_maps: *mut *mut types::LLMQMap,
    pub llmq_type_maps_count: usize,
}

impl Drop for MasternodeList {
    fn drop(&mut self) {
        unsafe {
            rs_ffi_interfaces::unbox_any(self.block_hash);
            if !self.masternode_merkle_root.is_null() {
                rs_ffi_interfaces::unbox_any(self.masternode_merkle_root);
            }
            if !self.llmq_merkle_root.is_null() {
                rs_ffi_interfaces::unbox_any(self.llmq_merkle_root);
            }
            rs_ffi_interfaces::unbox_any_vec_ptr(self.masternodes, self.masternodes_count);
            rs_ffi_interfaces::unbox_any_vec_ptr(self.llmq_type_maps, self.llmq_type_maps_count);

        }
    }
}