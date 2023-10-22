use crate::ffi::unboxer::{unbox_any, unbox_vec_ptr};
use crate::types::{BlockOperatorPublicKey, MasternodeEntryHash, OperatorPublicKey, Validity};

#[repr(C)]
#[derive(Clone, Debug)]
pub struct MasternodeEntry {
    pub confirmed_hash: *mut [u8; 32],
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: *mut [u8; 32], // nullable
    pub is_valid: bool,
    pub key_id_voting: *mut [u8; 20],
    pub known_confirmed_at_height: u32, // nullable
    pub entry_hash: *mut [u8; 32],
    pub operator_public_key: *mut OperatorPublicKey,
    pub previous_entry_hashes: *mut MasternodeEntryHash,
    pub previous_entry_hashes_count: usize,
    pub previous_operator_public_keys: *mut BlockOperatorPublicKey,
    pub previous_operator_public_keys_count: usize,
    pub previous_validity: *mut Validity,
    pub previous_validity_count: usize,
    pub provider_registration_transaction_hash: *mut [u8; 32],
    pub ip_address: *mut [u8; 16],
    pub port: u16,
    pub update_height: u32,
    // Core v0.19 (70227+)
    // 0: regular, 1: high performance
    pub mn_type: u16,
    pub platform_http_port: u16,
    pub platform_node_id: *mut [u8; 20],
}

impl Drop for MasternodeEntry {
    fn drop(&mut self) {
        unsafe {
            unbox_any(self.confirmed_hash);
            if !self.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
                unbox_any(self.confirmed_hash_hashed_with_provider_registration_transaction_hash);
            }
            unbox_any(self.key_id_voting);
            unbox_any(self.entry_hash);
            unbox_any(self.operator_public_key);
            unbox_vec_ptr(self.previous_entry_hashes, self.previous_entry_hashes_count);
            unbox_vec_ptr(self.previous_operator_public_keys, self.previous_operator_public_keys_count);
            unbox_vec_ptr(self.previous_validity, self.previous_validity_count);
            unbox_any(self.provider_registration_transaction_hash);
            unbox_any(self.ip_address);
            unbox_any(self.platform_node_id);

        }
    }
}