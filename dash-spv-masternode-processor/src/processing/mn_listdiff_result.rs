use crate::crypto::UInt256;
use crate::ffi::to::{encode_masternodes_map, encode_quorums_map, ToFFI};
use crate::types;
use std::collections::BTreeMap;

#[derive(Clone)]
#[rs_ffi_macro_derive::impl_ffi_conv]
pub struct MNListDiffResult {
    pub base_block_hash: UInt256,
    pub block_hash: UInt256,
    pub has_found_coinbase: bool,       //1 byte
    pub has_valid_coinbase: bool,       //1 byte
    pub has_valid_mn_list_root: bool,   //1 byte
    pub has_valid_llmq_list_root: bool, //1 byte
    pub has_valid_quorums: bool,        //1 byte
    pub masternode_list: crate::models::masternode_list::MasternodeList,
    pub added_masternodes: BTreeMap<UInt256, crate::models::masternode_entry::MasternodeEntry>,
    pub modified_masternodes: BTreeMap<UInt256, crate::models::masternode_entry::MasternodeEntry>,
    pub added_quorums: BTreeMap<
        crate::chain::common::llmq_type::LLMQType,
        BTreeMap<UInt256, crate::models::llmq_entry::LLMQEntry>,
    >,
    pub needed_masternode_lists: Vec<UInt256>,
    pub quorums_cl_sigs: Vec<crate::models::quorums_cl_sigs_object::QuorumsCLSigsObject>,
}

impl std::fmt::Debug for MNListDiffResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MNListDiffResult")
            // .field("error_status", &self.error_status)
            .field("base_block_hash", &self.base_block_hash)
            .field("block_hash", &self.block_hash)
            .field(
                "validation",
                &format!(
                    "{}{}{}{}{}",
                    u8::from(self.has_found_coinbase),
                    u8::from(self.has_valid_coinbase),
                    u8::from(self.has_valid_mn_list_root),
                    u8::from(self.has_valid_llmq_list_root),
                    u8::from(self.has_valid_quorums)
                ),
            )
            .field("masternode_list", &self.masternode_list)
            .field("added_masternodes", &self.added_masternodes)
            .field("modified_masternodes", &self.modified_masternodes)
            .field("added_quorums", &self.added_quorums)
            .field("needed_masternode_lists", &self.needed_masternode_lists)
            .finish()
    }
}

impl Default for MNListDiffResult {
    fn default() -> Self {
        Self {
            base_block_hash: UInt256::MIN,
            block_hash: UInt256::MAX,
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_llmq_list_root: false,
            has_valid_quorums: false,
            masternode_list: Default::default(),
            added_masternodes: Default::default(),
            modified_masternodes: Default::default(),
            added_quorums: Default::default(),
            needed_masternode_lists: vec![],
            quorums_cl_sigs: vec![],
        }
    }
}

impl MNListDiffResult {
    pub fn encode(&self) -> types::MNListDiffResult {
        types::MNListDiffResult {
            // error_status: self.error_status.into(),
            base_block_hash: rs_ffi_interfaces::boxed(self.base_block_hash.0),
            block_hash: rs_ffi_interfaces::boxed(self.block_hash.0),
            has_found_coinbase: self.has_found_coinbase,
            has_valid_coinbase: self.has_valid_coinbase,
            has_valid_mn_list_root: self.has_valid_mn_list_root,
            has_valid_llmq_list_root: self.has_valid_llmq_list_root,
            has_valid_quorums: self.has_valid_quorums,
            masternode_list: rs_ffi_interfaces::boxed(self.masternode_list.encode()),
            added_masternodes: encode_masternodes_map(&self.added_masternodes),
            added_masternodes_count: self.added_masternodes.len(),
            modified_masternodes: encode_masternodes_map(&self.modified_masternodes),
            modified_masternodes_count: self.modified_masternodes.len(),
            added_llmq_type_maps: encode_quorums_map(&self.added_quorums),
            added_llmq_type_maps_count: self.added_quorums.len(),
            needed_masternode_lists: rs_ffi_interfaces::boxed_vec(
                self.needed_masternode_lists
                    .iter()
                    .map(|h| rs_ffi_interfaces::boxed(h.0))
                    .collect(),
            ),
            needed_masternode_lists_count: self.needed_masternode_lists.len(),
            quorums_cl_sigs_count: self.quorums_cl_sigs.len(),
            quorums_cl_sigs: rs_ffi_interfaces::boxed_vec(
                self.quorums_cl_sigs
                    .iter()
                    .map(|h| rs_ffi_interfaces::boxed(h.encode()))
                    .collect(),
            ),
        }
    }
}


