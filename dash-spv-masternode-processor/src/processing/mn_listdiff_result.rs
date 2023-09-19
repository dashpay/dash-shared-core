use crate::crypto::UInt256;
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


