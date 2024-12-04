use std::collections::{BTreeMap, HashSet};
use crate::models::{masternode_entry::MasternodeEntry, masternode_list::MasternodeList};

#[derive(Clone)]
#[ferment_macro::export]
pub struct MNListDiffResult {
    pub base_block_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub has_found_coinbase: bool,       //1 byte
    pub has_valid_coinbase: bool,       //1 byte
    pub has_valid_mn_list_root: bool,   //1 byte
    pub has_valid_llmq_list_root: bool, //1 byte
    pub has_valid_quorums: bool,        //1 byte
    pub has_added_quorums: bool,
    pub has_added_rotated_quorums: bool,
    // pub has_missed_masternode_lists: bool,
    pub masternode_list: MasternodeList,
    pub added_masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
    pub modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
    // pub added_quorums: Vec<LLMQEntry>,
    pub needed_masternode_lists: HashSet<[u8; 32]>,
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
            .field("has_added_quorums", &self.has_added_quorums)
            .field("has_added_rotated_quorums", &self.has_added_rotated_quorums)
            .field("needed_masternode_lists", &self.needed_masternode_lists)
            // .field("added_quorums", &self.added_quorums)
            // .field("needed_masternode_lists", &self.needed_masternode_lists)
            .finish()
    }
}

impl Default for MNListDiffResult {
    fn default() -> Self {
        Self {
            base_block_hash: [0; 32],
            block_hash: [!0; 32],
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_llmq_list_root: false,
            has_valid_quorums: false,
            has_added_quorums: false,
            has_added_rotated_quorums: false,
            // has_missed_masternode_lists: false,
            masternode_list: Default::default(),
            added_masternodes: Default::default(),
            modified_masternodes: Default::default(),
            // added_quorums: vec![],
            needed_masternode_lists: Default::default(),
        }
    }
}

#[ferment_macro::export]
impl MNListDiffResult {
    pub fn is_valid(&self) -> bool {
        self.has_found_coinbase
            && self.has_valid_quorums
            && self.has_valid_mn_list_root
            && self.has_valid_llmq_list_root
    }

    // pub fn has_added_rotated_quorums(&self, chain_type: ChainType) -> bool {
    //     self.added_quorums.iter().any(|q| q.llmq_type == chain_type.isd_llmq_type())
    // }

    pub fn masternodes_changed(&self) -> Vec<MasternodeEntry> {
        let mut result = Vec::from_iter(self.added_masternodes.values().cloned());
        result.extend(self.modified_masternodes.values().cloned());
        result
    }
}

