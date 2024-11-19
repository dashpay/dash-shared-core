use std::collections::BTreeMap;
use dash_spv_crypto::crypto::byte_util::{Reversable, UInt256};
use dash_spv_crypto::llmq::LLMQEntry;
use dash_spv_crypto::network::LLMQType;
use dash_spv_crypto::tx::CoinbaseTransaction;
use dash_spv_crypto::util::data_ops::merkle_root_from_hashes;
use crate::{models, models::{masternode_entry::MasternodeEntry}};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
#[ferment_macro::export]
pub struct MasternodeList {
    pub block_hash: UInt256,
    pub known_height: u32,
    pub masternode_merkle_root: Option<UInt256>,
    pub llmq_merkle_root: Option<UInt256>,
    pub masternodes: BTreeMap<UInt256, MasternodeEntry>,
    pub quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
}

impl Default for MasternodeList {
    fn default() -> Self {
        Self {
            block_hash: UInt256::MAX,
            known_height: 0,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes: Default::default(),
            quorums: Default::default(),
        }
    }
}

impl<'a> std::fmt::Debug for MasternodeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeList")
            .field("block_hash", &self.block_hash)
            .field("known_height", &self.known_height)
            .field("masternode_merkle_root", &self.masternode_merkle_root.unwrap_or(UInt256::MIN))
            .field("llmq_merkle_root", &self.llmq_merkle_root.unwrap_or(UInt256::MIN))
            .field("masternodes", &self.masternodes)
            .field("quorums", &self.quorums)
            .finish()
    }
}

impl MasternodeList {
    pub fn empty(block_hash: UInt256, block_height: u32, quorums_active: bool) -> Self {
        Self::new(BTreeMap::default(), BTreeMap::new(), block_hash, block_height, quorums_active)
    }
    pub fn new(
        masternodes: BTreeMap<UInt256, MasternodeEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
        block_hash: UInt256,
        block_height: u32,
        quorums_active: bool,
    ) -> Self {
        let mut list = Self {
            quorums,
            block_hash,
            known_height: block_height,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes,
        };
        if let Some(hashes) = list.hashes_for_merkle_root(block_height) {
            //println!("MasternodeList: {}:{}: hashes_for_merkle_root: {:#?} masternodes: {:#?}", block_height, block_hash, hashes, list.masternodes);
            list.masternode_merkle_root = merkle_root_from_hashes(hashes);
        }
        if quorums_active {
            let hashes = list.hashes_for_quorum_merkle_root();
            //println!("MasternodeList: {}:{}: hashes_for_quorum_merkle_root: {:#?} quorums: {:#?}", block_height, block_hash, hashes, list.quorums);
            list.llmq_merkle_root = merkle_root_from_hashes(hashes);
        }
        list
    }

    pub fn quorums_count(&self) -> u64 {
        let mut count: u64 = 0;
        for entry in self.quorums.values() {
            count += entry.len() as u64;
        }
        count
    }

    pub fn hashes_for_merkle_root(&self, block_height: u32) -> Option<Vec<UInt256>> {
        (block_height != u32::MAX).then_some({
            let mut pro_tx_hashes = self.reversed_pro_reg_tx_hashes();
            pro_tx_hashes.sort_by(|&s1, &s2| s1.reversed().cmp(&s2.reversed()));
            pro_tx_hashes
                .iter()
                .map(|hash| (&self.masternodes[hash]).entry_hash_at(block_height))
                .collect::<Vec<_>>()
        })
    }

    fn hashes_for_quorum_merkle_root(&self) -> Vec<UInt256> {
        let mut llmq_commitment_hashes = self.quorums
            .values()
            .flat_map(|q_map| q_map.values().map(|entry| entry.entry_hash))
            .collect::<Vec<_>>();
        llmq_commitment_hashes.sort();
        llmq_commitment_hashes
    }

    pub fn masternode_for(&self, registration_hash: UInt256) -> Option<&MasternodeEntry> {
        self.masternodes.get(&registration_hash)
    }

    pub fn has_valid_mn_list_root(&self, tx: &CoinbaseTransaction) -> bool {
        // we need to check that the coinbase is in the transaction hashes we got back
        // and is in the merkle block
        if let Some(mn_merkle_root) = self.masternode_merkle_root {
            //println!("has_valid_mn_list_root: {} == {}", tx.merkle_root_mn_list, mn_merkle_root);
            tx.merkle_root_mn_list == mn_merkle_root
        } else {
            false
        }
    }

    pub fn has_valid_llmq_list_root(&self, tx: &CoinbaseTransaction) -> bool {
        let q_merkle_root = self.llmq_merkle_root;
        let ct_q_merkle_root = tx.merkle_root_llmq_list;
        let has_valid_quorum_list_root = q_merkle_root.is_some()
            && ct_q_merkle_root.is_some()
            && ct_q_merkle_root.unwrap() == q_merkle_root.unwrap();
        if !has_valid_quorum_list_root {
            warn!("LLMQ Merkle root not valid for DML on block {} version {} ({:?} wanted - {:?} calculated)",
                     tx.height,
                     tx.base.version,
                     tx.merkle_root_llmq_list,
                     self.llmq_merkle_root);
        }
        has_valid_quorum_list_root
    }

    pub fn quorum_entry_for_platform_with_quorum_hash(
        &self,
        quorum_hash: UInt256,
        llmq_type: LLMQType,
    ) -> Option<&LLMQEntry> {
        self.quorums
            .get(&llmq_type)?
            .values()
            .find(|&entry| entry.llmq_hash == quorum_hash)
    }

    pub fn quorum_entry_for_lock_request_id(
        &self,
        request_id: UInt256,
        llmq_type: LLMQType,
    ) -> Option<&LLMQEntry> {
        let mut first_quorum: Option<&LLMQEntry> = None;
        let mut lowest_value = UInt256::MAX;
        self.quorums.get(&llmq_type)?.values().for_each(|entry| {
            let ordering_hash = entry
                .ordering_hash_for_request_id(request_id, llmq_type)
                .reverse();
            if lowest_value > ordering_hash {
                lowest_value = ordering_hash;
                first_quorum = Some(entry);
            }
        });
        first_quorum
    }
    pub fn reversed_pro_reg_tx_hashes(&self) -> Vec<&UInt256> {
        self.masternodes.keys().collect::<Vec<&UInt256>>()
    }

    pub fn sorted_reversed_pro_reg_tx_hashes(&self) -> Vec<&UInt256> {
        let mut hashes = self.reversed_pro_reg_tx_hashes();
        hashes.sort_by(|&s1, &s2| s2.reversed().cmp(&s1.reversed()));
        hashes
    }

    pub fn has_masternode(&self, provider_registration_transaction_hash: UInt256) -> bool {
        self.masternodes.values().any(|node| node.provider_registration_transaction_hash == provider_registration_transaction_hash)
    }

    pub fn has_valid_masternode(&self, provider_registration_transaction_hash: UInt256) -> bool {
        self.masternodes.values()
            .find(|node| node.provider_registration_transaction_hash == provider_registration_transaction_hash)
            .map_or(false, |node| node.is_valid)
    }

    pub fn usage_info(&self, previous_quarters: [&Vec<Vec<MasternodeEntry>>; 3], skip_removed_masternodes: bool, quorum_count: usize) -> (Vec<MasternodeEntry>, Vec<MasternodeEntry>, Vec<Vec<MasternodeEntry>>) {
        let mut used_at_h_masternodes = Vec::<models::MasternodeEntry>::new();
        let mut used_at_h_indexed_masternodes = vec![Vec::<models::MasternodeEntry>::new(); quorum_count];
        for i in 0..quorum_count {
            // for quarters h - c, h -2c, h -3c
            for quarter in &previous_quarters {
                if let Some(quarter_nodes) = quarter.get(i) {
                    for node in quarter_nodes {
                        let hash = node.provider_registration_transaction_hash;
                        if (!skip_removed_masternodes || self.has_masternode(hash)) &&
                            self.has_valid_masternode(hash) {
                            if !used_at_h_masternodes.iter().any(|m| m.provider_registration_transaction_hash == hash) {
                                used_at_h_masternodes.push(node.clone());
                            }
                            if !used_at_h_indexed_masternodes[i].iter().any(|m| m.provider_registration_transaction_hash == hash) {
                                used_at_h_indexed_masternodes[i].push(node.clone());
                            }
                        }
                    }
                }
            }
        }
        let unused_at_h_masternodes = self.masternodes.values()
            .filter(|mn| mn.is_valid && !used_at_h_masternodes.iter().any(|node| mn.provider_registration_transaction_hash == node.provider_registration_transaction_hash))
            .cloned()
            .collect();
        (used_at_h_masternodes, unused_at_h_masternodes, used_at_h_indexed_masternodes)

    }
}

pub fn score_masternodes_map(
    masternodes: BTreeMap<UInt256, MasternodeEntry>,
    quorum_modifier: UInt256,
    block_height: u32,
    hpmn_only: bool,
) -> BTreeMap<UInt256, MasternodeEntry> {
    masternodes
        .into_iter()
        .filter_map(|(_, entry)|
            if !hpmn_only || entry.mn_type == crate::common::MasternodeType::HighPerformance {
                entry.score(quorum_modifier, block_height)
                    .map(|score| (score, entry))
            } else {
                None
            }
        )
        .collect()
}

#[cfg(all(test,feature = "serde"))]
impl From<crate::tests::serde_helper::MNList> for MasternodeList {
    fn from(value: crate::tests::serde_helper::MNList) -> Self {
        let block_hash = crate::tests::serde_helper::block_hash_to_block_hash(value.block_hash);
        let known_height = value.known_height;
        let masternode_merkle_root = Some(crate::tests::serde_helper::block_hash_to_block_hash(value.masternode_merkle_root));
        let llmq_merkle_root = Some(crate::tests::serde_helper::block_hash_to_block_hash(value.quorum_merkle_root));
        let masternodes = crate::tests::serde_helper::nodes_to_masternodes(value.mn_list);
        let quorums = crate::tests::serde_helper::quorums_to_quorums_map(value.new_quorums);
        Self {
            block_hash,
            known_height,
            masternode_merkle_root,
            llmq_merkle_root,
            masternodes,
            quorums
        }
    }
}