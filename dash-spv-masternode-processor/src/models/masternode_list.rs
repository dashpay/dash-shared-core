use std::cmp::Ordering;
use std::collections::BTreeMap;
use dash_spv_crypto::blake3;
use dash_spv_crypto::crypto::byte_util::{sup, Reversed};
use dash_spv_crypto::llmq::entry::LLMQEntry;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_crypto::tx::CoinbaseTransaction;
use dash_spv_crypto::util::data_ops::merkle_root_from_hashes;
use crate::{models, models::masternode_entry::MasternodeEntry};
use crate::common::SocketAddress;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
#[ferment_macro::export]
pub struct MasternodeList {
    pub block_hash: [u8; 32],
    pub known_height: u32,
    pub masternode_merkle_root: Option<[u8; 32]>,
    pub llmq_merkle_root: Option<[u8; 32]>,
    pub masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
    pub quorums: BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>,
}

impl Default for MasternodeList {
    fn default() -> Self {
        Self {
            block_hash: [!0; 32],
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
            .field("masternode_merkle_root", &self.masternode_merkle_root.unwrap_or([0u8; 32]))
            .field("llmq_merkle_root", &self.llmq_merkle_root.unwrap_or([0u8; 32]))
            .field("masternodes", &self.masternodes)
            .field("quorums", &self.quorums)
            .finish()
    }
}

impl MasternodeList {
    pub fn empty(block_hash: [u8; 32], block_height: u32, quorums_active: bool) -> Self {
        Self::new(BTreeMap::default(), BTreeMap::new(), block_hash, block_height, quorums_active)
    }
    pub fn new(
        masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>,
        block_hash: [u8; 32],
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
    pub fn with_merkle_roots(
        masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>,
        block_hash: [u8; 32],
        block_height: u32,
        masternode_merkle_root: [u8; 32],
        llmq_merkle_root: Option<[u8; 32]>,
    ) -> Self {
        Self {
            quorums,
            block_hash,
            known_height: block_height,
            masternode_merkle_root: Some(masternode_merkle_root),
            llmq_merkle_root,
            masternodes,
        }
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

    pub fn reversed_pro_reg_tx_hashes(&self) -> Vec<&[u8; 32]> {
        self.masternodes.keys().collect::<Vec<&[u8; 32]>>()
    }

    pub fn sorted_reversed_pro_reg_tx_hashes(&self) -> Vec<&[u8; 32]> {
        let mut hashes = self.reversed_pro_reg_tx_hashes();
        hashes.sort_by(|&s1, &s2| s2.reversed().cmp(&s1.reversed()));
        hashes
    }

    pub fn masternode_for(&self, registration_hash: [u8; 32]) -> Option<&MasternodeEntry> {
        self.masternodes.get(&registration_hash)
    }
    pub fn quorum_entry_for_platform_with_quorum_hash(
        &self,
        quorum_hash: [u8; 32],
        llmq_type: LLMQType,
    ) -> Option<&LLMQEntry> {
        self.quorums
            .get(&llmq_type)?
            .values()
            .find(|&entry| entry.llmq_hash == quorum_hash)
    }

    pub fn quorum_entry_for_lock_request_id(
        &self,
        request_id: [u8; 32],
        llmq_type: LLMQType,
    ) -> Option<&LLMQEntry> {
        let mut first_quorum: Option<&LLMQEntry> = None;
        let mut lowest_value = [!0; 32];
        self.quorums.get(&llmq_type)?.values().for_each(|entry| {
            let ordering_hash = entry
                .ordering_hash_for_request_id(request_id, llmq_type)
                .reversed();
            if lowest_value > ordering_hash {
                lowest_value = ordering_hash;
                first_quorum = Some(entry);
            }
        });
        first_quorum
    }

    pub fn has_valid_masternode(&self, provider_registration_transaction_hash: [u8; 32]) -> bool {
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
#[ferment_macro::export]
impl MasternodeList {
    pub fn hashes_for_merkle_root(&self, block_height: u32) -> Option<Vec<[u8; 32]>> {
        (block_height != u32::MAX).then_some({
            let mut pro_tx_hashes = self.reversed_pro_reg_tx_hashes();
            pro_tx_hashes.sort_by(|&s1, &s2| s1.reversed().cmp(&s2.reversed()));
            pro_tx_hashes
                .into_iter()
                .map(|hash| (&self.masternodes[hash]).entry_hash_at(block_height))
                .collect::<Vec<_>>()
        })
    }

    pub fn hashes_for_quorum_merkle_root(&self) -> Vec<[u8; 32]> {
        let mut llmq_commitment_hashes = self.quorums
            .values()
            .flat_map(|q_map| q_map.values().map(|entry| entry.entry_hash))
            .collect::<Vec<_>>();
        llmq_commitment_hashes.sort();
        llmq_commitment_hashes
    }
    pub fn masternode_by_pro_reg_tx_hash(&self, registration_hash: [u8; 32]) -> Option<MasternodeEntry> {
        self.masternodes.get(&registration_hash).cloned()
    }

    pub fn platform_llmq_with_quorum_hash(&self, hash: [u8; 32], llmq_type: LLMQType) -> Option<LLMQEntry> {
        self.quorum_entry_for_platform_with_quorum_hash(hash, llmq_type)
            .cloned()
    }
    pub fn lock_llmq_request_id(
        &self,
        request_id: [u8; 32],
        llmq_type: LLMQType,
    ) -> Option<LLMQEntry> {
        self.quorum_entry_for_lock_request_id(request_id, llmq_type)
            .cloned()
    }
    pub fn has_masternode(&self, provider_registration_transaction_hash: [u8; 32]) -> bool {
        self.masternodes.values().any(|node| node.provider_registration_transaction_hash == provider_registration_transaction_hash)
    }
    pub fn has_masternode_at_location(&self, address: [u8; 16], port: u16) -> bool {
        self.masternodes.values()
            .any(|node| node.socket_address.ip_address == address && node.socket_address.port == port)
    }
    pub fn masternode_count(&self) -> usize {
        self.masternodes.len()
    }
    pub fn quorums_count(&self) -> u64 {
        let mut count: u64 = 0;
        for entry in self.quorums.values() {
            count += entry.len() as u64;
        }
        count
    }

    pub fn has_unverified_rotated_quorums(&self, chain_type: ChainType) -> bool {
        let isd_llmq_type = chain_type.isd_llmq_type();
        self.quorums.get(&isd_llmq_type)
            .map(|q| q.values().any(|llmq| !llmq.verified))
            .unwrap_or(false)
    }
    pub fn has_unverified_regular_quorums(&self, chain_type: ChainType) -> bool {
        let isd_llmq_type = chain_type.isd_llmq_type();
        self.quorums.get(&isd_llmq_type)
            .map(|q| q.values().any(|llmq| !llmq.verified))
            .unwrap_or(false)
    }

    pub fn ordered_quorums_for_is_lock(&self, quorum_type: LLMQType, request_id: [u8; 32]) -> Vec<LLMQEntry> {
        use std::cmp::Ordering;
        let quorums_for_is = self.quorums
            .get(&quorum_type)
            .map(|inner_map| inner_map.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let ordered_quorum_map = quorums_for_is.into_iter()
            .fold(BTreeMap::new(), |mut acc, entry| {
                let ordering_hash = entry
                    .ordering_hash_for_request_id(request_id, quorum_type)
                    .reversed();
                acc.insert(entry, ordering_hash);
                acc
            });
        let mut ordered_quorums: Vec<_> = ordered_quorum_map.into_iter().collect();
        ordered_quorums.sort_by(|(_, hash1), (_, hash2)| {
            if sup(*hash1, hash2) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });
        ordered_quorums.into_iter().map(|(entry, _)| entry).collect()
    }

    pub fn peer_addresses_with_connectivity_nonce(&self, nonce: u64, max_count: usize) -> Vec<SocketAddress> {
        let registration_transaction_hashes: Vec<_> = self.masternodes.keys().cloned().collect();
        let mut sorted_hashes = registration_transaction_hashes.clone();
        sorted_hashes.sort_by(|hash1, hash2| {
            let nonce_le = nonce.to_le_bytes();
            let mut hash1_nonce = hash1.to_vec();
            hash1_nonce.extend_from_slice(&nonce_le);
            let mut hash2_nonce = hash2.to_vec();
            hash2_nonce.extend_from_slice(&nonce_le);
            let hash1_blake = blake3(&hash1_nonce);
            let hash2_blake = blake3(&hash2_nonce);
            if sup(hash1_blake, &hash2_blake) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });
        sorted_hashes
            .into_iter()
            .take(max_count.min(self.masternodes.len()))
            .filter_map(|hash| self.masternodes.get(&hash)
                .and_then(|entry| entry.is_valid.then_some(entry.socket_address.clone())))
            .collect()
    }
    pub fn provider_tx_ordered_hashes(&self) -> Vec<[u8; 32]> {
        let mut vec = Vec::from_iter(self.masternodes.keys().cloned());
        vec.sort_by(|hash1, hash2| if sup(*hash1, hash2) { Ordering::Less } else { Ordering::Greater });
        vec
    }

    pub fn compare_provider_tx_ordered_hashes(&self, list: MasternodeList) -> bool {
        let list_hashes = list.provider_tx_ordered_hashes();
        self.provider_tx_ordered_hashes().eq(&list_hashes)
    }

    // pub fn merged_with(&self, masternode_list: MasternodeList, height: u32) -> MasternodeList {
    //     let mut list = self.clone();
    //     // list.masternodes.entry()
    //     self.masternodes.iter().for_each(|(pro_tx_hash, entry)| {
    //         if let Some(new_entry) = masternode_list.masternodes.get(pro_tx_hash) {
    //             entry.merged_with_entry(new_entry, height);
    //         }
    //     });
    //
    //
    // }
    //     self.masternodes.iter_mut().for_each(|(hash, node)| {
    //         if let Some(new_entry) = masternode_list.masternodes.get(hash) {
    //             node.merge_with_entry(new_entry, height);
    //         }
    //     });
    //     self.quorums.iter_mut().for_each(|(quorum_type, quorums)| {
    //         quorums.iter_mut().for_each(|(hash, entry)| {
    //             if !entry.verified {
    //                 if let Some(new_entry) = masternode_list.quorums.get(quorum_type).and_then(|q| q.get(hash)) {
    //                     entry.merge_with_quorum_entry(new_entry);
    //                 }
    //             }
    //         });
    //     });
    //     self
    // }
}
#[ferment_macro::export]
pub fn new(
    masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
    quorums: BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>,
    block_hash: [u8; 32],
    block_height: u32,
    quorums_active: bool,
) -> MasternodeList {
    MasternodeList::new(masternodes, quorums, block_hash, block_height, quorums_active)
}

#[ferment_macro::export]
pub fn from_entry_pool(
    block_hash: [u8; 32],
    block_height: u32,
    mn_merkle_root: [u8; 32],
    llmq_merkle_root: Option<[u8; 32]>,
    masternodes: Vec<MasternodeEntry>,
    quorums: Vec<LLMQEntry>,
) -> MasternodeList {
    let masternodes = masternodes.into_iter().map(|entry| (entry.provider_registration_transaction_hash, entry)).collect();
    let quorums = quorums.iter().fold(BTreeMap::new(), |mut acc, entry| {
        acc.entry(entry.llmq_type)
            .or_insert_with(BTreeMap::new)
            .insert(entry.llmq_hash, entry.clone());
        acc
    });
    MasternodeList::with_merkle_roots(masternodes, quorums, block_hash, block_height, mn_merkle_root, llmq_merkle_root)
}

pub fn score_masternodes_map(
    masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
    quorum_modifier: [u8; 32],
    block_height: u32,
    hpmn_only: bool,
) -> BTreeMap<[u8; 32], MasternodeEntry> {
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