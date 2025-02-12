use std::cmp::Ordering;
use std::collections::BTreeMap;
use hashes::hex::ToHex;
use dash_spv_crypto::blake3;
use dash_spv_crypto::crypto::byte_util::{sup, Reversed, Zeroable};
use dash_spv_crypto::llmq::entry::LLMQEntry;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_crypto::tx::CoinbaseTransaction;
use dash_spv_crypto::util::data_ops::merkle_root_from_hashes;
use crate::models::masternode_entry::MasternodeEntry;
use crate::common::SocketAddress;
use crate::util::formatter::CustomFormatter;

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
        list.masternode_merkle_root = list.calculate_masternodes_merkle_root(block_height);
        if quorums_active {
            list.llmq_merkle_root = list.calculate_llmq_merkle_root();
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

    pub fn short_description(&self) -> String {
        format!("\t\t{}: {}:\n\t\t\tmn: \n\t\t\t\troot: {}\n\t\t\t\tcount: {}\n\t\t\tllmq:\n\t\t\t\troot: {}\n\t\t\t\tdesc:\n{}\n",
                self.known_height,
                self.block_hash.to_hex(),
                self.masternode_merkle_root.map_or("None".to_string(), |r| r.to_hex()),
                self.masternode_count(),
                self.llmq_merkle_root.map_or("None".to_string(), |r| r.to_hex()),
                self.quorums_short_description())
    }

    pub fn quorums_short_description(&self) -> String {
        self.quorums.iter().fold(String::new(), |mut acc, (ty, map)| {
            let s = map.iter().fold(String::new(), |mut acc, (hash, q)| {
                acc.push_str(format!("\t\t\t{}: {}\n", q.llmq_hash_hex(), q.verified).as_str());
                acc
            });
            acc.push_str(format!("\t\t{ty}: \n{s}").as_str());
            acc
        })
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
                     tx.merkle_root_llmq_list.map(|q| q.to_hex()).unwrap_or("None".to_string()),
                     self.llmq_merkle_root.map(|q| q.to_hex()).unwrap_or("None".to_string()));
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
    pub fn quorum_entry_of_type_for_quorum_hash(
        &self,
        llmq_type: LLMQType,
        quorum_hash: [u8; 32],
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
                .ordering_hash_for_request_id(request_id)
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
        let mut used_at_h_masternodes = Vec::<MasternodeEntry>::new();
        let mut used_at_h_indexed_masternodes = vec![Vec::<MasternodeEntry>::new(); quorum_count];
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

    pub fn print_description(&self) {
        println!("{}", self.format());
    }

    pub fn calculate_masternodes_merkle_root(&self, block_height: u32) -> Option<[u8; 32]> {
        self.hashes_for_merkle_root(block_height)
            .and_then(merkle_root_from_hashes)
    }
    pub fn calculate_masternodes_merkle_root_with_block_height_lookup<BL: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>(
        &self,
        context: *const std::os::raw::c_void,
        block_height_lookup: BL
    ) -> Option<[u8; 32]> {
        self.hashes_for_merkle_root_with_block_height_lookup(context, block_height_lookup)
            .and_then(merkle_root_from_hashes)
    }

    pub fn calculate_llmq_merkle_root(&self) -> Option<[u8; 32]> {
        merkle_root_from_hashes(self.hashes_for_quorum_merkle_root())
    }

    // pub fn reversed_pro_reg_tx_hashes_cloned(&self) -> Vec<[u8; 32]> {
    //     self.masternodes.keys().cloned().collect()
    // }
    //
    // pub fn sorted_reversed_pro_reg_tx_hashes_cloned(&self) -> Vec<[u8; 32]> {
    //     let mut hashes = self.reversed_pro_reg_tx_hashes_cloned();
    //     hashes.sort_by(|&s1, &s2| s2.reversed().cmp(&s1.reversed()));
    //     hashes
    // }

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

    pub fn hashes_for_merkle_root_with_block_height_lookup<BL: Fn(*const std::os::raw::c_void, [u8; 32]) -> u32>(
        &self,
        context: *const std::os::raw::c_void,
        block_height_lookup: BL
    ) -> Option<Vec<[u8; 32]>> {
        let pro_tx_hashes = self.provider_tx_ordered_hashes();
        let block_height = block_height_lookup(context, self.block_hash);
        if block_height == u32::MAX {
            println!("Block height lookup queried an unknown block {}", self.block_hash.to_hex());
            return None; //this should never happen
        }
        Some(pro_tx_hashes
            .into_iter()
            .map(|hash| (&self.masternodes[&hash]).entry_hash_at(block_height))
            .collect::<Vec<_>>())
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
        self.quorum_entry_of_type_for_quorum_hash(llmq_type, hash)
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
            .map(|q| q.values().any(LLMQEntry::is_not_verified))
            .unwrap_or(false)
    }
    pub fn has_unverified_regular_quorums(&self, chain_type: ChainType) -> bool {
        let isd_llmq_type = chain_type.isd_llmq_type();
        self.quorums.get(&isd_llmq_type)
            .map(|q| q.values().any(LLMQEntry::is_not_verified))
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
                    .ordering_hash_for_request_id(request_id)
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
        vec.sort_by(|hash1, hash2| if sup(*hash1, hash2) { Ordering::Greater } else { Ordering::Less });
        // vec.sort_by(|hash1, hash2| if sup(*hash1, hash2) { Ordering::Less } else { Ordering::Greater });
        vec
    }
    pub fn reversed_pro_reg_tx_hashes_cloned(&self) -> Vec<[u8; 32]> {
        let mut vec = Vec::from_iter(self.masternodes.keys().cloned());
        vec.sort();
        vec
    }

    pub fn compare_provider_tx_ordered_hashes(&self, list: MasternodeList) -> bool {
        let list_hashes = list.provider_tx_ordered_hashes();
        self.provider_tx_ordered_hashes().eq(&list_hashes)
    }

    pub fn compare_masternodes(&self, list: MasternodeList) -> bool {
        let mut vec1 = Vec::from_iter(self.masternodes.values());
        vec1.sort();
        let mut vec2 = Vec::from_iter(list.masternodes.values());
        vec2.sort();
        vec1.eq(&vec2)
    }

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
    let masternodes = masternode_vec_to_map(masternodes);
    let quorums = quorum_vec_to_map(quorums);
    let list = MasternodeList::with_merkle_roots(masternodes, quorums, block_hash, block_height, mn_merkle_root, llmq_merkle_root);
    //println!("from_entry_pool: {}", list.format());
    list
}

pub fn quorum_vec_to_map(vec: Vec<LLMQEntry>) -> BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>> {
    vec.into_iter()
        .fold(BTreeMap::new(), |mut acc, entry| {
            acc.entry(entry.llmq_type.clone())
                .or_insert_with(BTreeMap::new)
                .insert(entry.llmq_hash, entry);
            acc
        })
}
pub fn masternode_vec_to_map(vec: Vec<MasternodeEntry>) -> BTreeMap<[u8; 32], MasternodeEntry> {
    vec.into_iter().map(|entry| (entry.provider_registration_transaction_hash.reversed(), entry)).collect()
}

pub fn score_masternodes_map(
    masternodes: &BTreeMap<[u8; 32], MasternodeEntry>,
    quorum_modifier: [u8; 32],
    work_block_height: u32,
    hpmn_only: bool,
) -> Vec<([u8; 32], MasternodeEntry)> {
    let llmq_height = work_block_height + 8;
    masternodes.iter().filter_map(|(_, entry)| {
        let is_scorable = (!hpmn_only || entry.mn_type.is_hpmn()) && entry.is_valid_at(work_block_height) && !entry.confirmed_hash.is_zero() && entry.confirmed_hash_at(llmq_height).is_some();
        if is_scorable {
            entry.score(quorum_modifier, work_block_height, entry.confirmed_hash_hashed_with_pro_reg_tx_hash_at(llmq_height))
                .map(|score| (score, entry.clone()))
        } else {
            None
        }
    }).collect()
}

#[cfg(all(feature = "serde", feature = "test-helpers"))]
impl From<crate::tests::serde_helper::MNList> for MasternodeList {
    fn from(value: crate::tests::serde_helper::MNList) -> Self {
        use dash_spv_crypto::crypto::byte_util::UInt256;
        use hashes::hex::FromHex;
        let block_hash = UInt256::from_hex(value.block_hash.as_str()).unwrap().0;
        let known_height = value.known_height;
        let masternode_merkle_root = Some(UInt256::from_hex(value.masternode_merkle_root.as_str()).unwrap().0);
        let llmq_merkle_root = Some(UInt256::from_hex(value.quorum_merkle_root.as_str()).unwrap().0);
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