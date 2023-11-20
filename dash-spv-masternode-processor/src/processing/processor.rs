use std::collections::{BTreeMap, HashSet};
use byte::BytesExt;
use crate::{common, models, ok_or_return_processing_error, processing};
use crate::chain::common::{LLMQType, LLMQParams};
use crate::common::LLMQSnapshotSkipMode;
use crate::crypto::{byte_util::{Reversable, Zeroable}, UInt256, UInt768};
use crate::models::{LLMQModifierType, LLMQVerificationContext};
use crate::processing::{CoreProvider, CoreProviderError, LLMQValidationStatus, MasternodeProcessorCache, ProcessingError};

pub enum LLMQQuarterType {
    AtHeightMinus3Cycles,
    AtHeightMinus2Cycles,
    AtHeightMinusCycle,
    New,
}

#[derive(Clone, Copy)]
pub enum LLMQQuarterReconstructionType<'a> {
    Snapshot {
        cached_llmq_snapshots: &'a BTreeMap<UInt256, models::LLMQSnapshot>
    },
    New {
        previous_quarters: [&'a Vec<Vec<models::MasternodeEntry>>; 3],
        skip_removed_masternodes: bool,
    }
}

pub enum LLMQQuarterReconstructionInfo {
    Snapshot(models::MasternodeList, models::LLMQSnapshot, UInt256),
    New(models::MasternodeList, UInt256)
}

// https://github.com/rust-lang/rfcs/issues/2770
#[repr(C)]
#[derive(Debug)]
pub struct MasternodeProcessor {
    pub provider: Box<dyn CoreProvider>,
}

impl MasternodeProcessor {
    pub fn new<T: CoreProvider + 'static>(provider: T) -> Self {
        Self { provider: Box::new(provider) }
    }
}

impl MasternodeProcessor {

    pub fn llmq_modifier_type_for(&self, llmq_type: LLMQType, work_block_hash: UInt256, work_block_height: u32, cached_cl_signatures: &BTreeMap<UInt256, UInt768>) -> LLMQModifierType {
        if self.provider.chain_type().core20_is_active_at(work_block_height) {
            if let Ok(work_block_hash) = self.provider.lookup_block_hash_by_height(work_block_height) {
                if let Ok(best_cl_signature) = self.provider.find_cl_signature(work_block_hash, cached_cl_signatures) {
                    return LLMQModifierType::CoreV20(llmq_type, work_block_height, best_cl_signature);
                } else {
                    println!("llmq_modifier_type: clsig not found for block hash: {} ({})", work_block_hash, work_block_hash.reversed());
                }
            } else {
                println!("llmq_modifier_type: block not found for height: {}", work_block_height);
            }
        }
        LLMQModifierType::PreCoreV20(llmq_type, work_block_hash)
    }

    pub fn get_list_diff_result_with_base_lookup(
        &self,
        list_diff: models::MNListDiff,
        verification_context: LLMQVerificationContext,
        cache: &mut MasternodeProcessorCache,
    ) -> processing::MNListDiffResult {
        let base_list = self.provider.find_masternode_list(
            list_diff.base_block_hash,
            &cache.mn_lists,
            &mut cache.needed_masternode_lists,
        );
        self.get_list_diff_result(base_list.ok(), list_diff, verification_context, cache)
    }

    fn cache_masternode_list(
        &self,
        block_hash: UInt256,
        list: models::MasternodeList,
        cache: &mut MasternodeProcessorCache,
    ) {
        // It's good to cache lists to use it inside processing session
        // Here we use opaque-like pointer which we initiate on the C-side to sync its lifetime with runtime
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_masternode_list_to_json(&list, self.lookup_block_height_by_hash(block_hash));
        cache.add_masternode_list(block_hash, list);
        // Here we just store it in the C-side ()
        // self.save_masternode_list(block_hash, &masternode_list);
    }

    pub fn get_list_diff_result(
        &self,
        base_list: Option<models::MasternodeList>,
        list_diff: models::MNListDiff,
        verification_context: LLMQVerificationContext,
        cache: &mut MasternodeProcessorCache,
    ) -> processing::MNListDiffResult {
        let skip_removed_masternodes = list_diff.should_skip_removed_masternodes();
        let base_block_hash = list_diff.base_block_hash;
        let block_hash = list_diff.block_hash;
        let block_height = list_diff.block_height;
        let quorums_cl_sigs = list_diff.quorums_cls_sigs;
        let (base_masternodes, base_quorums) = match base_list {
            Some(list) => (list.masternodes, list.quorums),
            None => (BTreeMap::new(), BTreeMap::new()),
        };
        let mut coinbase_transaction = list_diff.coinbase_transaction;
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        let (added_masternodes, modified_masternodes, masternodes) = self.classify_masternodes(
            base_masternodes,
            list_diff.added_or_modified_masternodes,
            list_diff.deleted_masternode_hashes,
            block_height,
            block_hash,
        );
        let mut added_quorums = list_diff.added_quorums;

        let has_valid_quorums = self.verify_added_quorums(verification_context, &mut added_quorums, skip_removed_masternodes, &quorums_cl_sigs, cache);
        let (added_quorums, quorums) = self.process_quorums(
            base_quorums,
            added_quorums,
            list_diff.deleted_quorums,
        );
        let masternode_list = models::MasternodeList::new(
            masternodes,
            quorums,
            block_hash,
            block_height,
            quorums_active,
        );
        let merkle_tree = common::MerkleTree {
            tree_element_count: list_diff.total_transactions,
            hashes: list_diff.merkle_hashes,
            flags: list_diff.merkle_flags.as_slice(),
        };
        self.cache_masternode_list(block_hash, masternode_list.clone(), cache);
        let needed_masternode_lists = cache.needed_masternode_lists.clone();
        cache.needed_masternode_lists.clear();
        let has_found_coinbase = coinbase_transaction.has_found_coinbase(&merkle_tree.hashes);
        let has_valid_coinbase = self.provider.lookup_merkle_root_by_hash(block_hash)
            .map_or(false, |desired_merkle_root| merkle_tree.has_root(desired_merkle_root));
        let has_valid_mn_list_root = masternode_list.has_valid_mn_list_root(&coinbase_transaction);
        let has_valid_llmq_list_root = !quorums_active || masternode_list.has_valid_llmq_list_root(&coinbase_transaction);
        let result = processing::MNListDiffResult {
            base_block_hash,
            block_hash,
            has_found_coinbase,
            has_valid_coinbase,
            has_valid_mn_list_root,
            has_valid_llmq_list_root,
            has_valid_quorums,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            added_quorums,
            needed_masternode_lists
        };
        result
    }

    #[allow(clippy::type_complexity)]
    pub fn classify_masternodes(
        &self,
        base_masternodes: BTreeMap<UInt256, models::MasternodeEntry>,
        added_or_modified_masternodes: BTreeMap<UInt256, models::MasternodeEntry>,
        deleted_masternode_hashes: Vec<UInt256>,
        block_height: u32,
        block_hash: UInt256,
    ) -> (
        BTreeMap<UInt256, models::MasternodeEntry>,
        BTreeMap<UInt256, models::MasternodeEntry>,
        BTreeMap<UInt256, models::MasternodeEntry>,
    ) {
        let added_masternodes = added_or_modified_masternodes
            .iter()
            .filter(|(k, _)| !base_masternodes.contains_key(k))
            .map(|(k, v)| (*k, v.clone()))
            .collect::<BTreeMap<_, _>>();

        let mut modified_masternodes = added_or_modified_masternodes
            .iter()
            .filter(|(k, _)| base_masternodes.contains_key(k))
            .map(|(k, v)| (*k, v.clone()))
            .collect::<BTreeMap<_, _>>();

        let mut masternodes = if !base_masternodes.is_empty() {
            let mut old_masternodes = base_masternodes;
            for hash in deleted_masternode_hashes {
                old_masternodes.remove(&hash.reversed());
            }
            old_masternodes.extend(added_masternodes.clone());
            old_masternodes
        } else {
            added_masternodes.clone()
        };

        for (hash, modified) in &mut modified_masternodes {
            if let Some(old) = masternodes.get_mut(hash) {
                if old.update_height < modified.update_height {
                    modified.update_with_previous_entry(old, block_height, block_hash);
                    if !old.confirmed_hash.is_zero() &&
                        old.known_confirmed_at_height.is_some() &&
                        old.known_confirmed_at_height.unwrap() > block_height {
                        old.known_confirmed_at_height = Some(block_height);
                    }
                }
                masternodes.insert(*hash, modified.clone());
            }
        }
        (added_masternodes, modified_masternodes, masternodes)
    }

    fn find_cl_signature_at_index(quorums_cl_sigs: &BTreeMap<UInt768, HashSet<u16>>, index: u16) -> Option<UInt768> {
        quorums_cl_sigs.iter().find_map(|(signature, index_set)|
            if index_set.iter().any(|i| *i == index) { Some(*signature) } else { None })
    }

    #[allow(clippy::type_complexity)]
    fn verify_added_quorums(
        &self,
        verification_context: LLMQVerificationContext,
        added_quorums: &mut Vec<models::LLMQEntry>,
        skip_removed_masternodes: bool,
        quorums_cl_sigs: &BTreeMap<UInt768, HashSet<u16>>,
        cache: &mut MasternodeProcessorCache,
    ) -> bool {
        let mut has_valid_quorums = true;
        if verification_context.should_validate_quorums() {
            added_quorums
                .iter_mut()
                .enumerate()
                .for_each(|(index, quorum)| {
                    if let Some(signature) = Self::find_cl_signature_at_index(quorums_cl_sigs, index as u16) {
                        let llmq_height = self.provider.lookup_block_height_by_hash(quorum.llmq_hash);
                        let work_block_height = llmq_height - 8;
                        if llmq_height != u32::MAX {
                            if let Ok(work_block_hash) = self.provider.lookup_block_hash_by_height(work_block_height) {
                                cache.cl_signatures.insert(work_block_hash, signature);
                            } else {
                                warn!("unknown hash for {}", work_block_height);
                            }
                        } else {
                            warn!("unknown height for {}", quorum.llmq_hash);
                        }
                    }
                    if verification_context.should_validate_quorum_of_type(quorum.llmq_type, self.provider.chain_type()) {
                        match self.validate_quorum(quorum, skip_removed_masternodes, cache) {
                            Ok(LLMQValidationStatus::Verified | LLMQValidationStatus::NoMasternodeList) |
                            Err(CoreProviderError::NoMasternodeList) => {
                                has_valid_quorums &= true;
                            },
                            Err(CoreProviderError::BlockHashNotFoundAt(height)) => {
                                error!("missing block for height: {}", height);
                                panic!("missing block for height: {}", height)
                            },
                            Ok(status) => {
                                warn!("Error quorum validation: ({:?})", status);
                                has_valid_quorums &= false;
                            },
                            Err(error) => {
                                warn!("Error provider: ({:?})", error);
                                has_valid_quorums &= false;
                            }
                        }
                    }
                })
        }
        has_valid_quorums
    }

    pub fn process_quorums(
        &self,
        mut base_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, models::LLMQEntry>>,
        added_quorums: Vec<models::LLMQEntry>,
        deleted_quorums: BTreeMap<LLMQType, Vec<UInt256>>,
    ) -> (
        Vec<models::LLMQEntry>,
        BTreeMap<LLMQType, BTreeMap<UInt256, models::LLMQEntry>>,
    ) {
        for (llmq_type, keys_to_delete) in &deleted_quorums {
            if let Some(llmq_map) = base_quorums.get_mut(llmq_type) {
                for key in keys_to_delete {
                    llmq_map.remove(key);
                }
            }
        }
        added_quorums.iter().for_each(|llmq_entry| {
            base_quorums.entry(llmq_entry.llmq_type.clone())
                .or_insert_with(BTreeMap::new)
                .insert(llmq_entry.llmq_hash, llmq_entry.clone());
        });
        (added_quorums, base_quorums)
    }

    fn find_valid_masternodes_for_quorum(&self, quorum: &models::LLMQEntry, block_height: u32, skip_removed_masternodes: bool, masternodes: BTreeMap<UInt256, models::MasternodeEntry>, cache: &mut MasternodeProcessorCache) -> Result<Vec<models::MasternodeEntry>, CoreProviderError> {
        if quorum.index.is_some() {
            self.get_rotated_masternodes_for_quorum(quorum.llmq_type, quorum.llmq_hash, block_height, skip_removed_masternodes, cache)
        } else {
            self.get_non_rotated_masternodes_for_quorum(quorum.llmq_type, quorum.llmq_hash, block_height, quorum, masternodes, cache)
        }
    }

    pub fn validate_quorum(&self, quorum: &mut models::LLMQEntry, skip_removed_masternodes: bool, cache: &mut MasternodeProcessorCache) -> Result<LLMQValidationStatus, CoreProviderError> {
        let llmq_block_hash = quorum.llmq_hash;
        self.provider.find_masternode_list(llmq_block_hash, &cache.mn_lists, &mut cache.needed_masternode_lists)
            .and_then(|models::MasternodeList { masternodes, .. }| {
                let block_height = self.provider.lookup_block_height_by_hash(llmq_block_hash);
                self.find_valid_masternodes_for_quorum(quorum, block_height, skip_removed_masternodes, masternodes, cache)
                    .and_then(|valid_masternodes| quorum.verify(valid_masternodes, block_height))
            })
    }

    fn get_non_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: UInt256,
        block_height: u32,
        quorum: &models::LLMQEntry,
        masternodes: BTreeMap<UInt256, models::MasternodeEntry>,
        cache: &mut MasternodeProcessorCache
    ) -> Result<Vec<models::MasternodeEntry>, CoreProviderError> {
        Ok(models::MasternodeList::get_masternodes_for_quorum(
            quorum,
            self.provider.chain_type(),
            masternodes,
            block_height,
            self.llmq_modifier_type_for(llmq_type, block_hash, block_height - 8, &cache.cl_signatures)))
    }

    fn sort_scored_masternodes(scored_masternodes: BTreeMap<UInt256, models::MasternodeEntry>) -> Vec<models::MasternodeEntry> {
        let mut v = Vec::from_iter(scored_masternodes);
        v.sort_by(|(s1, _), (s2, _)| s2.reversed().cmp(&s1.reversed()));
        v.into_iter().map(|(s, node)| node).collect()
    }

    pub fn valid_masternodes_for_rotated_quorum_map(
        masternodes: Vec<models::MasternodeEntry>,
        quorum_modifier: UInt256,
        block_height: u32,
    ) -> Vec<models::MasternodeEntry> {
        let scored_masternodes = masternodes
            .into_iter()
            .filter_map(|entry| models::MasternodeList::masternode_score(&entry, quorum_modifier, block_height)
                .map(|score| (score, entry)))
            .collect::<BTreeMap<_, _>>();
        Self::sort_scored_masternodes(scored_masternodes)
    }

    fn order(work_block_height: u32, quorum_modifier: UInt256, used_at_h_masternodes: Vec<models::MasternodeEntry>, unused_at_h_masternodes: Vec<models::MasternodeEntry>) -> Vec<models::MasternodeEntry> {
        let sorted_used_mns_list = MasternodeProcessor::valid_masternodes_for_rotated_quorum_map(
            used_at_h_masternodes,
            quorum_modifier,
            work_block_height);
        let sorted_unused_mns_list = MasternodeProcessor::valid_masternodes_for_rotated_quorum_map(
            unused_at_h_masternodes,
            quorum_modifier,
            work_block_height);
        let mut sorted_combined_mns_list = sorted_unused_mns_list;
        sorted_combined_mns_list.extend(sorted_used_mns_list);
        sorted_combined_mns_list
    }
    pub fn apply_skip_strategy_for_snapshot(
        snapshot: models::LLMQSnapshot,
        sorted_combined_mns_list: Vec<models::MasternodeEntry>,
        quorum_count: usize,
        quarter_size: usize,
    ) -> Vec<Vec<models::MasternodeEntry>> {
        let mut quarter_quorum_members = vec![Vec::<models::MasternodeEntry>::new(); quorum_count];
        match snapshot.skip_list_mode {
            LLMQSnapshotSkipMode::NoSkipping => {
                let mut iter = sorted_combined_mns_list.iter();
                (0..quorum_count).for_each(|i| {
                    let mut quarter = Vec::<models::MasternodeEntry>::new();
                    while quarter.len() < quarter_size {
                        if let Some(node) = iter.next() {
                            quarter.push(node.clone());
                        } else {
                            iter = sorted_combined_mns_list.iter();
                        }
                    }
                    quarter_quorum_members[i] = quarter;
                });
            }
            LLMQSnapshotSkipMode::SkipFirst => {
                let mut first_entry_index = 0;
                let mut processed_skip_list = Vec::<i32>::new();
                for &s in &snapshot.skip_list {
                    if first_entry_index == 0 {
                        first_entry_index = s;
                        processed_skip_list.push(s);
                    } else {
                        processed_skip_list.push(first_entry_index + s);
                    }
                }
                let mut idx = 0;
                let mut idxk = 0;
                for i in 0..quorum_count {
                    while quarter_quorum_members[i].len() < quarter_size {
                        if idxk != processed_skip_list.len() && idx == processed_skip_list[idxk] {
                            idxk += 1;
                        } else {
                            quarter_quorum_members[i].push(sorted_combined_mns_list[idx as usize].clone());
                        }
                        idx += 1;
                        if idx == sorted_combined_mns_list.len() as i32 {
                            idx = 0;
                        }
                    }
                }
            }
            LLMQSnapshotSkipMode::SkipExcept => {
                (0..quorum_count).for_each(|i| {
                    let mut quarter = Vec::<models::MasternodeEntry>::new();
                    snapshot.skip_list.iter().for_each(|unskipped| {
                        if let Some(node) = sorted_combined_mns_list.get(*unskipped as usize) {
                            if quarter.len() < quarter_size {
                                quarter.push(node.clone());
                            }
                        }
                    });
                    quarter_quorum_members[i] = quarter;
                });
            }
            LLMQSnapshotSkipMode::SkipAll => {
                // TODO: do we need to impl smth in this strategy ?
                warn!("skip_mode SkipAll not supported yet");
            }
        }
        quarter_quorum_members
    }

    fn apply_skip_strategy_for_new_quarter(mut used_at_h_indexed_masternodes: Vec<Vec<models::MasternodeEntry>>, sorted_combined_mns_list: Vec<models::MasternodeEntry>, quorum_count: usize, quarter_size: usize) -> Vec<Vec<models::MasternodeEntry>> {
        let mut quarter_quorum_members = vec![Vec::<models::MasternodeEntry>::new(); quorum_count];
        let mut skip_list = Vec::<i32>::new();
        let mut first_skipped_index = 0i32;
        let mut idx = 0i32;
        for i in 0..quorum_count {
            let masternodes_used_at_h_indexed_at_i = used_at_h_indexed_masternodes.get_mut(i).unwrap();
            let used_mns_count = masternodes_used_at_h_indexed_at_i.len();
            let sorted_combined_mns_list_len = sorted_combined_mns_list.len();
            let mut updated = false;
            let initial_loop_idx = idx;
            while quarter_quorum_members[i].len() < quarter_size &&
                used_mns_count + quarter_quorum_members[i].len() < sorted_combined_mns_list_len {
                let mn = sorted_combined_mns_list.get(idx as usize).unwrap();
                // TODO: replace masternodes with smart pointers to avoid cloning
                if masternodes_used_at_h_indexed_at_i.iter().any(|node| mn.provider_registration_transaction_hash == node.provider_registration_transaction_hash) {
                    let skip_index = idx - first_skipped_index;
                    if first_skipped_index == 0 {
                        first_skipped_index = idx;
                    }
                    skip_list.push(idx);
                } else {
                    masternodes_used_at_h_indexed_at_i.push(mn.clone());
                    quarter_quorum_members[i].push(mn.clone());
                    updated = true;
                }
                idx += 1;
                if idx == sorted_combined_mns_list_len as i32 {
                    idx = 0;
                }
                if idx == initial_loop_idx {
                    if !updated {
                        warn!("there are not enough MNs then required for quarter size: ({})", quarter_size);
                        return quarter_quorum_members;
                    }
                    updated = false;
                }
            }
        }
        quarter_quorum_members
    }

    fn usage_info_from_snapshot(snapshot: &models::LLMQSnapshot, masternode_list: models::MasternodeList, quorum_modifier: UInt256, work_block_height: u32) -> (Vec<models::MasternodeEntry>, Vec<models::MasternodeEntry>) {
        let scored_masternodes = models::MasternodeList::score_masternodes_map(masternode_list.masternodes, quorum_modifier, work_block_height, false);
        let sorted_scored_masternodes = MasternodeProcessor::sort_scored_masternodes(scored_masternodes);
        let mut i = 0u32;
        sorted_scored_masternodes
            .into_iter()
            .partition(|_| {
                let used = snapshot.member_is_true_at_index(i);
                i += 1;
                used
            })
    }

    fn usage_info_(previous_quarters: [&Vec<Vec<models::MasternodeEntry>>; 3], masternode_list: models::MasternodeList, skip_removed_masternodes: bool, quorum_count: usize) -> (Vec<models::MasternodeEntry>, Vec<models::MasternodeEntry>, Vec<Vec<models::MasternodeEntry>>) {
        let mut used_at_h_masternodes = Vec::<models::MasternodeEntry>::new();
        let mut used_at_h_indexed_masternodes = vec![Vec::<models::MasternodeEntry>::new(); quorum_count];
        for i in 0..quorum_count {
            // for quarters h - c, h -2c, h -3c
            for quarter in &previous_quarters {
                if let Some(quarter_nodes) = quarter.get(i) {
                    for node in quarter_nodes {
                        let hash = node.provider_registration_transaction_hash;
                        if (!skip_removed_masternodes || masternode_list.has_masternode(hash)) &&
                            masternode_list.has_valid_masternode(hash) {
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
        let unused_at_h_masternodes = masternode_list.masternodes.values()
            .filter(|mn| mn.is_valid && !used_at_h_masternodes.iter().any(|node| mn.provider_registration_transaction_hash == node.provider_registration_transaction_hash))
            .cloned()
            .collect();
        (used_at_h_masternodes, unused_at_h_masternodes, used_at_h_indexed_masternodes)
    }

    pub fn quorum_quarter_members_by_reconstruction_type(
        &self,
        reconstruction_type: LLMQQuarterReconstructionType,
        llmq_params: &LLMQParams,
        work_block_height: u32,
        cached_mn_lists: &BTreeMap<UInt256, models::MasternodeList>,
        cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
        unknown_mn_lists: &mut Vec<UInt256>,
    ) -> Result<Vec<Vec<models::MasternodeEntry>>, CoreProviderError> {
        self.provider.masternode_list_info_for_height(work_block_height, cached_mn_lists, unknown_mn_lists, reconstruction_type)
            .and_then(|info| {
                let llmq_type = llmq_params.r#type;
                let quorum_count = llmq_params.signing_active_quorum_count as usize;
                let quorum_size = llmq_params.size as usize;
                let quarter_size = quorum_size / 4;

                match (reconstruction_type, info) {
                    (LLMQQuarterReconstructionType::Snapshot { .. },
                        LLMQQuarterReconstructionInfo::Snapshot(masternode_list, snapshot, work_block_hash)) => {
                        let quorum_modifier_type =  self.llmq_modifier_type_for(llmq_type, work_block_hash, work_block_height, cached_cl_signatures);
                        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
                        let (used_at_h_masternodes, unused_at_h_masternodes) = MasternodeProcessor::usage_info_from_snapshot(&snapshot, masternode_list, quorum_modifier, work_block_height);
                        let sorted_combined_mns_list = MasternodeProcessor::order(work_block_height, quorum_modifier, used_at_h_masternodes, unused_at_h_masternodes);
                        let quarter_quorum_members = Self::apply_skip_strategy_for_snapshot(snapshot, sorted_combined_mns_list, quorum_count, quarter_size);
                        Ok(quarter_quorum_members)
                    },
                    (LLMQQuarterReconstructionType::New { previous_quarters, skip_removed_masternodes },
                        LLMQQuarterReconstructionInfo::New(masternode_list, work_block_hash)) => {
                        let quorum_modifier_type = self.llmq_modifier_type_for(llmq_type, work_block_hash, work_block_height, cached_cl_signatures);
                        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
                        let (used_at_h_masternodes, unused_at_h_masternodes, used_at_h_indexed_masternodes) = MasternodeProcessor::usage_info_(previous_quarters, masternode_list, skip_removed_masternodes, quorum_count);
                        let sorted_combined_mns_list = MasternodeProcessor::order(work_block_height, quorum_modifier, used_at_h_masternodes, unused_at_h_masternodes);
                        let quarter_quorum_members = Self::apply_skip_strategy_for_new_quarter(used_at_h_indexed_masternodes, sorted_combined_mns_list, quorum_count, quarter_size);
                        Ok(quarter_quorum_members)
                    },
                    _ => Err(CoreProviderError::NullResult)
                }
            })
    }

    fn add_quorum_members_from_quarter(
        quorum_members: &mut Vec<Vec<models::MasternodeEntry>>,
        quarter: &[Vec<models::MasternodeEntry>],
        index: usize,
    ) {
        if let Some(indexed_quarter) = quarter.get(index) {
            quorum_members.resize_with(index + 1, Vec::new);
            quorum_members[index].extend(indexed_quarter.iter().cloned());
        }
    }

    fn rotate_members(
        &self,
        cycle_base_height: u32,
        llmq_params: LLMQParams,
        skip_removed_masternodes: bool,
        cached_mn_lists: &BTreeMap<UInt256, models::MasternodeList>,
        cached_llmq_snapshots: &BTreeMap<UInt256, models::LLMQSnapshot>,
        cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
        unknown_mn_lists: &mut Vec<UInt256>,
    ) -> Result<Vec<Vec<models::MasternodeEntry>>, CoreProviderError> {
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        // Reconstruct quorum members at h - 3c from snapshot
        let reconstruction_type_snapshot = LLMQQuarterReconstructionType::Snapshot { cached_llmq_snapshots };
        self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, (cycle_base_height - 3 * cycle_length) - 8, cached_mn_lists, cached_cl_signatures, unknown_mn_lists)
            .and_then(|q_h_m_3c|
                // Reconstruct quorum members at h - 2c from snapshot
                self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, (cycle_base_height - 2 * cycle_length) - 8, cached_mn_lists, cached_cl_signatures, unknown_mn_lists)
                    .and_then(|q_h_m_2c|
                        // Reconstruct quorum members at h - c from snapshot
                        self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, (cycle_base_height - cycle_length) - 8, cached_mn_lists, cached_cl_signatures, unknown_mn_lists)
                            .and_then(|q_h_m_c|
                                // Determine quorum members at new index
                                self.quorum_quarter_members_by_reconstruction_type(LLMQQuarterReconstructionType::New { previous_quarters:  [&q_h_m_c, &q_h_m_2c, &q_h_m_3c], skip_removed_masternodes }, &llmq_params, (cycle_base_height - 0) - 8, cached_mn_lists, cached_cl_signatures, unknown_mn_lists)
                                    .map(|quarter_new| {
                                        let mut quorum_members =
                                            Vec::<Vec<models::MasternodeEntry>>::with_capacity(num_quorums);
                                        (0..num_quorums).for_each(|index| {
                                            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_3c, index);
                                            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_2c, index);
                                            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_c, index);
                                            Self::add_quorum_members_from_quarter(&mut quorum_members, &quarter_new, index);
                                        });
                                        quorum_members
                                    }))))

    }

    /// Determine masternodes which is responsible for signing at this quorum index
    #[allow(clippy::too_many_arguments)]
    pub fn get_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: UInt256,
        block_height: u32,
        skip_removed_masternodes: bool,
        cache: &mut MasternodeProcessorCache
    ) -> Result<Vec<models::MasternodeEntry>, CoreProviderError> {
        let cached_llmq_members = &mut cache.llmq_members;
        let cached_llmq_indexed_members = &mut cache.llmq_indexed_members;
        let map_by_type_opt = cached_llmq_members.get_mut(&llmq_type);
        if map_by_type_opt.is_some() {
            if let Some(members) = map_by_type_opt.as_ref().unwrap().get(&block_hash) {
                return Ok(members.clone());
            }
        } else {
            cached_llmq_members.insert(llmq_type, BTreeMap::new());
        }
        let map_by_type = cached_llmq_members.get_mut(&llmq_type).unwrap();
        let llmq_params = llmq_type.params();
        let quorum_index = block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = block_height - quorum_index;
        self.provider.lookup_block_hash_by_height(cycle_base_height)
            .and_then(|cycle_base_hash| {
                let map_by_type_indexed_opt = cached_llmq_indexed_members.get_mut(&llmq_type);
                if map_by_type_indexed_opt.is_some() {
                    if let Some(members) = map_by_type_indexed_opt
                        .as_ref()
                        .unwrap()
                        .get(&(cycle_base_hash, quorum_index).into())
                    {
                        map_by_type.insert(block_hash, members.clone());
                        return Ok(members.clone());
                    }
                } else {
                    cached_llmq_indexed_members.insert(llmq_type, BTreeMap::new());
                }
                self.rotate_members(cycle_base_height, llmq_params, skip_removed_masternodes, &cache.mn_lists, &cache.llmq_snapshots, &cache.cl_signatures, &mut cache.needed_masternode_lists)
                    .and_then(|rotated_members| {
                        let result = if let Some(members) = rotated_members.get(quorum_index as usize) {
                            map_by_type.insert(block_hash, members.clone());
                            Ok(members.clone())
                        } else {
                            Err(CoreProviderError::NullResult)
                        };
                        let map_indexed_quorum_members_of_type =
                            cached_llmq_indexed_members.get_mut(&llmq_type).unwrap();
                        rotated_members.into_iter().enumerate().for_each(|(i, members)| {
                            map_indexed_quorum_members_of_type.insert((cycle_base_hash, i).into(), members);
                        });
                        result
                    })
            })
    }

    pub fn read_list_diff_from_message<'a>(&self, message: &'a [u8], offset: &mut usize, protocol_version: u32) -> Result<models::MNListDiff, byte::Error> {
        models::MNListDiff::new(message, offset, |block_hash| self.provider.lookup_block_height_by_hash(block_hash), protocol_version)
    }

    pub fn mn_list_diff_result_from_message(&self, message: &[u8], is_from_snapshot: bool, protocol_version: u32, cache: &mut MasternodeProcessorCache) -> Result<processing::MNListDiffResult, ProcessingError> {
        self.read_list_diff_from_message(message, &mut 0, protocol_version)
            .map_err(ProcessingError::from)
            .and_then(|list_diff| {
                if !is_from_snapshot {
                    ok_or_return_processing_error!(self.provider.should_process_diff_with_range(list_diff.base_block_hash, list_diff.block_hash));
                }
                Ok(self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff, cache))
            })
    }

    pub fn qr_info_result_from_message(&self, message: &[u8], is_from_snapshot: bool, protocol_version: u32, is_rotated_quorums_presented: bool, cache: &mut MasternodeProcessorCache) -> Result<processing::QRInfoResult, ProcessingError> {
        let process_list_diff = |list_diff, verification_context|
            self.get_list_diff_result_with_base_lookup(list_diff, verification_context, cache);
        let result = message.read_with::<models::QRInfo>(&mut 0, (&*self.provider, is_from_snapshot, protocol_version, is_rotated_quorums_presented))
            .map_err(ProcessingError::from)
            .map(|qr_info| qr_info.into_result(process_list_diff, is_rotated_quorums_presented));

        #[cfg(feature = "generate-dashj-tests")]
        if let Ok(ref result) = result {
            crate::util::java::generate_qr_state_test_file_json(self.provider.chain_type(), result);
        }
        result
    }

}
