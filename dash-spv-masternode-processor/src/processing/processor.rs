use std::collections::{BTreeMap, HashSet};
use byte::BytesExt;
use crate::{common, processing};
use dash_spv_crypto::llmq::{LLMQEntry, LLMQModifierType};
use dash_spv_crypto::network::{LLMQType, LLMQParams};
use dash_spv_crypto::crypto::byte_util::{Reversable, UInt256, UInt768};
use crate::common::LLMQSnapshotSkipMode;
use crate::models::{LLMQIndexedHash, LLMQSnapshot, LLMQVerificationContext, MasternodeEntry, MasternodeList, mn_list_diff::MNListDiff, QRInfo, llmq};
use crate::models::masternode_list::{score_masternodes_map};
use crate::processing::core_provider::{CoreProvider, CoreProviderError};
use crate::processing::{LLMQValidationStatus, MasternodeProcessorCache, processing_error::ProcessingError};

pub enum LLMQQuarterType {
    AtHeightMinus3Cycles,
    AtHeightMinus2Cycles,
    AtHeightMinusCycle,
    New,
}

#[derive(Clone, Copy)]
pub enum LLMQQuarterReconstructionType<'a> {
    Snapshot {
        cached_llmq_snapshots: &'a BTreeMap<UInt256, LLMQSnapshot>
    },
    New {
        previous_quarters: [&'a Vec<Vec<MasternodeEntry>>; 3],
        skip_removed_masternodes: bool,
    }
}

pub enum LLMQQuarterUsageType {
    Snapshot(LLMQSnapshot),
    New(Vec<Vec<MasternodeEntry>>)
}

// https://github.com/rust-lang/rfcs/issues/2770
#[derive(Debug)]
#[ferment_macro::opaque]
pub struct MasternodeProcessor {
    pub provider: Box<dyn CoreProvider>,
}
impl MasternodeProcessor {
    pub fn new(provider: Box<dyn CoreProvider>) -> Self {
        Self { provider }
    }
}
impl MasternodeProcessor {
    fn llmq_modifier_type_for(&self, llmq_type: LLMQType, work_block_hash: UInt256, work_block_height: u32, cached_cl_signatures: &BTreeMap<UInt256, UInt768>) -> LLMQModifierType {
        if self.provider.chain_type().core20_is_active_at(work_block_height) {
            if let Ok(work_block_hash) = self.provider.lookup_block_hash_by_height(work_block_height) {
                if let Ok(best_cl_signature) = self.provider.find_cl_signature(work_block_hash, cached_cl_signatures) {
                    return LLMQModifierType::CoreV20(llmq_type, work_block_height, best_cl_signature);
                } else {
                    println!("llmq_modifier_type: chain lock signature for block hash {} ({}) not found", work_block_hash, work_block_hash.reversed());
                }
            } else {
                println!("llmq_modifier_type: block for height {} not found", work_block_height);
            }
        }
        LLMQModifierType::PreCoreV20(llmq_type, work_block_hash)
    }

    fn get_list_diff_result_with_base_lookup(
        &self,
        list_diff: MNListDiff,
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
        list: MasternodeList,
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
        base_list: Option<MasternodeList>,
        list_diff: MNListDiff,
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
        let masternode_list = MasternodeList::new(
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
    fn classify_masternodes(
        &self,
        base_masternodes: BTreeMap<UInt256, MasternodeEntry>,
        added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry>,
        deleted_masternode_hashes: Vec<UInt256>,
        block_height: u32,
        block_hash: UInt256,
    ) -> (
        BTreeMap<UInt256, MasternodeEntry>,
        BTreeMap<UInt256, MasternodeEntry>,
        BTreeMap<UInt256, MasternodeEntry>,
    ) {
        let (mut modified_masternodes, added_masternodes): (BTreeMap<UInt256, MasternodeEntry>, BTreeMap<UInt256, MasternodeEntry>) =
            added_or_modified_masternodes
                .into_iter()
                .partition(|(hash, _)| base_masternodes.contains_key(hash));

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
                    old.confirm_at_height_if_need(block_height);
                }
                masternodes.insert(*hash, modified.clone());
            }
        }
        (added_masternodes, modified_masternodes, masternodes)
    }


    #[allow(clippy::type_complexity)]
    fn verify_added_quorums(
        &self,
        verification_context: LLMQVerificationContext,
        added_quorums: &mut Vec<LLMQEntry>,
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
                    if let Some(signature) = find_cl_signature_at_index(quorums_cl_sigs, index as u16) {
                        let llmq_height = self.provider.lookup_block_height_by_hash(quorum.llmq_hash);
                        if llmq_height != u32::MAX {
                            let work_block_height = llmq_height - 8;
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

    fn process_quorums(
        &self,
        mut base_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
        added_quorums: Vec<LLMQEntry>,
        deleted_quorums: BTreeMap<LLMQType, Vec<UInt256>>,
    ) -> (
        Vec<LLMQEntry>,
        BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
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

    fn find_valid_masternodes_for_quorum(&self, quorum: &LLMQEntry, block_height: u32, skip_removed_masternodes: bool, masternodes: BTreeMap<UInt256, MasternodeEntry>, cache: &mut MasternodeProcessorCache) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
        if quorum.index.is_some() {
            self.get_rotated_masternodes_for_quorum(quorum.llmq_type, quorum.llmq_hash, block_height, skip_removed_masternodes, cache)
        } else {
            self.get_non_rotated_masternodes_for_quorum(quorum.llmq_type, quorum.llmq_hash, block_height, quorum, masternodes, cache)
        }
    }

    fn validate_quorum(&self, quorum: &mut LLMQEntry, skip_removed_masternodes: bool, cache: &mut MasternodeProcessorCache) -> Result<LLMQValidationStatus, CoreProviderError> {
        let llmq_block_hash = quorum.llmq_hash;
        self.provider.find_masternode_list(llmq_block_hash, &cache.mn_lists, &mut cache.needed_masternode_lists)
            .and_then(|MasternodeList { masternodes, .. }| {
                let block_height = self.provider.lookup_block_height_by_hash(llmq_block_hash);
                self.find_valid_masternodes_for_quorum(quorum, block_height, skip_removed_masternodes, masternodes, cache)
                    .and_then(|valid_masternodes| llmq::verify(quorum, valid_masternodes, block_height))
            })
    }

    fn get_non_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: UInt256,
        block_height: u32,
        quorum: &LLMQEntry,
        masternodes: BTreeMap<UInt256, MasternodeEntry>,
        cache: &mut MasternodeProcessorCache
    ) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
        Ok(llmq::valid_masternodes(quorum, self.provider.chain_type(), masternodes, block_height, self.llmq_modifier_type_for(llmq_type, block_hash, block_height - 8, &cache.cl_signatures)))
    }

    fn quorum_quarter_members_by_reconstruction_type(
        &self,
        reconstruction_type: LLMQQuarterReconstructionType,
        llmq_params: &LLMQParams,
        work_block_height: u32,
        cached_mn_lists: &BTreeMap<UInt256, MasternodeList>,
        cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
        unknown_mn_lists: &mut Vec<UInt256>,
    ) -> Result<Vec<Vec<MasternodeEntry>>, CoreProviderError> {
        self.provider.lookup_block_hash_by_height(work_block_height)
            .map_err(|err| CoreProviderError::BlockHashNotFoundAt(work_block_height))
            .and_then(|work_block_hash|
                self.provider.find_masternode_list(work_block_hash, cached_mn_lists, unknown_mn_lists)
                    .and_then(|masternode_list| {
                        let llmq_type = llmq_params.r#type;
                        let quorum_count = llmq_params.signing_active_quorum_count as usize;
                        let quorum_size = llmq_params.size as usize;
                        let quarter_size = quorum_size / 4;
                        let quorum_modifier_type = self.llmq_modifier_type_for(llmq_type, work_block_hash, work_block_height, cached_cl_signatures);
                        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
                        match reconstruction_type {
                            LLMQQuarterReconstructionType::New { previous_quarters, skip_removed_masternodes } => {
                                let (used_at_h_masternodes, unused_at_h_masternodes, used_at_h_indexed_masternodes) =
                                    masternode_list.usage_info(previous_quarters, skip_removed_masternodes, quorum_count);
                                Ok(apply_skip_strategy_of_type(LLMQQuarterUsageType::New(used_at_h_indexed_masternodes), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size))
                            },
                            LLMQQuarterReconstructionType::Snapshot { cached_llmq_snapshots } => {
                                self.provider.find_snapshot(work_block_hash, cached_llmq_snapshots)
                                    .map(|snapshot| {
                                        let (used_at_h_masternodes, unused_at_h_masternodes) =
                                            usage_info_from_snapshot(masternode_list, &snapshot, quorum_modifier, work_block_height);
                                        apply_skip_strategy_of_type(LLMQQuarterUsageType::Snapshot(snapshot), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size)
                                    })
                            }
                        }
                    }))
    }


    fn rotate_members(
        &self,
        cycle_base_height: u32,
        llmq_params: LLMQParams,
        skip_removed_masternodes: bool,
        cached_mn_lists: &BTreeMap<UInt256, MasternodeList>,
        cached_llmq_snapshots: &BTreeMap<UInt256, LLMQSnapshot>,
        cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
        unknown_mn_lists: &mut Vec<UInt256>,
    ) -> Result<Vec<Vec<MasternodeEntry>>, CoreProviderError> {
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        // Reconstruct quorum members at h - 3c from snapshot
        let work_block_height_for_index = |index: u32| (cycle_base_height - index * cycle_length) - 8;
        let reconstruction_type_snapshot = LLMQQuarterReconstructionType::Snapshot { cached_llmq_snapshots };
        self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, work_block_height_for_index(3), cached_mn_lists, cached_cl_signatures, unknown_mn_lists)
            .and_then(|q_h_m_3c|
                // Reconstruct quorum members at h - 2c from snapshot
                self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, work_block_height_for_index(2), cached_mn_lists, cached_cl_signatures, unknown_mn_lists)
                    .and_then(|q_h_m_2c|
                        // Reconstruct quorum members at h - c from snapshot
                        self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, work_block_height_for_index(1), cached_mn_lists, cached_cl_signatures, unknown_mn_lists)
                            .and_then(|q_h_m_c|
                                // Determine quorum members at new index
                                self.quorum_quarter_members_by_reconstruction_type(
                                    LLMQQuarterReconstructionType::New {
                                        previous_quarters:  [&q_h_m_c, &q_h_m_2c, &q_h_m_3c],
                                        skip_removed_masternodes
                                    },
                                    &llmq_params,
                                    work_block_height_for_index(0),
                                    cached_mn_lists,
                                    cached_cl_signatures,
                                    unknown_mn_lists)
                                    .map(|quarter_new| {
                                        let mut quorum_members =
                                            Vec::<Vec<MasternodeEntry>>::with_capacity(num_quorums);
                                        (0..num_quorums).for_each(|index| {
                                            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_3c, index);
                                            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_2c, index);
                                            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_c, index);
                                            add_quorum_members_from_quarter(&mut quorum_members, &quarter_new, index);
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
    ) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
        let cached_llmq_members = &mut cache.llmq_members;
        let cached_llmq_indexed_members = &mut cache.llmq_indexed_members;
        let cached_members_of_llmq_type_opt = cached_llmq_members.get_mut(&llmq_type);
        if cached_members_of_llmq_type_opt.is_some() {
            if let Some(cached_members) = cached_members_of_llmq_type_opt.as_ref().unwrap().get(&block_hash) {
                return Ok(cached_members.clone());
            }
        } else {
            cached_llmq_members.insert(llmq_type, BTreeMap::new());
        }

        let cached_members_of_llmq_type = cached_llmq_members.get_mut(&llmq_type).unwrap();
        let llmq_params = llmq_type.params();
        let quorum_index = block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = block_height - quorum_index;
        self.provider.lookup_block_hash_by_height(cycle_base_height)
            .and_then(|cycle_base_hash| {
                if let Some(map_by_type_indexed) = cached_llmq_indexed_members.get(&llmq_type) {
                    let indexed_hash = LLMQIndexedHash::from((cycle_base_hash, quorum_index));
                    if let Some(cached_members) = map_by_type_indexed.get(&indexed_hash) {
                        cached_members_of_llmq_type.insert(block_hash, cached_members.clone());
                        return Ok(cached_members.clone());
                    }
                } else {
                    cached_llmq_indexed_members.insert(llmq_type, BTreeMap::new());
                }
                self.rotate_members(cycle_base_height, llmq_params, skip_removed_masternodes, &cache.mn_lists, &cache.llmq_snapshots, &cache.cl_signatures, &mut cache.needed_masternode_lists)
                    .and_then(|rotated_members| {
                        let result = if let Some(rotated_members_at_index) = rotated_members.get(quorum_index as usize) {
                            cached_members_of_llmq_type.insert(block_hash, rotated_members_at_index.clone());
                            Ok(rotated_members_at_index.clone())
                        } else {
                            Err(CoreProviderError::NullResult)
                        };
                        cached_llmq_indexed_members.get_mut(&llmq_type)
                            .unwrap()
                            .extend(rotated_members.into_iter()
                                .enumerate()
                                .map(|(index, members)|
                                    (LLMQIndexedHash::from((cycle_base_hash, index)), members)));
                        result
                    })
            })
    }

    pub fn read_list_diff_from_message(&self, message: &[u8], offset: &mut usize, protocol_version: u32) -> Result<MNListDiff, byte::Error> {
        MNListDiff::new(message, offset, &*self.provider, protocol_version)
    }

    pub fn mn_list_diff_result_from_message(
        &self,
        message: &[u8],
        is_from_snapshot: bool,
        protocol_version: u32,
        cache: &mut MasternodeProcessorCache
    ) -> Result<processing::MNListDiffResult, ProcessingError> {
        self.read_list_diff_from_message(message, &mut 0, protocol_version)
            .map_err(ProcessingError::from)
            .and_then(|list_diff| {
                if !is_from_snapshot {
                    self.provider.should_process_diff_with_range(list_diff.base_block_hash, list_diff.block_hash)?;
                }
                Ok(self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff, cache))
            })
    }

    pub fn qr_info_result_from_message(&self, message: &[u8], is_from_snapshot: bool, protocol_version: u32, is_rotated_quorums_presented: bool, cache: &mut MasternodeProcessorCache) -> Result<processing::QRInfoResult, ProcessingError> {
        let list_diff_processor = |list_diff, verification_context|
            self.get_list_diff_result_with_base_lookup(list_diff, verification_context, cache);
        let result = message.read_with::<QRInfo>(&mut 0, (&*self.provider, is_from_snapshot, protocol_version, is_rotated_quorums_presented))
            .map_err(ProcessingError::from)
            .map(|qr_info| qr_info.into_result(list_diff_processor, is_rotated_quorums_presented));

        #[cfg(feature = "generate-dashj-tests")]
        if let Ok(ref result) = result {
            crate::util::java::generate_qr_state_test_file_json(self.provider.chain_type(), result);
        }
        result
    }

}
fn add_quorum_members_from_quarter(
    quorum_members: &mut Vec<Vec<MasternodeEntry>>,
    quarter: &[Vec<MasternodeEntry>],
    index: usize,
) {
    if let Some(indexed_quarter) = quarter.get(index) {
        quorum_members.resize_with(index + 1, Vec::new);
        quorum_members[index].extend(indexed_quarter.iter().cloned());
    }
}

fn apply_skip_strategy_of_type(
    skip_type: LLMQQuarterUsageType,
    used_at_h_masternodes: Vec<MasternodeEntry>,
    unused_at_h_masternodes: Vec<MasternodeEntry>,
    work_block_height: u32,
    quorum_modifier: UInt256,
    quorum_count: usize,
    quarter_size: usize,
) -> Vec<Vec<MasternodeEntry>> {
    let sorted_used_mns_list = valid_masternodes_for_rotated_quorum_map(
        used_at_h_masternodes,
        quorum_modifier,
        work_block_height);
    let sorted_unused_mns_list = valid_masternodes_for_rotated_quorum_map(
        unused_at_h_masternodes,
        quorum_modifier,
        work_block_height);
    let sorted_combined_mns_list = Vec::from_iter(sorted_unused_mns_list.into_iter().chain(sorted_used_mns_list.into_iter()));
    match skip_type {
        LLMQQuarterUsageType::Snapshot(snapshot) => {
            match snapshot.skip_list_mode {
                LLMQSnapshotSkipMode::NoSkipping => {
                    sorted_combined_mns_list
                        .chunks(quarter_size)
                        .map(|chunk| chunk.to_vec())
                        .collect()
                }
                LLMQSnapshotSkipMode::SkipFirst => {
                    let mut first_entry_index = 0;
                    let processed_skip_list = Vec::from_iter(snapshot.skip_list.into_iter().map(|s| if first_entry_index == 0 {
                        first_entry_index = s;
                        s
                    } else {
                        first_entry_index + s
                    }));
                    let mut idx = 0;
                    let mut skip_idx = 0;
                    (0..quorum_count).map(|_| {
                        let mut quarter = Vec::with_capacity(quarter_size);
                        while quarter.len() < quarter_size {
                            let index = (idx + 1) % sorted_combined_mns_list.len();
                            if skip_idx < processed_skip_list.len() && idx == processed_skip_list[skip_idx] as usize {
                                skip_idx += 1;
                            } else {
                                quarter.push(sorted_combined_mns_list[idx].clone());
                            }
                            idx = index
                        }
                        quarter
                    }).collect()
                }
                LLMQSnapshotSkipMode::SkipExcept => {
                    (0..quorum_count)
                        .map(|i| snapshot.skip_list
                            .iter()
                            .filter_map(|unskipped| sorted_combined_mns_list.get(*unskipped as usize))
                            .take(quarter_size)
                            .cloned()
                            .collect())
                        .collect()
                }
                LLMQSnapshotSkipMode::SkipAll => {
                    // TODO: do we need to impl smth in this strategy ?
                    warn!("skip_mode SkipAll not supported yet");
                    vec![Vec::<MasternodeEntry>::new(); quorum_count]
                }
            }
        },
        LLMQQuarterUsageType::New(mut used_at_h_indexed_masternodes) => {
            let mut quarter_quorum_members = vec![Vec::<MasternodeEntry>::new(); quorum_count];
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
    }
}
fn find_cl_signature_at_index(quorums_cl_sigs: &BTreeMap<UInt768, HashSet<u16>>, index: u16) -> Option<UInt768> {
    quorums_cl_sigs.iter().find_map(|(signature, index_set)|
        if index_set.iter().any(|i| *i == index) { Some(*signature) } else { None })
}

fn sort_scored_masternodes(scored_masternodes: BTreeMap<UInt256, MasternodeEntry>) -> Vec<MasternodeEntry> {
    let mut v = Vec::from_iter(scored_masternodes);
    v.sort_by(|(s1, _), (s2, _)| s2.reversed().cmp(&s1.reversed()));
    v.into_iter().map(|(s, node)| node).collect()
}
fn usage_info_from_snapshot(masternode_list: MasternodeList, snapshot: &LLMQSnapshot, quorum_modifier: UInt256, work_block_height: u32) -> (Vec<MasternodeEntry>, Vec<MasternodeEntry>) {
    let scored_masternodes = score_masternodes_map(masternode_list.masternodes, quorum_modifier, work_block_height, false);
    let sorted_scored_masternodes = sort_scored_masternodes(scored_masternodes);
    let mut i = 0u32;
    sorted_scored_masternodes
        .into_iter()
        .partition(|_| {
            let used = snapshot.member_is_true_at_index(i);
            i += 1;
            used
        })
}
fn valid_masternodes_for_rotated_quorum_map(
    masternodes: Vec<MasternodeEntry>,
    quorum_modifier: UInt256,
    block_height: u32,
) -> Vec<MasternodeEntry> {
    let scored_masternodes = masternodes
        .into_iter()
        .filter_map(|entry| entry.score(quorum_modifier, block_height)
            .map(|score| (score, entry)))
        .collect::<BTreeMap<_, _>>();
    sort_scored_masternodes(scored_masternodes)
}

