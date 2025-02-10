use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use hashes::hex::ToHex;
use crate::common;
use dash_spv_crypto::llmq::{LLMQEntry, LLMQModifierType};
use dash_spv_crypto::network::{LLMQType, LLMQParams, CHAIN_LOCK_ACTIVATION_HEIGHT, IHaveChainSettings};
use dash_spv_crypto::crypto::byte_util::{Reversed, Zeroable};
use dash_spv_crypto::llmq::entry::{LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus};
use dash_spv_crypto::llmq::status::LLMQValidationError;
use dash_spv_crypto::network::llmq_type::{dkg_rotation_params, DKGParams};
// use dash_spv_event_bus::DAPIAddressHandler;
use crate::common::{Block, LLMQSnapshotSkipMode};
use crate::models::{LLMQIndexedHash, LLMQSnapshot, LLMQVerificationContext, MasternodeEntry, MasternodeList, mn_list_diff::MNListDiff, QRInfo, llmq};
use crate::models::llmq::{validate, validate_payload};
use crate::models::masternode_list::{masternode_vec_to_map, quorum_vec_to_map, score_masternodes_map};
use crate::models::sync_state::CacheState;
use crate::processing::core_provider::{CoreProvider, CoreProviderError};
use crate::processing::{MasternodeProcessorCache, processing_error::ProcessingError, MNListDiffResult};
use crate::processing::processor_cache::RetrievalQueue;
use crate::util::formatter::CustomFormatter;

pub enum LLMQQuarterType {
    AtHeightMinus3Cycles,
    AtHeightMinus2Cycles,
    AtHeightMinusCycle,
    New,
}

#[derive(Clone, Copy)]
pub enum LLMQQuarterReconstructionType<'a> {
    Snapshot,
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
#[ferment_macro::opaque]
pub struct MasternodeProcessor {
    pub provider: Arc<dyn CoreProvider>,
    pub cache: Arc<MasternodeProcessorCache>,
    // pub dapi_address_handler: Option<Arc<dyn DAPIAddressHandler>>,
}
impl Debug for MasternodeProcessor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}] [PROC]", self.provider.chain_type().identifier()).as_str())
    }
}
impl MasternodeProcessor {
    pub fn new(provider: Arc<dyn CoreProvider>, cache: Arc<MasternodeProcessorCache>) -> Self {
        Self { provider, cache }
    }
}

#[ferment_macro::export]
impl MasternodeProcessor {
    pub fn current_masternode_list(&self, is_rotated_quorums_presented: bool) -> Option<MasternodeList> {
        let result = if is_rotated_quorums_presented {
            let last_mn_list_diff_list = self.cache.get_last_queried_mn_masternode_list();
            let last_qr_list_diff_list = self.cache.get_last_queried_qr_masternode_list_at_tip();
            match (&last_mn_list_diff_list, &last_qr_list_diff_list) {
                (Some(mn_list), Some(qr_list)) => {
                    let last_mn_height = self.height_for_block_hash(mn_list.block_hash);
                    let last_qr_height = self.height_for_block_hash(qr_list.block_hash);
                    if last_mn_height > last_qr_height {
                        last_mn_list_diff_list
                    } else {
                        last_qr_list_diff_list
                    }
                },
                _ => last_mn_list_diff_list
            }
        } else {
            self.cache.get_last_queried_mn_masternode_list()
        };
        println!("{self:?} current_masternode_list: {}", result.as_ref().map(|r| format!("{} ({})", r.known_height, r.block_hash.to_hex())).unwrap_or("None".to_string()));
        result
    }

    pub fn has_current_masternode_list(&self, is_rotated_quorums_presented: bool) -> bool {
        self.current_masternode_list(is_rotated_quorums_presented).is_some()
    }

    pub fn current_masternode_list_masternode_with_pro_reg_tx_hash(&self, is_rotated_quorums_presented: bool, hash: [u8; 32]) -> Option<MasternodeEntry> {
        let list = self.current_masternode_list(is_rotated_quorums_presented);
        list.and_then(|list| list.masternode_for(hash).cloned())
    }
    pub fn current_masternode_list_masternode_count(&self, is_rotated_quorums_presented: bool) -> usize {
        let list = self.current_masternode_list(is_rotated_quorums_presented);
        list.map(|list| list.masternode_count())
            .unwrap_or_default()
    }
    pub fn current_masternode_list_quorum_count(&self, is_rotated_quorums_presented: bool) -> usize {
        let list = self.current_masternode_list(is_rotated_quorums_presented);
        list.map(|list| list.quorums_count() as usize)
            .unwrap_or_default()
    }

    pub fn add_to_mn_list_retrieval_queue(&self, block_hash: [u8; 32]) {
        assert!(!block_hash.is_zero(), "the hash must not be empty");
        self.cache.write_mn_list_retrieval_queue(|lock| {
            lock.queue.insert(block_hash);
            lock.update_retrieval_queue(self);
        });
    }
    pub fn extend_mn_list_retrieval_queue(&self, block_hashes: Vec<[u8; 32]>) {
        // assert!(!block_hash.is_zero(), "the hash must not be empty");
        self.cache.write_mn_list_retrieval_queue(|lock| {
            lock.queue.extend(block_hashes);
            lock.update_retrieval_queue(self);
        });
    }
    pub fn remove_from_mn_list_retrieval_queue(&self, block_hash: &[u8; 32]) {
        // assert!(!block_hash.is_zero(), "the hash must not be empty");
        self.cache.write_mn_list_retrieval_queue(|lock| {
            lock.queue.shift_remove(block_hash);
            lock.update_retrieval_queue(self);
        });
    }

    pub fn update_mn_list_retrieval_queue(&self) -> RetrievalQueue {
        self.cache.write_mn_list_retrieval_queue(|lock| {
            lock.update_retrieval_queue(self);
            lock.clone()
        })
    }
    pub fn clean_mn_list_retrieval_queue(&self) {
        self.cache.write_mn_list_retrieval_queue(|lock| {
            lock.queue.clear();
            lock.update_retrieval_queue(self);
            println!("{} Masternode list queue cleaned up: 0/{}", self.provider.chain_type().name(), lock.max_amount);
        });
    }
    pub fn add_to_qr_info_retrieval_queue(&self, block_hash: [u8; 32]) {
        assert!(!block_hash.is_zero(), "the hash must not be empty");
        self.cache.write_qr_info_retrieval_queue(|lock| {
            lock.queue.insert(block_hash);
            lock.update_retrieval_queue(self);
        });
    }
    pub fn extend_qr_info_retrieval_queue(&self, block_hashes: Vec<[u8; 32]>) {
        // assert!(!block_hash.is_zero(), "the hash must not be empty");
        self.cache.write_qr_info_retrieval_queue(|lock| {
            lock.queue.extend(block_hashes);
            lock.update_retrieval_queue(self);
        });
    }
    pub fn remove_from_qr_info_retrieval_queue(&self, block_hash: &[u8; 32]) {
        assert!(!block_hash.is_zero(), "the hash must not be empty");
        self.cache.write_qr_info_retrieval_queue(|lock| {
            lock.queue.shift_remove(block_hash);
            lock.update_retrieval_queue(self);
        });
    }
    pub fn update_qr_info_retrieval_queue(&self) -> RetrievalQueue {
        self.cache.write_qr_info_retrieval_queue(|lock| {
            lock.update_retrieval_queue(self);
            lock.clone()
        })
    }
    pub fn clean_qr_info_retrieval_queue(&self) {
        self.cache.write_qr_info_retrieval_queue(|lock| {
            lock.queue.clear();
            lock.update_retrieval_queue(self);
            println!("{} Quorum Rotation queue cleaned up: 0/{}", self.provider.chain_type().name(), lock.max_amount);
        });
    }

    pub fn merkle_root_for_block_hash(&self, block_hash: [u8; 32], peer: *const std::os::raw::c_void) -> Result<[u8; 32], ProcessingError> {
        if block_hash.is_zero() {
            Ok([0; 32])
        } else {
            self.provider.last_block_for_block_hash(block_hash, peer)
                .map(|b| b.merkle_root)
                .map_err(ProcessingError::from)
        }
    }

    pub fn mn_list_diff_result_from_file(&self, message: &[u8], protocol_version: u32) -> Result<([u8; 32], [u8; 32], bool), ProcessingError> {
        let list_diff = self.read_list_diff_from_message(message, &mut 0, protocol_version)?;
        // println!("{self:?}: {}", list_diff);
        let base_block_hash = list_diff.base_block_hash.clone();
        let block_hash = list_diff.block_hash.clone();
        let block = self.provider.block_by_hash(block_hash)
            .map_err(ProcessingError::from)?;
        // println!("block by block_hash {} is {}", block_hash.to_hex(), block);

        let result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff, block.merkle_root).map_err(ProcessingError::from)?;
        println!("{self:?} MNL diff from file: {}", result.short_description());
        if result.is_valid() {
            self.masternode_list_processed(
                result.masternode_list,
                result.added_masternodes,
                result.modified_masternodes,
                result.added_dapi_nodes,
                result.removed_dapi_nodes,
                |list_block_hash| self.cache.set_last_queried_mn_masternode_list(list_block_hash))
                .map_err(ProcessingError::from)?;
            Ok((base_block_hash, block_hash, result.has_added_rotated_quorums))
        } else {
            Err(ProcessingError::InvalidResult(result.short_description()))
        }
    }

    pub fn mn_list_diff_result_from_message(
        &self,
        message: &[u8],
        is_from_snapshot: bool,
        protocol_version: u32,
        allow_invalid_merkle_roots: bool,
        peer: *const std::os::raw::c_void
    ) -> Result<([u8; 32], [u8; 32], bool), ProcessingError> {
        let list_diff = self.read_list_diff_from_message(message, &mut 0, protocol_version)?;
        // println!("{self:?}: {}", list_diff);
        let base_block_hash = list_diff.base_block_hash;
        let block_hash = list_diff.block_hash;
        if !is_from_snapshot {
            self.should_process_diff_with_range(false, base_block_hash, block_hash, peer)?;
        }
        let merkle_root = self.merkle_root_for_block_hash(block_hash, peer)?;
        // println!("last block for block_hash {} is {}", block_hash.to_hex(), block);
        let result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff, merkle_root).map_err(ProcessingError::from)?;

        let should_process = is_from_snapshot || self.should_process_diff_result(&result, allow_invalid_merkle_roots, false);
        let raise_peer_issue = !should_process;
        println!("{self:?} MNL diff from msg: {}", result.short_description());
        let MNListDiffResult {
            block_hash,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists,
            has_added_rotated_quorums,
            added_dapi_nodes,
            removed_dapi_nodes,
            ..
        } = result;
        if should_process {
            let need_validate_llmq = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
            if needed_masternode_lists.is_empty() || !need_validate_llmq {
                let result = self.masternode_list_processed(
                    masternode_list,
                    added_masternodes,
                    modified_masternodes,
                    added_dapi_nodes,
                    removed_dapi_nodes,
                    |list| {
                        if self.cache.get_last_queried_block_hash().eq(&block_hash) {
                            self.cache.set_last_queried_mn_masternode_list(block_hash);
                            self.cache.remove_block_hash_for_list_needing_quorums_validated(block_hash);
                        }
                    }
                );
                result.map_err(ProcessingError::from)?;
            } else {
                self.cache.add_needed_masternode_lists(needed_masternode_lists.clone());
            }
        }
        if !needed_masternode_lists.is_empty() {
            self.cache.write_mn_list_retrieval_queue(|lock| {
                lock.queue.shift_remove(&block_hash);
            });
            let debug_info = needed_masternode_lists.format();
            println!("missing lists:\n {}", debug_info);
            self.process_missing_masternode_lists(block_hash, needed_masternode_lists);
            Err(ProcessingError::MissingLists(debug_info))
        } else {
            Ok((base_block_hash, block_hash, has_added_rotated_quorums))
        }
    }


    pub fn qr_info_result_from_message(
        &self,
        message: &[u8],
        is_from_snapshot: bool,
        protocol_version: u32,
        is_rotated_quorums_presented: bool,
        allow_invalid_merkle_roots: bool,
        peer: *const std::os::raw::c_void
    ) -> Result<([u8; 32], [u8; 32]), ProcessingError> {
        let qr_info = QRInfo::new(message, self, is_from_snapshot, protocol_version, peer)?;
        //println!("{self:?}: {}", qr_info);
        let QRInfo {
            diff_h_4c,
            diff_h_3c,
            diff_h_2c,
            diff_h_c,
            diff_h,
            diff_tip,
            extra_share,
            mn_list_diff_list,
            quorum_snapshot_list,
            snapshot_h_4c,
            snapshot_h_3c,
            snapshot_h_2c,
            snapshot_h_c,
            last_quorum_per_index
        } = qr_info;
        let result_at_h_4c = if let Some(diff_h_4c) = diff_h_4c {
            let merkle_root_h_4c = self.merkle_root_for_block_hash(diff_h_4c.block_hash, peer)?;
            Some(self.get_list_diff_result_with_base_lookup(diff_h_4c, LLMQVerificationContext::None, merkle_root_h_4c).map_err(ProcessingError::from)?)
        } else { None };


        let merkle_root_h_3c = self.merkle_root_for_block_hash(diff_h_3c.block_hash, peer)?;
        let merkle_root_h_2c = self.merkle_root_for_block_hash(diff_h_2c.block_hash, peer)?;
        let merkle_root_h_c = self.merkle_root_for_block_hash(diff_h_c.block_hash, peer)?;
        let merkle_root_h = self.merkle_root_for_block_hash(diff_h.block_hash, peer)?;
        let merkle_root_tip = self.merkle_root_for_block_hash(diff_tip.block_hash, peer)?;

        let result_at_h_3c = self.get_list_diff_result_with_base_lookup(diff_h_3c, LLMQVerificationContext::None, merkle_root_h_3c).map_err(ProcessingError::from)?;
        let result_at_h_2c = self.get_list_diff_result_with_base_lookup(diff_h_2c, LLMQVerificationContext::None, merkle_root_h_2c).map_err(ProcessingError::from)?;
        let result_at_h_c = self.get_list_diff_result_with_base_lookup(diff_h_c, LLMQVerificationContext::None, merkle_root_h_c).map_err(ProcessingError::from)?;
        let result_at_h = self.get_list_diff_result_with_base_lookup(diff_h, LLMQVerificationContext::QRInfo(is_rotated_quorums_presented), merkle_root_h).map_err(ProcessingError::from)?;
        let result_at_tip = self.get_list_diff_result_with_base_lookup(diff_tip, LLMQVerificationContext::None, merkle_root_tip).map_err(ProcessingError::from)?;

        println!("{self:?} h-4c: {}", result_at_h_4c.as_ref().map(MNListDiffResult::short_description).unwrap_or_else(|| "None".to_string()));
        println!("{self:?} h-3c: {}", result_at_h_3c.short_description());
        println!("{self:?} h-2c: {}", result_at_h_2c.short_description());
        println!("{self:?}  h-c: {}", result_at_h_c.short_description());
        println!("{self:?}   h: {}", result_at_h.short_description());
        println!("{self:?} tip: {}", result_at_tip.short_description());

        // if not present in retrieval queue -> should be treated as error
        let mut error_info = String::new();

        let maybe_save_snapshot = |block_hash, snapshot|
            self.provider.save_llmq_snapshot_into_db(block_hash, snapshot)
                .map_err(ProcessingError::from);


        if let Some(result) = result_at_h_4c {
            let should_process = is_from_snapshot || self.should_process_diff_result(&result, allow_invalid_merkle_roots, true);
            let MNListDiffResult {
                block_hash,
                masternode_list,
                added_masternodes,
                modified_masternodes,
                needed_masternode_lists,
                added_dapi_nodes,
                removed_dapi_nodes,
                ..
            } = result;
            let has_missed_lists = !needed_masternode_lists.is_empty();
            if should_process {
                let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
                if !has_missed_lists || !waiting_for_validation {
                    self.masternode_list_processed(
                        masternode_list,
                        added_masternodes,
                        modified_masternodes,
                        added_dapi_nodes,
                        removed_dapi_nodes,
                        |list_block_hash| self.cache.set_last_queried_qr_masternode_list_at_h_4c(list_block_hash)
                    )
                        .map_err(ProcessingError::from)?;
                }
            } else {
                error_info.push_str("Shouldn't process diff result at h - 4c\n");
            }
            if has_missed_lists {
                self.cache.add_needed_masternode_lists(needed_masternode_lists);
            }
            maybe_save_snapshot(block_hash, snapshot_h_4c.unwrap())?;
        }

        let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h_3c, allow_invalid_merkle_roots, true);
        let MNListDiffResult {
            block_hash,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists,
            added_dapi_nodes,
            removed_dapi_nodes,
            ..
        } = result_at_h_3c;
        let has_missed_lists = !needed_masternode_lists.is_empty();

        if should_process {
            let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
            if !has_missed_lists || !waiting_for_validation {
                self.masternode_list_processed(
                    masternode_list,
                    added_masternodes,
                    modified_masternodes,
                    added_dapi_nodes,
                    removed_dapi_nodes,
                    |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h_3c(list_block_hash)
                )
                    .map_err(ProcessingError::from)?;
            }
        } else {
            error_info.push_str("Shouldn't process diff result at h - 3c\n");
        }
        if has_missed_lists {
            self.cache.add_needed_masternode_lists(needed_masternode_lists);
        }
        maybe_save_snapshot(block_hash, snapshot_h_3c)?;

        let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h_2c, allow_invalid_merkle_roots, true);
        let MNListDiffResult {
            block_hash,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists,
            added_dapi_nodes,
            removed_dapi_nodes,
            ..
        } = result_at_h_2c;
        let has_missed_lists = !needed_masternode_lists.is_empty();
        if should_process {
            let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
            if !has_missed_lists || !waiting_for_validation {
                self.masternode_list_processed(
                    masternode_list,
                    added_masternodes,
                    modified_masternodes,
                    added_dapi_nodes,
                    removed_dapi_nodes,
                    |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h_2c(list_block_hash)
                )
                    .map_err(ProcessingError::from)?;
            }
        } else {
            error_info.push_str("Shouldn't process diff result at h - 2c\n");
        }

        if has_missed_lists {
            self.cache.add_needed_masternode_lists(needed_masternode_lists);
        }
        maybe_save_snapshot(block_hash, snapshot_h_2c)?;

        let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h_c, allow_invalid_merkle_roots, true);
        let MNListDiffResult {
            block_hash,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists,
            added_dapi_nodes,
            removed_dapi_nodes,
            ..
        } = result_at_h_c;
        let has_missed_lists = !needed_masternode_lists.is_empty();
        if should_process {
            let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
            if !has_missed_lists || !waiting_for_validation {
                self.masternode_list_processed(
                    masternode_list,
                    added_masternodes,
                    modified_masternodes,
                    added_dapi_nodes,
                    removed_dapi_nodes,
                    |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h_c(list_block_hash)
                )
                    .map_err(ProcessingError::from)?;
            }
        } else {
            error_info.push_str("Shouldn't process diff result at h - c\n");
        }
        if has_missed_lists {
            self.cache.add_needed_masternode_lists(needed_masternode_lists);
        }
        maybe_save_snapshot(block_hash, snapshot_h_c)?;


        let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h, allow_invalid_merkle_roots, true);
        let MNListDiffResult {
            block_hash,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists,
            added_dapi_nodes,
            removed_dapi_nodes,
            ..
        } = result_at_h;
        let has_missed_lists = !needed_masternode_lists.is_empty();
        if should_process {
            let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
            if !has_missed_lists || !waiting_for_validation {
                self.masternode_list_processed(
                    masternode_list,
                    added_masternodes,
                    modified_masternodes,
                    added_dapi_nodes,
                    removed_dapi_nodes,
                    |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h(list_block_hash)
                )
                    .map_err(ProcessingError::from)?;
            }
        } else {
            error_info.push_str("Shouldn't process diff result at h\n");
        }
        if has_missed_lists {
            self.cache.add_needed_masternode_lists(needed_masternode_lists);
        }
        let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_tip, allow_invalid_merkle_roots, true);
        if !should_process {
            error_info.push_str("Shouldn't process diff result at tip\n");
        }
        let MNListDiffResult {
            base_block_hash,
            block_hash,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists,
            added_dapi_nodes,
            removed_dapi_nodes,
            ..
        } = result_at_tip;
        let has_missed_lists = !needed_masternode_lists.is_empty();
        if should_process {
            let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
            if !has_missed_lists || !waiting_for_validation {
                self.masternode_list_processed(
                    masternode_list,
                    added_masternodes,
                    modified_masternodes,
                    added_dapi_nodes,
                    removed_dapi_nodes,
                    |list_block_hash | {
                        let last_queried_is_the_same = self.cache.get_last_queried_block_hash().eq(&block_hash);
                        println!("masternode at tip processed: {} same as queried? {}", block_hash.to_hex(), last_queried_is_the_same);
                        if self.cache.get_last_queried_block_hash().eq(&block_hash) {
                            self.cache.set_last_queried_qr_masternode_list_at_tip(list_block_hash);
                            self.cache.remove_block_hash_for_list_needing_quorums_validated(block_hash);
                        }
                    }
                )
                    .map_err(ProcessingError::from)?;
            }
            if has_missed_lists {
                self.cache.add_needed_masternode_lists(needed_masternode_lists);
            }
        }

        for (list_diff, snapshot) in mn_list_diff_list.into_iter().zip(quorum_snapshot_list.into_iter()) {
            let block = self.provider.last_block_for_block_hash(list_diff.block_hash, peer)
                .map_err(ProcessingError::from)?;
            let diff_result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::None, block.merkle_root).map_err(ProcessingError::from)?;
            let should_process = is_from_snapshot || self.should_process_diff_result(&diff_result, allow_invalid_merkle_roots, true);
            let MNListDiffResult {
                block_hash,
                masternode_list,
                added_masternodes,
                modified_masternodes,
                needed_masternode_lists,
                added_dapi_nodes,
                removed_dapi_nodes,
                ..
            } = diff_result;
            if should_process {
                let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
                if needed_masternode_lists.is_empty() || !waiting_for_validation {
                    self.masternode_list_processed(
                        masternode_list,
                        added_masternodes,
                        modified_masternodes,
                        added_dapi_nodes,
                        removed_dapi_nodes,
                        |list | {}
                    )
                        .map_err(ProcessingError::from)?;
                }
            }
            maybe_save_snapshot(block_hash, snapshot)?;
        }
        // println!("qr_info_result_from_message: {}", raise_peer_issue);
        if !error_info.is_empty() {
            Err(ProcessingError::InvalidResult(error_info))
        } else {
            let missed = self.cache.read_needed_masternode_lists(|lock| lock.clone());
            if missed.is_empty() {
                Ok((base_block_hash, block_hash))
            } else {
                self.cache.write_qr_info_retrieval_queue(|lock| lock.remove_one(&block_hash));
                let debug_info = missed.format();
                self.process_missing_masternode_lists(block_hash, missed);
                Err(ProcessingError::MissingLists(debug_info))
            }
        }
    }

    pub fn block_hash_for_height(&self, height: u32) -> [u8; 32] {
        self.provider.lookup_block_hash_by_height(height)
    }

    pub fn height_for_block_hash(&self, block_hash: [u8; 32]) -> u32 {
        if block_hash.is_zero() {
            return 0
        }
        if let Some(maybe_height) = self.cache.block_height_for_hash(block_hash) {
            return maybe_height;
        }
        let chain_height = self.provider.lookup_block_height_by_hash(block_hash);
        //println!("lookup_block_height_by_hash: {} = {}", block_hash.to_hex(), chain_height);
        if chain_height != u32::MAX {
            self.cache.cache_block_height_for_hash(block_hash, chain_height);
        }
        chain_height
    }

    // quorums
    pub fn quorum_entry_for_lock_request_id(&self, request_id: [u8; 32], llmq_type: LLMQType, block_hash: [u8; 32], block_height: u32, expiration_offset: u32) -> Option<LLMQEntry> {
        let mut debug_str = format!("{self:?} LLMQ ({llmq_type}: {block_height}: {}), request_id: {}", block_hash.to_hex(), request_id.to_hex());
        if block_hash.is_zero() {
            return None
        }
        let active_quorum = self.cache.active_quorum_of_type(llmq_type.clone(), block_hash);
        if active_quorum.is_some() {
            println!("{debug_str}: found active LLMQ: {}", active_quorum.as_ref()?.llmq_hash_hex());
            return active_quorum;
        }
        let result = match self.masternode_list_before_block_hash(block_hash) {
            None => {
                debug_str.push_str(": No masternode list found yet");
                println!("{debug_str}: No masternode list found yet at {}", block_hash.to_hex());
                None
            }
            Some(list) => {
                let known_height = list.known_height;
                let age = block_height - known_height;
                if age > expiration_offset {
                    debug_str.push_str(format!(": Masternode list for is too old (age: {age}, list: {known_height}").as_str());
                    None
                } else {
                    list.lock_llmq_request_id(request_id, llmq_type)
                }
            }
        };
        println!("{debug_str} = {}", result.as_ref().map_or("None".to_string(), LLMQEntry::llmq_hash_hex));
        result
    }

    pub fn quorum_entry_having_quorum_hash(&self, llmq_type: LLMQType, llmq_hash: [u8; 32], chain_lock_height: u32) -> Option<LLMQEntry> {
        let debug_str = format!("{self:?} LLMQ having quorum hash: (type: {llmq_type}, llmq_hash: {}, chain_lock_height: {chain_lock_height}", llmq_hash.to_hex());
        println!("{debug_str} -->");
        let list = self.masternode_list_for_block_hash(llmq_hash)
            .or_else(|| self.masternode_list_before_block_hash(llmq_hash));
        let result = match list {
            None => {
                println!("{debug_str}: No masternode list found yet {chain_lock_height} ({})", llmq_hash.to_hex());
                None
            }
            Some(masternode_list) => {
                // println!("MasternodeList Found: {}", masternode_list.format());
                // if height - masternode_list.known_height > 32 {
                //     warn!("{self:?} Masternode list is too old {}", masternode_list.known_height);
                //     return None;
                // }
                let maybe_list_quorum = masternode_list.quorum_entry_of_type_for_quorum_hash(llmq_type.clone(), llmq_hash);
                if maybe_list_quorum.is_none() {
                    self.quorum_entry_for_platform_having_quorum_hash(llmq_hash, chain_lock_height - 1)
                        .or_else(|| self.cache.active_quorum_of_type(llmq_type, llmq_hash))
                } else {
                    maybe_list_quorum.cloned()
                }
            }
        };
        println!("{debug_str} <-- {}", result.as_ref().map_or("None".to_string(), |q| format!("{}", q.llmq_hash_hex())));
        result

    }

    pub fn quorum_entry_for_chain_lock_request_id(&self, request_id: [u8; 32], block_hash: [u8; 32], block_height: u32) -> Option<LLMQEntry> {
        self.quorum_entry_for_lock_request_id(
            request_id,
            self.provider.chain_type().chain_locks_type(),
            block_hash,
            block_height,
            24)
    }
    pub fn quorum_entry_for_instant_send_request_id(&self, request_id: [u8; 32], block_hash: [u8; 32], block_height: u32) -> Option<LLMQEntry> {
        self.quorum_entry_for_lock_request_id(
            request_id,
            self.provider.chain_type().is_llmq_type(),
            block_hash,
            block_height,
            32)
    }
    pub fn quorum_entry_for_platform_having_quorum_hash(&self, quorum_hash: [u8; 32], block_height: u32) -> Option<LLMQEntry> {
        self.provider.lookup_block_by_height_or_last_terminal(block_height).ok()
            .and_then(|block| self.quorum_entry_for_platform_having_quorum_hash_with_block(quorum_hash, block))
    }
    pub fn quorum_entry_for_platform_having_quorum_hash_with_block(&self, quorum_hash: [u8; 32], block: Block) -> Option<LLMQEntry> {
        let Block { height, hash } = block;
        let debug_str = format!("{self:?} LLMQ (platform) having quorum hash: (block: {height}: {}, llmq_hash: {})", hash.to_hex(), quorum_hash.to_hex());
        println!("{debug_str} -->");
        let list = self.masternode_list_for_block_hash(hash)
            .or_else(|| self.masternode_list_before_block_hash(hash));
        let result = match list {
            None => {
                println!("{debug_str}: No masternode list found yet {block}");
                None
            }
            Some(masternode_list) => {
                if height - masternode_list.known_height > 32 {
                    warn!("{debug_str}: Masternode list is too old {}", masternode_list.known_height);
                    return None;
                }
                let llmq_type = self.provider.chain_type().platform_type();
                let maybe_list_quorum = masternode_list.quorum_entry_of_type_for_quorum_hash(llmq_type.clone(), quorum_hash);
                if maybe_list_quorum.is_none() {
                    self.quorum_entry_for_platform_having_quorum_hash(quorum_hash, height - 1)
                        .or_else(|| self.cache.active_quorum_of_type(llmq_type, quorum_hash))
                } else {
                    maybe_list_quorum.cloned()
                }
            }
        };
        println!("debug_str <-- {}", result.as_ref().map_or("None".to_string(), |q| format!("{}", q.llmq_hash_hex())));
        result
    }


    // masternode list

    pub fn load_masternode_list_at_block_hash(&self, block_hash: [u8; 32]) -> Result<MasternodeList, CoreProviderError> {
        self.provider.load_masternode_list_from_db(block_hash)
    }

    pub fn masternode_list_for_block_hash(&self, block_hash: [u8; 32]) -> Option<MasternodeList> {
        let maybe_list = self.cache.masternode_list_by_block_hash(block_hash);
        let is_genesis = self.provider.chain_type().genesis_hash().eq(&block_hash);
        if is_genesis || block_hash.is_zero() {
            return Some(MasternodeList::default());
        }
        let block_height = self.height_for_block_hash(block_hash);

        let result = if let Some(masternode_list) = maybe_list {
            Some(masternode_list)
        } else if self.cache.has_stub_for_masternode_list(block_hash) {
            self.load_masternode_list_at_block_hash(block_hash).ok()
        } else {
            None
        };
        println!("{self:?} masternode_list_for_block_hash: {block_height} {} ({}) -- {}", block_hash.to_hex(), block_hash.reversed().to_hex(), result.as_ref().map(|l| l.known_height.to_string()).unwrap_or("None".to_string()));
        result
    }
    pub fn masternode_list_before_block_hash(&self, block_hash: [u8; 32]) -> Option<MasternodeList> {
        let block_height = self.height_for_block_hash(block_hash);
        let mut closest_masternode_list = self.cache.read_mn_lists(|lock| {
            let mut min_distance = u32::MAX;
            let mut closest_masternode_list = None;
            for (block_hash_data, list) in lock.iter() {
                let masternode_list_block_height = self.height_for_block_hash(block_hash_data.clone());
                if block_height <= masternode_list_block_height {
                    continue;
                }
                let distance = block_height - masternode_list_block_height;
                if distance < min_distance {
                    min_distance = distance;
                    closest_masternode_list = Some(list.clone());
                }
            }
            closest_masternode_list
        });
        if self.provider.chain_type().is_mainnet() {
            if let Some(ref mut closest_masternode_list) = closest_masternode_list {
                if closest_masternode_list.known_height == 0 || closest_masternode_list.known_height == u32::MAX {
                    self.cache.write_mn_lists(|lock| {
                        if let Some(list) = lock.get_mut(&closest_masternode_list.block_hash) {
                            list.known_height = block_height;
                            closest_masternode_list.known_height = block_height;
                        }
                    })
                }
                if closest_masternode_list.known_height < CHAIN_LOCK_ACTIVATION_HEIGHT && block_height >= CHAIN_LOCK_ACTIVATION_HEIGHT {
                    return None; // special main net case
                }
            }
        }
        closest_masternode_list
    }

    pub fn closest_known_block_hash_for_block_hash(&self, block_hash: [u8; 32]) -> [u8; 32] {
        self.masternode_list_before_block_hash(block_hash)
            .map(|list| list.block_hash)
            .unwrap_or_else(|| self.provider.chain_type().genesis_hash())
    }

    pub fn earliest_masternode_list_block_height(&self) -> u32 {
        let mut earliest = u32::MAX;
        self.cache.read_mn_list_stubs(|lock| {
            for block_hash in lock.iter() {
                earliest = std::cmp::min(earliest, self.height_for_block_hash(block_hash.clone()));
            }
        });
        self.cache.read_mn_lists(|lock| {
            for block_hash in lock.keys() {
                earliest = std::cmp::min(earliest, self.height_for_block_hash(block_hash.clone()));
            }
        });
        earliest
    }
    pub fn last_masternode_list_block_height(&self) -> u32 {
        let mut last = 0;
        self.cache.read_mn_list_stubs(|lock| {
            for block_hash in lock.iter() {
                last = std::cmp::max(last, self.height_for_block_hash(block_hash.clone()));
            }
        });
        self.cache.read_mn_lists(|lock| {
            for block_hash in lock.keys() {
                last = std::cmp::max(last, self.height_for_block_hash(block_hash.clone()));
            }
        });
        if last == 0 {
            u32::MAX
        } else {
            last
        }
    }

    pub fn load_masternode_list(
        &self,
        masternodes: Vec<MasternodeEntry>,
        quorums: Vec<LLMQEntry>,
        block_hash: [u8; 32],
        block_height: u32,
        quorums_active: bool
    ) -> MasternodeList {
        let masternodes_map = masternode_vec_to_map(masternodes);
        let quorums_map = quorum_vec_to_map(quorums);
        MasternodeList::new(masternodes_map, quorums_map, block_hash, block_height, quorums_active)
    }

    pub fn should_update_qr_info(&self, block: Block) -> bool {
        let Block { hash, height } = block;
        let chain_type = self.provider.chain_type();
        let DKGParams { mining_window_end, interval, .. } = dkg_rotation_params(chain_type.clone());
        let need_update = match self.cache.get_last_queried_qr_masternode_list_at_h() {
            None => true,
            Some(last_queried) =>
                last_queried.has_unverified_rotated_quorums(chain_type) ||
                    height % interval == mining_window_end && height >= self.height_for_block_hash(last_queried.block_hash) + mining_window_end,
        };
        let cached = self.cache.has_masternode_list_at(hash);
        if cached {
            println!("{self:?} Already have that masternode list (or in stub) {}", height);
            return false;
        }
        self.cache_query(hash);
        true
    }
    pub fn cache_query(&self, hash: [u8; 32]) {
        self.cache.set_last_queried_block_hash(hash);
        self.cache.add_block_hash_for_list_needing_quorums_validated(hash);
    }

    // find block height to which the lists can be safely removed from storage
    pub fn calculate_outdated_height(&self) -> u32 {
        let mut height_to_delete = u32::MAX;
        if let Some(list) = self.cache.get_last_queried_mn_masternode_list() {
            height_to_delete = if list.known_height == 0 || list.known_height == u32::MAX {
                self.height_for_block_hash(list.block_hash)
            } else {
                list.known_height
            };
            if let Some(oldest_hash_in_mn_diff_queue) = self.cache.read_mn_list_retrieval_queue(RetrievalQueue::first) {
                let oldest_height = self.height_for_block_hash(oldest_hash_in_mn_diff_queue);
                if height_to_delete > oldest_height {
                    height_to_delete = oldest_height;
                }
            }
        } else {
            // Don't remove if we didn't get updates from mnlistdiff
            return height_to_delete;
        }
        if let Some(list) = self.cache.get_last_queried_qr_masternode_list_at_h_4c()
            .or_else(|| self.cache.get_last_queried_qr_masternode_list_at_h_3c()) {
            let h = if list.known_height == 0 || list.known_height == u32::MAX {
                self.height_for_block_hash(list.block_hash)
            } else {
                list.known_height
            };
            if height_to_delete > h {
                height_to_delete = h;
            }
            if let Some(oldest_hash_in_qr_info_queue) = self.cache.read_qr_info_retrieval_queue(RetrievalQueue::first) {
                let oldest_height = self.height_for_block_hash(oldest_hash_in_qr_info_queue);
                if height_to_delete > oldest_height {
                    height_to_delete = oldest_height;
                }
            }
        } else {
            // Don't remove if we didn't get updates from qrinfo
            return height_to_delete;
        }
        height_to_delete
    }

    pub fn get_recent_mn_list(&self, block: Block) {
        let Block { hash, height } = block;
        if self.cache.has_latest_block_in_mn_list_retrieval_queue_with_hash(&hash) {
            // We are asking for the same as the last one
            return
        }
        let has_cached = self.cache.has_masternode_list_at(hash);
        if has_cached {
            println!("{} Already have that masternode list (or in stub) {}", self.provider.chain_type().name(), height);
            return
        }
        self.cache.set_last_queried_block_hash(hash);
        self.cache.add_block_hash_for_list_needing_quorums_validated(hash);
        println!("{} MasternodeListService.Getting masternode list {} ({})", self.provider.chain_type().name(), height, hash.to_hex());
        let has_empty_request_queue = self.cache.write_mn_list_retrieval_queue(|lock| {
            let is_empty = lock.queue.is_empty();
            assert!(!hash.is_zero(), "the hash data must not be empty");
            lock.add(hash, self);
            is_empty
        });
        if has_empty_request_queue {
            self.provider.dequeue_masternode_list(false);
        }
    }

    pub fn get_recent_qr_info(&self, block: Block) {
        let has_already_requested = self.cache.read_qr_info_retrieval_queue(|lock| lock.has_latest_block_with_hash(&block.hash));

        if has_already_requested {
            // We are asking for the same as the last one
            return
        }
        let should_update_qr_info = self.should_update_qr_info(block.clone());
        if !should_update_qr_info {
            return
        }
        println!("{} QuorumRotationService.Getting masternode list {} ({})", self.provider.chain_type().name(), block.height, block.hash.to_hex());
        let has_empty_request_queue = self.cache.write_qr_info_retrieval_queue(|lock| {
            let is_empty = lock.queue.is_empty();
            assert!(!block.hash.is_zero(), "the hash data must not be empty");
            lock.add(block.hash, self);
            is_empty
        });
        if has_empty_request_queue {
            self.provider.dequeue_masternode_list(true);
        }
    }
}

impl MasternodeProcessor {
    pub fn should_process_diff_with_range(
        &self,
        is_dip24: bool,
        base_block_hash: [u8; 32],
        block_hash: [u8; 32],
        peer: *const std::os::raw::c_void
    ) -> Result<u8, ProcessingError> {
        let block_height = self.height_for_block_hash(block_hash);
        if block_height == u32::MAX {
            warn!("{self:?} MNL unknown block_hash {}", block_hash.reversed().to_hex());
            return Err(ProcessingError::UnknownBlockHash(block_hash))
        }
        if !self.provider.remove_request_in_retrieval(is_dip24, base_block_hash, block_hash) {
            let base_block_height = self.height_for_block_hash(base_block_hash);
            warn!("{self:?} MNL unexpected diff [{base_block_height}..{block_height}] ({}..{})", base_block_hash.reversed().to_hex(), block_hash.reversed().to_hex());
            return Err(ProcessingError::PersistInRetrieval(base_block_hash, block_hash))
        }
        let list = self.masternode_list_for_block_hash(block_hash);
        let need_verify_rotated_quorums = is_dip24 && (self.cache.get_last_queried_qr_masternode_list_at_h().is_none() || self.cache.get_last_queried_qr_masternode_list_at_h().unwrap().has_unverified_rotated_quorums(self.provider.chain_type()));
        let need_verify_regular_quorums = !is_dip24 && (list.is_none() || list.unwrap().has_unverified_regular_quorums(self.provider.chain_type()));
        let no_need_to_verify_quorums = !(need_verify_rotated_quorums || need_verify_regular_quorums);
        let has_locally_stored = self.cache.has_masternode_list_at(block_hash);
        if has_locally_stored && no_need_to_verify_quorums {
            warn!("{self:?} MNL already persist and doesn't contain unverified llmq: {block_height}: {}", block_hash.reversed().to_hex());
            // self.provider.remove_from_retrieval_queue(is_dip24, block_hash);
            let queue_handler = |lock: &mut RetrievalQueue| {
                let _removed = lock.queue.shift_remove(&block_hash);
                CacheState::queue(lock.queue.len(), lock.max_amount)
            };
            let sync_state = if is_dip24 {
                self.cache.write_qr_info_retrieval_queue(queue_handler)
            } else {
                self.cache.write_mn_list_retrieval_queue(queue_handler)
            };
            self.provider.notify_sync_state(if is_dip24 {
                self.cache.write_qr_info_retrieval_queue(queue_handler)
            } else {
                self.cache.write_mn_list_retrieval_queue(queue_handler)
            });
            // TODO: notify sync state change
            return Err(ProcessingError::LocallyStored(block_height, block_hash));
        }
        match self.masternode_list_for_block_hash(base_block_hash) {
            None if !self.provider.chain_type().genesis_hash().eq(&base_block_hash) && !base_block_hash.is_zero() => {
                self.provider.issue_with_masternode_list_from_peer(is_dip24, peer);
                let base_block_height = self.height_for_block_hash(base_block_hash);
                warn!("{self:?} MNL has no base at: {base_block_height}: {}", base_block_hash.reversed().to_hex());
                Err(ProcessingError::HasNoBaseBlockHash(base_block_hash))
            }
            _ => Ok(0)
        }
    }

    //fn dapi_addresses_change_list(&)

    pub fn masternode_list_processed<T>(
        &self,
        masternode_list: MasternodeList,
        added_masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
        modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
        added_dapi_nodes: Vec<[u8; 16]>,
        removed_dapi_nodes: Vec<[u8; 16]>,
        mut query_handler: T
    ) -> Result<bool, CoreProviderError> where T: FnMut([u8; 32]) {
        let block_hash = masternode_list.block_hash;
        let known_height = masternode_list.known_height;
        let mut changed = Vec::from_iter(added_masternodes.values().cloned());


        changed.extend(modified_masternodes.values().cloned());
        // if let Some(old_list) = self.cache.masternode_list_by_block_hash(block_hash) {
        //     masternode_list.merged_with_old_list(old_list, known_height);
        // }
        // if let Some(ref dapi_address_handler) = self.dapi_address_handler {
        //     dapi_address_handler.remove_nodes(removed_dapi_nodes);
        //     dapi_address_handler.add_nodes(added_dapi_nodes);
        // }
        query_handler(block_hash);
        self.provider.update_address_usage_of_masternodes(changed);
        self.cache.remove_from_awaiting_quorum_validation_list(block_hash);
        self.cache.remove_stub_for_masternode_list(block_hash);
        println!("ADD LIST to cache: {}", block_hash.to_hex());
        let count = self.cache.add_masternode_list(block_hash, masternode_list.clone());
        self.provider.save_masternode_list_into_db(block_hash, modified_masternodes)
    }

    fn process_missing_masternode_lists(&self, block_hash: [u8; 32], lists: HashSet<[u8; 32]>) {
        self.cache.add_to_awaiting_quorum_validation_list(block_hash);
        self.cache.clear_needed_masternode_lists();
        self.cache.write_mn_list_retrieval_queue(|lock| {
            lock.queue.extend(lists);
            lock.queue.insert(block_hash);
            lock.update_retrieval_queue(self);
        });
        self.provider.dequeue_masternode_list(false);
    }

    fn should_process_diff_result(&self, result: &MNListDiffResult, allow_invalid_merkle_roots: bool, is_dip24: bool) -> bool {
        let persist = is_dip24 || self.cache.read_mn_list_retrieval_queue(|lock| lock.queue.contains(&result.block_hash));
        persist && (allow_invalid_merkle_roots || result.is_valid())
    }


    fn llmq_modifier_type_for(&self, llmq_type: LLMQType, work_block_hash: [u8; 32], work_block_height: u32) -> LLMQModifierType {
        //println!("llmq_modifier_type_for: {} {} {}", llmq_type, work_block_height, work_block_hash.to_hex());
        if self.provider.chain_type().core20_is_active_at(work_block_height) {
            let work_block_hash = self.provider.lookup_block_hash_by_height(work_block_height);
            if work_block_hash.is_zero() {
                println!("{self:?} llmq_modifier_type: block for height {} not found -> using zero", work_block_height);
            }
            let best_cl_signature = if let Some(best_cl_signature) = self.cache.maybe_cl_signature(work_block_hash) {
                best_cl_signature
            } else {
                println!("{self:?} llmq_modifier_type: chain lock signature for block hash {} ({}) not found -> using zero", work_block_hash.to_hex(), work_block_hash.reversed().to_hex());
                [0u8; 96]
            };
            LLMQModifierType::CoreV20(llmq_type, work_block_height, best_cl_signature)
        } else {
            LLMQModifierType::PreCoreV20(llmq_type, work_block_hash)
        }
    }

    fn get_list_diff_result_with_base_lookup(
        &self,
        list_diff: MNListDiff,
        verification_context: LLMQVerificationContext,
        merkle_root: [u8; 32],
    ) -> Result<MNListDiffResult, CoreProviderError> {
        let base_block_hash = list_diff.base_block_hash;
        if let Some(base_list) = self.masternode_list_for_block_hash(base_block_hash) {
            Ok(self.get_list_diff_result(base_list, list_diff, merkle_root, verification_context))
        } else {
            Err(CoreProviderError::NullResult(format!("No base masternode list for {} ({})", base_block_hash.to_hex(), base_block_hash.reversed().to_hex())))
        }
    }

    pub fn get_list_diff_result(
        &self,
        base_list: MasternodeList,
        list_diff: MNListDiff,
        merkle_root: [u8; 32],
        verification_context: LLMQVerificationContext,
    ) -> MNListDiffResult {
        let skip_removed_masternodes = list_diff.should_skip_removed_masternodes();
        let base_block_hash = list_diff.base_block_hash;
        let block_hash = list_diff.block_hash;
        let base_block_height = list_diff.base_block_height;
        let block_height = list_diff.block_height;
        let quorums_cl_sigs = list_diff.quorums_cls_sigs;
        // let (base_masternodes, base_quorums) = match base_list {
        //     Some(list) => (list.masternodes.clone(), list.quorums.clone()),
        //     None => (BTreeMap::new(), BTreeMap::new()),
        // };
        let mut coinbase_transaction = list_diff.coinbase_transaction;
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        let (added_masternodes,
            modified_masternodes,
            masternodes,
            added_dapi_addresses,
            removed_dapi_addresses,
        ) = self.classify_masternodes(
            base_list.masternodes,
            list_diff.added_or_modified_masternodes,
            list_diff.deleted_masternode_hashes,
            block_height,
            block_hash,
        );
        let mut added_quorums = list_diff.added_quorums;

        let (has_valid_quorums, missed_lists) = self.verify_added_quorums(verification_context, &mut added_quorums, skip_removed_masternodes, quorums_cl_sigs);
        let (added_quorums, quorums) = self.process_quorums(
            base_list.quorums,
            added_quorums,
            list_diff.deleted_quorums,
        );
        let has_added_quorums = !added_quorums.is_empty();

        let has_added_rotated_quorums = added_quorums.iter().any(|q| q.llmq_type == self.provider.chain_type().isd_llmq_type());
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
        // It's good to cache lists to use it inside processing session
        // Here we use opaque-like pointer which we initiate on the C-side to sync its lifetime with runtime
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_masternode_list_to_json(&masternode_list, self.height_for_block_hash(block_hash));
        //self.cache.add_masternode_list(block_hash, Arc::new(masternode_list.clone()));
        let has_found_coinbase = coinbase_transaction.has_found_coinbase(&merkle_tree.hashes);

        let has_valid_coinbase = merkle_tree.has_root(merkle_root);
        // println!("has_valid_coinbase for {}: {}", desired_merkle_root.to_hex(), has_valid_coinbase);
        let has_valid_mn_list_root = masternode_list.has_valid_mn_list_root(&coinbase_transaction);
        let has_valid_llmq_list_root = !quorums_active || masternode_list.has_valid_llmq_list_root(&coinbase_transaction);
        let result = MNListDiffResult {
            base_block_height,
            block_height,
            base_block_hash,
            block_hash,
            has_found_coinbase,
            has_valid_coinbase,
            has_valid_mn_list_root,
            has_valid_llmq_list_root,
            has_valid_quorums,
            has_added_quorums,
            has_added_rotated_quorums,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists: missed_lists,
            added_dapi_nodes: added_dapi_addresses,
            removed_dapi_nodes: removed_dapi_addresses,
        };
        result
    }

    #[allow(clippy::type_complexity)]
    fn classify_masternodes(
        &self,
        base_masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
        added_or_modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
        deleted_masternode_hashes: Vec<[u8; 32]>,
        block_height: u32,
        block_hash: [u8; 32],
    ) -> (
        BTreeMap<[u8; 32], MasternodeEntry>,
        BTreeMap<[u8; 32], MasternodeEntry>,
        BTreeMap<[u8; 32], MasternodeEntry>,
        Vec<[u8; 16]>,
        Vec<[u8; 16]>,
    ) {
        // println!("base_masternodes:\n{}", format_masternodes_map(&base_masternodes));
        // let (mut modified_masternodes, added_masternodes): (BTreeMap<[u8; 32], MasternodeEntry>, BTreeMap<[u8; 32], MasternodeEntry>) =
        //     added_or_modified_masternodes
        //         .into_iter()
        //         .partition(|(hash, _)| base_masternodes.contains_key(hash));

        let mut added_masternodes = BTreeMap::new();
        let mut modified_masternodes = BTreeMap::new();
        let mut added_addresses = vec![];
        let mut removed_addresses = vec![];

        for (hash, added_or_modified) in added_or_modified_masternodes {
            let maybe_old = base_masternodes.get(&hash);
            if let Some(old_node) = base_masternodes.get(&hash) {
                if old_node.is_valid && !added_or_modified.is_valid {
                    removed_addresses.push(added_or_modified.socket_address.ip_address.clone());
                } else if !old_node.is_valid && added_or_modified.is_valid {
                    added_addresses.push(added_or_modified.socket_address.ip_address.clone());
                }
                modified_masternodes.insert(hash, added_or_modified);
            } else {
                if added_or_modified.is_valid {
                    added_addresses.push(added_or_modified.socket_address.ip_address.clone());
                }
                added_masternodes.insert(hash, added_or_modified);
            }
        }

        // let added_masternodes = added_or_modified_masternodes
        //     .iter()
        //     .filter(|&(k, _)| !base_masternodes.contains_key(k))
        //     .map(|(k, v)| (*k, v.clone()))
        //     .collect::<BTreeMap<_, _>>();
        //
        // let mut modified_masternodes = added_or_modified_masternodes
        //     .iter()
        //     .filter(|&(k, _)| base_masternodes.contains_key(k))
        //     .map(|(k, v)| (*k, v.clone()))
        //     .collect::<BTreeMap<_, _>>();

        let mut masternodes = if !base_masternodes.is_empty() {
            let mut old_masternodes = base_masternodes;
            for hash in deleted_masternode_hashes {
                if let Some(removed) = old_masternodes.remove(&hash.reversed()) {
                    if removed.is_valid {
                        removed_addresses.push(removed.socket_address.ip_address);
                    }
                }
            }
            old_masternodes.extend(added_masternodes.clone());
            old_masternodes
        } else {
            added_masternodes.clone()
        };

        // for (hash, modified) in &mut modified_masternodes {
        //     if let Some(old) = masternodes.get_mut(hash) {
        //         if old.update_height < modified.update_height {
        //             modified.update_with_previous_entry(old, block_height, block_hash);
        //             old.confirm_at_height_if_need(block_height);
        //         }
        //         masternodes.insert(*hash, modified.clone());
        //     }
        // }
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
        // println!("added_masternodes:\n{}", format_masternodes_map(&added_masternodes));
        // println!("modified_masternodes:\n{}", format_masternodes_map(&modified_masternodes));
        // println!("masternodes:\n{}", format_masternodes_map(&masternodes));
        (added_masternodes, modified_masternodes, masternodes, added_addresses, removed_addresses)
    }

    fn verify_added_quorums(
        &self,
        verification_context: LLMQVerificationContext,
        added_quorums: &mut Vec<LLMQEntry>,
        skip_removed_masternodes: bool,
        quorums_cl_sigs: BTreeMap<[u8; 96], HashSet<u16>>,
    ) -> (bool, HashSet<[u8; 32]>) {
        let mut has_valid_quorums = true;
        let mut block_hashes_for_missed_lists = HashSet::<[u8; 32]>::new();
        if verification_context.should_validate_quorums() {
            added_quorums
                .iter_mut()
                .enumerate()
                .for_each(|(index, quorum)| {
                    let maybe_quorum_sig = quorums_cl_sigs.iter().find_map(|(signature, index_set)|
                        if index_set.iter().any(|i| *i == index as u16) { Some(signature) } else { None });
                    let llmq_height = self.height_for_block_hash(quorum.llmq_hash);
                    if let Some(signature) = maybe_quorum_sig {
                        //println!("verify_added_quorums: found signature {} at index: {}", signature.to_hex(), index);
                        if llmq_height != u32::MAX {
                            let work_block_height = llmq_height - 8;
                            let work_block_hash = self.provider.lookup_block_hash_by_height(work_block_height);
                            if work_block_hash.is_zero() {
                                warn!("{self:?} zero hash for {}", work_block_height);
                            }
                            self.cache.add_cl_signature(work_block_hash, signature.clone());
                        } else {
                            warn!("{self:?} unknown height for {} ({})", quorum.llmq_hash.to_hex(), quorum.llmq_hash.reversed().to_hex());
                        }
                    } else {
                        warn!("{self:?} couldn't find llmq signature for added quorum {} ({}) at index {}", quorum.llmq_hash.to_hex(), quorum.llmq_hash.reversed().to_hex(), index);
                    }
                    match verification_context.has_reason_to_skip_validation(quorum.llmq_type.clone(), self.provider.chain_type(), llmq_height) {
                        Some(skip_status) => {
                            quorum.verified = LLMQEntryVerificationStatus::Skipped(skip_status);
                        }
                        None => match self.validate_quorum(quorum, skip_removed_masternodes, &mut block_hashes_for_missed_lists) {
                            Ok(()) => {
                                quorum.verified = LLMQEntryVerificationStatus::Verified;
                                has_valid_quorums &= true;
                            }
                            Err(CoreProviderError::BlockHashNotFoundAt(height)) => {
                                error!("{self:?} LLMQ validation: BlockHashNotFoundAt: ({height})");
                                has_valid_quorums &= false;
                                panic!("missing block for height: {}", height)
                            },
                            Err(error) => {
                                warn!("{self:?} LLMQ validation Error: ({:?})", error);
                                has_valid_quorums &= false;
                            }
                        }
                    }
                })
        }
        (has_valid_quorums, block_hashes_for_missed_lists)
    }

    fn process_quorums(
        &self,
        mut base_quorums: BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>,
        added_quorums: Vec<LLMQEntry>,
        deleted_quorums: BTreeMap<LLMQType, Vec<[u8; 32]>>,
    ) -> (
        Vec<LLMQEntry>,
        BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>>,
    ) {
        //println!("process_quorums: \n\tbase: {}\n\tadded: {}\n\tdeleted: {}", base_quorums.format(), added_quorums.format(), deleted_quorums.format());
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

    fn find_valid_masternodes_for_quorum(
        &self,
        quorum: &LLMQEntry,
        block_height: u32,
        skip_removed_masternodes: bool,
        masternodes: &BTreeMap<[u8; 32], MasternodeEntry>,
    ) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
        if quorum.index != u16::MAX {
            self.get_rotated_masternodes_for_quorum(quorum.llmq_type.clone(), quorum.llmq_hash, block_height, skip_removed_masternodes)
        } else {
            self.get_non_rotated_masternodes_for_quorum(quorum.llmq_type.clone(), quorum.llmq_hash, block_height, quorum, masternodes)
        }
    }

    fn validate_quorum(&self, quorum: &mut LLMQEntry, skip_removed_masternodes: bool, missing_lists: &mut HashSet<[u8; 32]>) -> Result<(), CoreProviderError> {
        let llmq_block_hash = quorum.llmq_hash;
        let maybe_masternode_list = self.masternode_list_for_block_hash(llmq_block_hash);
        // let masternode_list = self.masternode_list_for_block_hash(llmq_block_hash)
        //     .ok_or(CoreProviderError::MissedMasternodeListAt(llmq_block_hash))?;
        let block_height = self.height_for_block_hash(llmq_block_hash);
        if let Some(masternode_list) = maybe_masternode_list {
            // if block_height == 2188848 {
            //     let masternodes = masternode_list.masternodes.values().map(|entry| format!("{} : {}", entry.provider_registration_transaction_hash.reversed().to_hex(), entry.is_valid)).collect::<Vec<_>>().join("\n ");
            //     println!("{}", masternodes);
            // }
            let valid_masternodes = self.find_valid_masternodes_for_quorum(quorum, block_height, skip_removed_masternodes, &masternode_list.masternodes)?;
            if block_height == 2188848 {
                let masternodes = valid_masternodes.iter().map(|entry| format!("{} : {}", entry.provider_registration_transaction_hash.reversed().to_hex(), entry.is_valid)).collect::<Vec<_>>().join("\n ");
                println!("v {}", masternodes);
            }
            let payload_status = validate_payload(quorum);
            if !payload_status.is_ok() {
                quorum.verified = LLMQEntryVerificationStatus::Invalid(LLMQValidationError::InvalidPayload(payload_status.clone()));
                return Err(CoreProviderError::QuorumValidation(LLMQValidationError::InvalidPayload(payload_status)));
            }
            let result = validate(quorum, valid_masternodes, block_height);
            return result
        } else if block_height != u32::MAX && !llmq_block_hash.is_zero() {
            warn!("LLMQ was skipped from validation (missing masternode list at {}): {}: {}", block_height, quorum.llmq_type , quorum.llmq_hash_hex());
            quorum.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::UnknownBlock(llmq_block_hash));
            missing_lists.insert(llmq_block_hash);
        } else {
            quorum.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(llmq_block_hash));
        }
        Ok(())
    }

    fn get_non_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: [u8; 32],
        block_height: u32,
        quorum: &LLMQEntry,
        masternodes: &BTreeMap<[u8; 32], MasternodeEntry>,
    ) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
        Ok(llmq::valid_masternodes(
            quorum,
            self.provider.chain_type(),
            masternodes,
            block_height - 8,
            self.llmq_modifier_type_for(llmq_type, block_hash, block_height - 8)))
    }

    fn quorum_quarter_members_by_reconstruction_type(
        &self,
        reconstruction_type: LLMQQuarterReconstructionType,
        llmq_params: &LLMQParams,
        work_block_height: u32,
    ) -> Result<Vec<Vec<MasternodeEntry>>, CoreProviderError> {
        let work_block_hash = self.provider.lookup_block_hash_by_height(work_block_height);
        if work_block_hash.is_zero() {
            warn!("quorum_quarter_members_by_reconstruction_type: empty work block hash for {work_block_height}")
        }
        let masternode_list = self.masternode_list_for_block_hash(work_block_hash)
            .ok_or(CoreProviderError::MissedMasternodeListAt(work_block_hash))?;
        let llmq_type = llmq_params.r#type.clone();
        let quorum_count = llmq_params.signing_active_quorum_count as usize;
        let quorum_size = llmq_params.size as usize;
        let quarter_size = quorum_size / 4;
        let quorum_modifier_type = self.llmq_modifier_type_for(llmq_type, work_block_hash, work_block_height);
        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
        match reconstruction_type {
            LLMQQuarterReconstructionType::New { previous_quarters, skip_removed_masternodes } => {
                let (used_at_h_masternodes, unused_at_h_masternodes, used_at_h_indexed_masternodes) =
                    masternode_list.usage_info(previous_quarters, skip_removed_masternodes, quorum_count);
                Ok(apply_skip_strategy_of_type(LLMQQuarterUsageType::New(used_at_h_indexed_masternodes), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size))
            },
            LLMQQuarterReconstructionType::Snapshot => {
                if let Some(snapshot) = self.cache.maybe_snapshot(work_block_hash) {
                    let (used_at_h_masternodes, unused_at_h_masternodes) =
                        usage_info_from_snapshot(&masternode_list.masternodes, &snapshot, quorum_modifier, work_block_height);
                    Ok(apply_skip_strategy_of_type(LLMQQuarterUsageType::Snapshot(snapshot), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size))
                } else {
                    Err(CoreProviderError::NoSnapshot)
                }

                // self.provider.find_snapshot(work_block_hash, &self.cache)
                //     .map(|snapshot| {
                //         let (used_at_h_masternodes, unused_at_h_masternodes) =
                //             usage_info_from_snapshot(masternode_list, &snapshot, quorum_modifier, work_block_height);
                //         apply_skip_strategy_of_type(LLMQQuarterUsageType::Snapshot(snapshot), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size)
                //     })
            }
        }
    }


    fn rotate_members(
        &self,
        cycle_base_height: u32,
        llmq_params: LLMQParams,
        skip_removed_masternodes: bool,
        // cache: &Arc<RwLock<MasternodeProcessorCache>>
        // cached_mn_lists: &BTreeMap<UInt256, MasternodeList>,
        // cached_llmq_snapshots: &BTreeMap<UInt256, LLMQSnapshot>,
        // cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
        // unknown_mn_lists: &mut Vec<UInt256>,
    ) -> Result<Vec<Vec<MasternodeEntry>>, CoreProviderError> {
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let work_block_height_for_index = |index: u32| (cycle_base_height - index * cycle_length) - 8;
        // Reconstruct quorum members at h - 3c from snapshot
        let q_h_m_3c = self.quorum_quarter_members_by_reconstruction_type(LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(3))?;
        // Reconstruct quorum members at h - 2c from snapshot
        let q_h_m_2c = self.quorum_quarter_members_by_reconstruction_type(LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(2))?;
        // Reconstruct quorum members at h - c from snapshot
        let q_h_m_c = self.quorum_quarter_members_by_reconstruction_type(LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(1))?;
        // Determine quorum members at new index
        let reconstruction_type = LLMQQuarterReconstructionType::New { previous_quarters:  [&q_h_m_c, &q_h_m_2c, &q_h_m_3c], skip_removed_masternodes };
        let quarter_new = self.quorum_quarter_members_by_reconstruction_type(reconstruction_type, &llmq_params, work_block_height_for_index(0))?;
        let mut quorum_members =
            Vec::<Vec<MasternodeEntry>>::with_capacity(num_quorums);
        (0..num_quorums).for_each(|index| {
            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_3c, index);
            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_2c, index);
            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_c, index);
            add_quorum_members_from_quarter(&mut quorum_members, &quarter_new, index);
        });
        Ok(quorum_members)
    }

    /// Determine masternodes which is responsible for signing at this quorum index
    #[allow(clippy::too_many_arguments)]
    pub fn get_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: [u8; 32],
        block_height: u32,
        skip_removed_masternodes: bool,
    ) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
        let mut llmq_members_lock = self.cache.llmq_members.write().unwrap();
        let cached_members_of_llmq_type_opt = llmq_members_lock.get_mut(&llmq_type);
        if cached_members_of_llmq_type_opt.is_some() {
            if let Some(cached_members) = cached_members_of_llmq_type_opt.as_ref().unwrap().get(&block_hash).cloned() {
                drop(llmq_members_lock);
                return Ok(cached_members);
            }
        } else {
            llmq_members_lock.insert(llmq_type.clone(), BTreeMap::new());
        }

        let cached_members_of_llmq_type = llmq_members_lock.get_mut(&llmq_type).unwrap();
        let llmq_params = llmq_type.params();
        let quorum_index = block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = block_height - quorum_index;
        let cycle_base_hash = self.provider.lookup_block_hash_by_height(cycle_base_height);
        let mut llmq_indexed_members_lock = self.cache.llmq_indexed_members.write().unwrap();
        if let Some(map_by_type_indexed) = llmq_indexed_members_lock.get(&llmq_type) {
            let indexed_hash = LLMQIndexedHash::from((cycle_base_hash, quorum_index));
            if let Some(cached_members) = map_by_type_indexed.get(&indexed_hash).cloned() {
                cached_members_of_llmq_type.insert(block_hash, cached_members.clone());
                drop(llmq_members_lock);
                drop(llmq_indexed_members_lock);
                return Ok(cached_members);
            }
        } else {
            llmq_indexed_members_lock.insert(llmq_type.clone(), BTreeMap::new());
        }
        drop(llmq_indexed_members_lock);
        let rotated_members = self.rotate_members(cycle_base_height, llmq_params, skip_removed_masternodes)?;
        let result = if let Some(rotated_members_at_index) = rotated_members.get(quorum_index as usize) {
            cached_members_of_llmq_type.insert(block_hash, rotated_members_at_index.clone());
            Ok(rotated_members_at_index.clone())
        } else {
            Err(CoreProviderError::NullResult(format!("No rotated_members for llmq index {} ({})", quorum_index, block_hash.to_hex())))
        };
        drop(llmq_members_lock);

        self.cache.write_llmq_indexed_members(|lock| {
            lock.get_mut(&llmq_type)
                .unwrap()
                .extend(rotated_members.into_iter()
                    .enumerate()
                    .map(|(index, members)|
                        (LLMQIndexedHash::from((cycle_base_hash, index)), members)));
        });
        result
    }

    pub fn read_list_diff_from_message(&self, message: &[u8], offset: &mut usize, protocol_version: u32) -> Result<MNListDiff, ProcessingError> {
        MNListDiff::new(message, offset, self, protocol_version)
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
    quorum_modifier: [u8; 32],
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
fn find_cl_signature_at_index(quorums_cl_sigs: &BTreeMap<[u8; 96], HashSet<u16>>, index: u16) -> Option<[u8; 96]> {
    quorums_cl_sigs.iter().find_map(|(signature, index_set)|
        if index_set.iter().any(|i| *i == index) { Some(*signature) } else { None })
}

fn sort_scored_masternodes(mut scored_masternodes: Vec<([u8; 32], MasternodeEntry)>) -> Vec<MasternodeEntry> {
    scored_masternodes.sort_by(|(s1, _), (s2, _)| s2.reversed().cmp(&s1.reversed()));
    scored_masternodes.into_iter().map(|(s, node)| node).collect()
}
fn usage_info_from_snapshot(masternodes: &BTreeMap<[u8; 32], MasternodeEntry>, snapshot: &LLMQSnapshot, quorum_modifier: [u8; 32], work_block_height: u32) -> (Vec<MasternodeEntry>, Vec<MasternodeEntry>) {
    let scored_masternodes = score_masternodes_map(masternodes, quorum_modifier, work_block_height, false);
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
    quorum_modifier: [u8; 32],
    block_height: u32,
) -> Vec<MasternodeEntry> {
    let scored_masternodes = masternodes
        .into_iter()
        .filter_map(|entry| entry.score(quorum_modifier, block_height)
            .map(|score| (score, entry)))
        .collect::<Vec<_>>();
    sort_scored_masternodes(scored_masternodes)
}

