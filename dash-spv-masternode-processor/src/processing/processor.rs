use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use byte::BytesExt;
use hashes::hex::ToHex;
use crate::common;
use dash_spv_crypto::llmq::{LLMQEntry, LLMQModifierType};
use dash_spv_crypto::network::{LLMQType, LLMQParams, CHAIN_LOCK_ACTIVATION_HEIGHT, IHaveChainSettings};
use dash_spv_crypto::crypto::byte_util::{Reversed, Zeroable};
use dash_spv_crypto::network::llmq_type::{dkg_rotation_params, DKGParams};
use crate::common::{Block, LLMQSnapshotSkipMode};
use crate::models::{LLMQIndexedHash, LLMQSnapshot, LLMQVerificationContext, MasternodeEntry, MasternodeList, mn_list_diff::MNListDiff, QRInfo, llmq};
use crate::models::masternode_list::{score_masternodes_map};
use crate::processing::core_provider::{CoreProvider, CoreProviderError};
use crate::processing::{LLMQValidationStatus, MasternodeProcessorCache, processing_error::ProcessingError, MNListDiffResult};

pub enum LLMQQuarterType {
    AtHeightMinus3Cycles,
    AtHeightMinus2Cycles,
    AtHeightMinusCycle,
    New,
}

#[derive(Clone, Copy)]
pub enum LLMQQuarterReconstructionType<'a> {
    Snapshot {
        cached_llmq_snapshots: &'a BTreeMap<[u8; 32], LLMQSnapshot>
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
    pub provider: Arc<dyn CoreProvider>,
    pub cache: Arc<MasternodeProcessorCache>,
}
impl MasternodeProcessor {
    pub fn new(provider: Arc<dyn CoreProvider>, cache: Arc<MasternodeProcessorCache>) -> Self {
        Self { provider, cache }
    }
}

#[ferment_macro::export]
impl MasternodeProcessor {

    pub fn current_masternode_list(&self, is_rotated_quorums_presented: bool) -> Option<Arc<MasternodeList>> {
        if is_rotated_quorums_presented {
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
        }
    }


    pub fn mn_list_diff_result_from_file(&self, message: &[u8], protocol_version: u32) -> Result<[u8; 32], ProcessingError> {
        let list_diff = self.read_list_diff_from_message(message, &mut 0, protocol_version)
            .map_err(ProcessingError::from)?;
        let block_hash = list_diff.block_hash.clone();
        let result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff);
        println!("mn_list_diff_result_from_file: {}", result.block_hash.to_hex());
        if result.is_valid() {
            let changed = result.masternodes_changed();
            let list = Arc::new(result.masternode_list);
            self.cache.masternode_list_loaded(block_hash, list.clone());
            self.cache.set_last_queried_mn_masternode_list(list.clone());
            self.provider.update_address_usage_of_masternodes(changed);
            self.provider.save_masternode_list_into_db(list, result.modified_masternodes)
                .map_err(ProcessingError::from)?;
            Ok(block_hash)
        } else {
            Err(ProcessingError::InvalidResult)
        }
    }

    pub fn mn_list_diff_result_from_message(
        &self,
        message: &[u8],
        is_from_snapshot: bool,
        protocol_version: u32,
        // #[cfg(test)]
        allow_invalid_merkle_roots: bool,
        peer: *const std::os::raw::c_void
        // cache: &Arc<RwLock<MasternodeProcessorCache>>,
        // cache: &mut MasternodeProcessorCache
    ) -> Result<([u8; 32], bool), ProcessingError> {
        let list_diff = self.read_list_diff_from_message(message, &mut 0, protocol_version)
            .map_err(ProcessingError::from)?;
        let block_hash = list_diff.block_hash.clone();
        if !is_from_snapshot {
            self.should_process_diff_with_range(false, list_diff.base_block_hash, list_diff.block_hash, peer)?;
        }
        let result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff);

        let should_process = self.should_process_diff_result(&result, allow_invalid_merkle_roots, false);
        let raise_peer_issue = !should_process;
        println!("mn_list_diff_result_from_message: {} = {}", result.block_hash.to_hex(), result.is_valid());
        let MNListDiffResult {
            block_hash,
            masternode_list,
            modified_masternodes,
            needed_masternode_lists,
            has_added_rotated_quorums,
            ..
        } = result;
        if should_process {
            let needing_validation_lock = self.cache.list_needing_quorum_validation.read().unwrap();
            if needed_masternode_lists.is_empty() || !needing_validation_lock.contains(&block_hash) {
                let list = Arc::new(masternode_list);
                if self.cache.get_last_queried_block_hash().eq(&block_hash) {
                    self.cache.set_last_queried_mn_masternode_list(list.clone());
                    let mut lock = self.cache.list_needing_quorum_validation.write().unwrap();
                    lock.remove(&block_hash);
                }
                self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                self.cache.masternode_list_loaded(block_hash, list.clone());
                self.provider.save_masternode_list_into_db(list, modified_masternodes)
                    .map_err(ProcessingError::from)?;
            } else  {
                let mut needed_lock = self.cache.needed_masternode_lists.write().unwrap();
                needed_lock.extend(needed_masternode_lists);
            }
        }
        Ok((block_hash, has_added_rotated_quorums))
    }


    pub fn qr_info_result_from_message(
        &self,
        message: &[u8],
        is_from_snapshot: bool,
        protocol_version: u32,
        is_rotated_quorums_presented: bool,
        allow_invalid_merkle_roots: bool,
        peer: *const std::os::raw::c_void
    ) -> Result<[u8; 32], ProcessingError> {
        println!("qr_info_result_from_message: [{}]: {} -- {} -- {}", message.len(), is_from_snapshot, protocol_version, is_rotated_quorums_presented);
        let qr_info = message.read_with::<QRInfo>(&mut 0, (self, is_from_snapshot, protocol_version, is_rotated_quorums_presented, peer))
            .map_err(ProcessingError::from)?;
        let list_diff_processor = |list_diff, verification_context|
            self.get_list_diff_result_with_base_lookup(list_diff, verification_context);
        let result_at_h_4c = qr_info.diff_h_4c.map(|list_diff| list_diff_processor(list_diff, LLMQVerificationContext::None));
        let result_at_h_3c = list_diff_processor(qr_info.diff_h_3c, LLMQVerificationContext::None);
        let result_at_h_2c = list_diff_processor(qr_info.diff_h_2c, LLMQVerificationContext::None);
        let result_at_h_c = list_diff_processor(qr_info.diff_h_c, LLMQVerificationContext::None);
        let result_at_h = list_diff_processor(qr_info.diff_h, LLMQVerificationContext::QRInfo(is_rotated_quorums_presented));
        let result_at_tip = list_diff_processor(qr_info.diff_tip, LLMQVerificationContext::None);
        println!("qr_info_result_from_message h-4c: {} = {}", result_at_h_4c.as_ref().map(|r| r.block_hash.to_hex()).unwrap_or_else(|| "None".to_string()), result_at_h_4c.as_ref().map(|r| r.is_valid().to_string()).unwrap_or_else(|| "None".to_string()));
        println!("qr_info_result_from_message h-3c: {} = {}", result_at_h_3c.block_hash.to_hex(), result_at_h_3c.is_valid());
        println!("qr_info_result_from_message h-2c: {} = {}", result_at_h_2c.block_hash.to_hex(), result_at_h_2c.is_valid());
        println!("qr_info_result_from_message h-c: {} = {}", result_at_h_c.block_hash.to_hex(), result_at_h_c.is_valid());
        println!("qr_info_result_from_message h: {} = {}", result_at_h.block_hash.to_hex(), result_at_h.is_valid());
        println!("qr_info_result_from_message tip: {} = {}", result_at_tip.block_hash.to_hex(), result_at_tip.is_valid());
        let mut needed_lock = self.cache.needed_masternode_lists.write().unwrap();
        let needing_validation_lock = self.cache.list_needing_quorum_validation.read().unwrap();

        // if not present in retrieval queue -> should be treated as error
        let mut raise_peer_issue = false;

        let maybe_save_snapshot = |block_hash, snapshot|
            self.provider.save_llmq_snapshot_into_db(block_hash, snapshot)
                .map_err(ProcessingError::from);


        if let Some(result) = result_at_h_4c {
            let should_process = self.should_process_diff_result(&result, allow_invalid_merkle_roots, true);
            let changed_nodes = result.masternodes_changed();
            let MNListDiffResult {
                block_hash,
                masternode_list,
                modified_masternodes,
                needed_masternode_lists: missing,
                ..
            } = result;
            if should_process {
                if missing.is_empty() || !needing_validation_lock.contains(&block_hash) {
                    let list = Arc::new(masternode_list);
                    self.provider.update_address_usage_of_masternodes(changed_nodes);
                    self.cache.set_last_queried_qr_masternode_list_at_h_4c(list.clone());
                    self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                    self.cache.masternode_list_loaded(block_hash, list.clone());
                    self.provider.save_masternode_list_into_db(list, modified_masternodes)
                        .map_err(ProcessingError::from)?;
                }
            }

            raise_peer_issue |= !should_process;
            needed_lock.extend(missing);
            maybe_save_snapshot(block_hash, qr_info.snapshot_h_4c.unwrap())?;
        }

        let should_process = self.should_process_diff_result(&result_at_h_3c, allow_invalid_merkle_roots, true);
        let changed_nodes = result_at_h_3c.masternodes_changed();
        let MNListDiffResult {
            block_hash,
            masternode_list,
            modified_masternodes,
            needed_masternode_lists: missing,
            ..
        } = result_at_h_3c;
        if should_process {
            if missing.is_empty() || !needing_validation_lock.contains(&block_hash) {
                self.provider.update_address_usage_of_masternodes(changed_nodes);
                let list = Arc::new(masternode_list);
                self.cache.set_last_queried_qr_masternode_list_at_h_3c(list.clone());
                self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                self.cache.masternode_list_loaded(block_hash, list.clone());
                self.provider.save_masternode_list_into_db(list, modified_masternodes)
                    .map_err(ProcessingError::from)?;
            }
        }
        raise_peer_issue |= !should_process;
        needed_lock.extend(missing);
        maybe_save_snapshot(block_hash, qr_info.snapshot_h_3c)?;

        let should_process = self.should_process_diff_result(&result_at_h_2c, allow_invalid_merkle_roots, true);
        let changed_nodes = result_at_h_2c.masternodes_changed();
        let MNListDiffResult {
            block_hash,
            masternode_list,
            modified_masternodes,
            needed_masternode_lists: missing,
            ..
        } = result_at_h_2c;
        if should_process {
            if missing.is_empty() || !needing_validation_lock.contains(&block_hash) {
                self.provider.update_address_usage_of_masternodes(changed_nodes);
                let list = Arc::new(masternode_list);
                self.cache.set_last_queried_qr_masternode_list_at_h_2c(list.clone());
                self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                self.cache.masternode_list_loaded(block_hash, list.clone());
                self.provider.save_masternode_list_into_db(list, modified_masternodes)
                    .map_err(ProcessingError::from)?;
            }
        }

        raise_peer_issue |= !should_process;
        needed_lock.extend(missing);
        maybe_save_snapshot(block_hash, qr_info.snapshot_h_2c)?;

        let should_process = self.should_process_diff_result(&result_at_h_c, allow_invalid_merkle_roots, true);
        let changed_nodes = result_at_h_c.masternodes_changed();
        let MNListDiffResult {
            block_hash,
            masternode_list,
            modified_masternodes,
            needed_masternode_lists: missing,
            ..
        } = result_at_h_c;
        if should_process {
            if missing.is_empty() || !needing_validation_lock.contains(&block_hash) {
                self.provider.update_address_usage_of_masternodes(changed_nodes);
                let list = Arc::new(masternode_list);
                self.cache.set_last_queried_qr_masternode_list_at_h_c(list.clone());
                self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                self.cache.masternode_list_loaded(block_hash, list.clone());
                self.provider.save_masternode_list_into_db(list, modified_masternodes)
                    .map_err(ProcessingError::from)?;
            }
        }
        raise_peer_issue |= !should_process;
        needed_lock.extend(missing);
        maybe_save_snapshot(block_hash, qr_info.snapshot_h_c)?;


        let should_process = self.should_process_diff_result(&result_at_h, allow_invalid_merkle_roots, true);
        let changed_nodes = result_at_h.masternodes_changed();
        let MNListDiffResult {
            block_hash,
            masternode_list,
            modified_masternodes,
            needed_masternode_lists: missing,
            ..
        } = result_at_h;
        if should_process {
            if missing.is_empty() || !needing_validation_lock.contains(&block_hash) {
                self.provider.update_address_usage_of_masternodes(changed_nodes);
                let list = Arc::new(masternode_list);
                self.cache.set_last_queried_qr_masternode_list_at_h(list.clone());
                self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                self.cache.masternode_list_loaded(block_hash, list.clone());
                self.provider.save_masternode_list_into_db(list, modified_masternodes)
                    .map_err(ProcessingError::from)?;
            }
        }
        raise_peer_issue |= !should_process;
        needed_lock.extend(missing);

        let should_process = self.should_process_diff_result(&result_at_tip, allow_invalid_merkle_roots, true);
        raise_peer_issue |= !should_process;
        let changed_nodes = result_at_tip.masternodes_changed();
        let MNListDiffResult {
            block_hash,
            masternode_list,
            modified_masternodes,
            needed_masternode_lists,
            ..
        } = result_at_tip;
        if should_process {
            if needed_masternode_lists.is_empty() || !needing_validation_lock.contains(&block_hash) {
                let list = Arc::new(masternode_list);
                if self.cache.get_last_queried_block_hash().eq(&block_hash) {
                    self.cache.set_last_queried_qr_masternode_list_at_tip(list.clone());
                    let mut lock = self.cache.list_needing_quorum_validation.write().unwrap();
                    lock.remove(&block_hash);
                }
                self.provider.update_address_usage_of_masternodes(changed_nodes);
                self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                self.cache.masternode_list_loaded(block_hash, list.clone());
                self.provider.save_masternode_list_into_db(list, modified_masternodes)
                    .map_err(ProcessingError::from)?;
            } else  {
                needed_lock.extend(needed_masternode_lists);
            }
        }

        for (list_diff, snapshot) in qr_info.mn_list_diff_list.into_iter().zip(qr_info.quorum_snapshot_list.into_iter()) {
            let diff_result = list_diff_processor(list_diff, LLMQVerificationContext::None);
            // let block_hash = diff_result.block_hash.clone();
            // maybe_process_diff_result(diff_result)?;
            let should_process = self.should_process_diff_result(&diff_result, allow_invalid_merkle_roots, true);
            let changed_nodes = diff_result.masternodes_changed();
            let MNListDiffResult {
                block_hash,
                masternode_list,
                modified_masternodes,
                needed_masternode_lists,
                ..
            } = diff_result;
            if should_process {
                if needed_masternode_lists.is_empty() || !needing_validation_lock.contains(&block_hash) {
                    let list = Arc::new(masternode_list);
                    self.provider.update_address_usage_of_masternodes(changed_nodes);
                    self.cache.remove_from_awaiting_quorum_validation_list(list.block_hash);
                    self.cache.masternode_list_loaded(block_hash, list.clone());
                    self.provider.save_masternode_list_into_db(list, modified_masternodes)
                        .map_err(ProcessingError::from)?;
                }
            }
            maybe_save_snapshot(block_hash, snapshot)?;
        }
        println!("qr_info_result_from_message: {}", raise_peer_issue);
        if raise_peer_issue {
            Err(ProcessingError::InvalidResult)
        } else {
            Ok(block_hash)
        }
    }

    pub fn height_for_block_hash(&self, block_hash: [u8; 32]) -> u32 {
        if block_hash.is_zero() {
            return 0
        }
        let mut cached_block_hash_heights_lock = self.cache.cached_block_hash_heights.write().unwrap();
        if let Some(maybe_height) = cached_block_hash_heights_lock.get(&block_hash) {
            return *maybe_height;
        }
        let chain_height = self.provider.lookup_block_height_by_hash(block_hash);
        if chain_height != u32::MAX {
            cached_block_hash_heights_lock.insert(block_hash, chain_height);
        }
        drop(cached_block_hash_heights_lock);
        chain_height
    }

    // quorums
    pub fn quorum_entry_for_lock_request_id(&self, request_id: [u8; 32], llmq_type: LLMQType, block_hash: [u8; 32], block_height: u32, expiration_offset: u32) -> Option<LLMQEntry> {
        if block_hash.is_zero() {
            return None
        }
        let active_quorum = self.cache.active_quorum_of_type(llmq_type, block_hash);
        if active_quorum.is_some() {
            return active_quorum;
        }
        match self.masternode_list_before_block_hash(block_hash) {
            None => {
                println!("No masternode list found yet at {}", block_hash.to_hex());
                None
            }
            Some(list) => {
                let known_height = list.known_height;
                let age = block_height - known_height;
                if age > expiration_offset {
                    println!("Masternode list for is too old (age: {age}, list: {known_height}, block: {block_height}");
                    None
                } else {
                    list.lock_llmq_request_id(request_id, llmq_type)
                }
            }
        }
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
        let list = self.masternode_list_for_block_hash(hash)
            .or_else(|| self.masternode_list_before_block_hash(hash));
        match list {
            None => {
                println!("No masternode list found yet {block}");
                None
            }
            Some(masternode_list) => {
                // if masternode_list.known_height == 0 || masternode_list.known_height == u32::MAX {
                //     masternode_list.known_height = self.height_for_block_hash(masternode_list.block_hash);
                // }
                if height - masternode_list.known_height > 32 {
                    warn!("Masternode list is too old {}", masternode_list.known_height);
                    return None;
                }
                let llmq_type = self.provider.chain_type().platform_type();
                let maybe_list_quorum = masternode_list.quorum_entry_for_platform_with_quorum_hash(quorum_hash, llmq_type);
                if maybe_list_quorum.is_none() {
                    let lock = self.cache.active_quorums.read().unwrap();
                    let maybe_active_quorum = lock.iter().find(|q| q.llmq_type == llmq_type && q.llmq_hash == quorum_hash);
                    return self.quorum_entry_for_platform_having_quorum_hash(quorum_hash, height - 1)
                }
                None
            }
        }
    }


    // masternode list

    pub fn load_masternode_list_at_block_hash(&self, block_hash: [u8; 32]) -> Result<Arc<MasternodeList>, CoreProviderError> {
        self.provider.load_masternode_list_from_db(block_hash)
    }

    pub fn masternode_list_for_block_hash(&self, block_hash: [u8; 32]) -> Option<Arc<MasternodeList>> {
        let lock = self.cache.mn_lists.read().unwrap();
        if let Some(masternode_list) = lock.get(&block_hash) {
            return Some(masternode_list.clone());
        } else {
            let stubs = self.cache.mn_list_stubs.read().unwrap();
            if stubs.contains(&block_hash) {
                return self.load_masternode_list_at_block_hash(block_hash).ok()
            }
        }
        None
    }
    pub fn masternode_list_before_block_hash(&self, block_hash: [u8; 32]) -> Option<Arc<MasternodeList>> {
        let mut min_distance = u32::MAX;
        let block_height = self.height_for_block_hash(block_hash);
        let mut closest_masternode_list = None;
        let lists = self.cache.mn_lists.read().unwrap();
        for (block_hash_data, list) in lists.iter() {
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
        if self.provider.chain_type().is_mainnet() {
            if let Some(ref mut closest_masternode_list) = closest_masternode_list {
                // if closest_masternode_list.known_height == 0 || closest_masternode_list.known_height == u32::MAX {
                //     closest_masternode_list.known_height = self.height_for_block_hash(block_hash);
                // }
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
        let stubs = self.cache.mn_list_stubs.read().unwrap();
        for block_hash in stubs.iter() {
            earliest = std::cmp::min(earliest, self.height_for_block_hash(block_hash.clone()));
        }
        let lists = self.cache.mn_lists.read().unwrap();
        for block_hash in lists.keys() {
            earliest = std::cmp::min(earliest, self.height_for_block_hash(block_hash.clone()));
        }
        earliest
    }
    pub fn last_masternode_list_block_height(&self) -> u32 {
        let mut last = 0;
        let stubs = self.cache.mn_list_stubs.read().unwrap();
        for block_hash in stubs.iter() {
            last = std::cmp::max(last, self.height_for_block_hash(block_hash.clone()));
        }
        let lists = self.cache.mn_lists.read().unwrap();
        for block_hash in lists.keys() {
            last = std::cmp::max(last, self.height_for_block_hash(block_hash.clone()));
        }
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
        let masternodes_map = masternodes.into_iter().fold(BTreeMap::new(), |mut acc, node| {
            acc.insert(node.provider_registration_transaction_hash.reversed(), node);
            acc
        });
        let quorums_map = quorums.into_iter().fold(BTreeMap::new(), |mut acc, entry| {
            acc.entry(entry.llmq_type)
                .or_insert_with(BTreeMap::new)
                .insert(entry.llmq_hash, entry);
            acc
        });
        MasternodeList::new(masternodes_map, quorums_map, block_hash, block_height, quorums_active)
    }

    pub fn should_update_qr_info(&self, block: Block) -> bool {
        let Block { hash, height } = block;
        let chain_type = self.provider.chain_type();
        let DKGParams { mining_window_end, interval, .. } = dkg_rotation_params(chain_type);
        let need_update = match self.cache.get_last_queried_qr_masternode_list_at_h() {
            None => true,
            Some(last_queried) =>
                last_queried.has_unverified_rotated_quorums(chain_type) ||
                    height % interval == mining_window_end && height >= self.height_for_block_hash(last_queried.block_hash) + mining_window_end,
        };
        let cached = self.cache.has_masternode_list_at(hash);
        if cached {
            println!("Already have that masternode list (or in stub) {}", height);
            return false;
        }
        self.cache.set_last_queried_block_hash(hash);
        self.cache.add_block_hash_for_list_needing_quorums_validated(hash);
        true
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
            if let Some(oldest_hash_in_mn_diff_queue) = self.provider.first_in_retrieval_queue(false) {
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
            if let Some(oldest_hash_in_qr_info_queue) = self.provider.first_in_retrieval_queue(true) {
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
}

impl MasternodeProcessor {

    pub fn should_process_diff_with_range(
        &self,
        is_dip24: bool,
        base_block_hash: [u8; 32],
        block_hash: [u8; 32],
        peer: *const std::os::raw::c_void
    ) -> Result<u8, ProcessingError> {
        let base_block_height = self.height_for_block_hash(base_block_hash);
        let block_height = self.height_for_block_hash(block_hash);
        if block_height == u32::MAX {
            return Err(ProcessingError::UnknownBlockHash)
        }
        if !self.provider.remove_request_in_retrieval(is_dip24, base_block_hash, block_hash) {
            println!("•••• shouldProcessDiffWithRange: persist in retrieval: {base_block_height}..{block_height} {}..{}", base_block_hash.to_hex(), block_hash.to_hex());
            return Err(ProcessingError::PersistInRetrieval)
        }
        let list = self.masternode_list_for_block_hash(block_hash);
        // if list.is_none() {
        //     println!("•••• shouldProcessDiffWithRange: no list no stub: {block_height} {}", block_hash.to_hex());
        //     return Err(ProcessingError::InvalidResult)
        // }
        let need_verify_rotated_quorums = is_dip24 && (self.cache.get_last_queried_qr_masternode_list_at_h().is_none() || self.cache.get_last_queried_qr_masternode_list_at_h().unwrap().has_unverified_rotated_quorums(self.provider.chain_type()));
        let need_verify_regular_quorums = !is_dip24 && (list.is_none() || list.unwrap().has_unverified_regular_quorums(self.provider.chain_type()));
        let no_need_to_verify_quorums = !(need_verify_rotated_quorums || need_verify_regular_quorums);
        let has_locally_stored = self.cache.has_masternode_list_at(block_hash);
        if has_locally_stored && no_need_to_verify_quorums {
            println!("•••• shouldProcessDiffWithRange: already persist: {block_height}: {} needToVerifyRotatedQuorums: {need_verify_rotated_quorums} needToVerifyRegularQuorums: {need_verify_regular_quorums}", block_hash.reversed().to_hex());
            self.provider.remove_from_retrieval_queue(is_dip24, block_hash);
            return Err(ProcessingError::LocallyStored);
        }
        match self.masternode_list_for_block_hash(base_block_hash) {
            None if !self.provider.chain_type().genesis_hash().eq(&base_block_hash) && !base_block_hash.is_zero() => {
                self.provider.issue_with_masternode_list_from_peer(is_dip24, peer);
                println!("•••• No base masternode list at: {base_block_height}: {}", base_block_hash.reversed().to_hex());
                Err(ProcessingError::HasNoBaseBlockHash)
            }
            _ => Ok(0)
        }
    }
    fn should_process_diff_result(&self, result: &MNListDiffResult, allow_invalid_merkle_roots: bool, is_dip24: bool) -> bool {
        (self.provider.persist_in_retrieval_queue(result.block_hash, is_dip24) || is_dip24) && (allow_invalid_merkle_roots || result.is_valid())
    }

    fn llmq_modifier_type_for(&self, llmq_type: LLMQType, work_block_hash: [u8; 32], work_block_height: u32) -> LLMQModifierType {
        if self.provider.chain_type().core20_is_active_at(work_block_height) {
            if let Ok(work_block_hash) = self.provider.lookup_block_hash_by_height(work_block_height) {
                if let Some(best_cl_signature) = self.cache.maybe_cl_signature(work_block_hash) {
                // if let Ok(best_cl_signature) = self.provider.find_cl_signature(work_block_hash, &self.cache) {
                    return LLMQModifierType::CoreV20(llmq_type, work_block_height, best_cl_signature);
                } else {
                    println!("llmq_modifier_type: chain lock signature for block hash {} ({}) not found", work_block_hash.to_hex(), work_block_hash.reversed().to_hex());
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
        // cache: &Arc<MasternodeProcessorCache>,
    ) -> MNListDiffResult {
        let base_list = self.provider.find_masternode_list(
            list_diff.base_block_hash,
            &self.cache
        );
        let list_diff_result = self.get_list_diff_result(base_list.ok(), list_diff, verification_context);

        // let mut cache_lock = cache.write().unwrap();
        // self.cache.add_masternode_list(block_hash, masternode_list.clone());
        // let needed_masternode_lists = self.cache.needed_masternode_lists.read().unwrap();
        // cache_lock.needed_masternode_lists.clear();
        // drop(cache_lock);
        list_diff_result
    }

    pub fn get_list_diff_result(
        &self,
        base_list: Option<Arc<MasternodeList>>,
        list_diff: MNListDiff,
        verification_context: LLMQVerificationContext,
        // cache: &mut MasternodeProcessorCache,
    ) -> MNListDiffResult {
        let skip_removed_masternodes = list_diff.should_skip_removed_masternodes();
        let base_block_hash = list_diff.base_block_hash;
        let block_hash = list_diff.block_hash;
        let block_height = list_diff.block_height;
        let quorums_cl_sigs = list_diff.quorums_cls_sigs;
        let (base_masternodes, base_quorums) = match base_list {
            Some(list) => (list.masternodes.clone(), list.quorums.clone()),
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

        let (has_valid_quorums, missed_lists) = self.verify_added_quorums(verification_context, &mut added_quorums, skip_removed_masternodes, &quorums_cl_sigs);
        let (added_quorums, quorums) = self.process_quorums(
            base_quorums,
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
            flags: list_diff.merkle_flags,
        };
        // It's good to cache lists to use it inside processing session
        // Here we use opaque-like pointer which we initiate on the C-side to sync its lifetime with runtime
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_masternode_list_to_json(&masternode_list, self.height_for_block_hash(block_hash));
        // let mut cache_lock = cache.write().unwrap();
        // self.cache.add_masternode_list(block_hash, masternode_list.clone());
        let has_found_coinbase = coinbase_transaction.has_found_coinbase(&merkle_tree.hashes);
        let has_valid_coinbase = self.provider.lookup_merkle_root_by_hash(block_hash)
            .map_or(false, |desired_merkle_root| merkle_tree.has_root(desired_merkle_root));
        let has_valid_mn_list_root = masternode_list.has_valid_mn_list_root(&coinbase_transaction);
        let has_valid_llmq_list_root = !quorums_active || masternode_list.has_valid_llmq_list_root(&coinbase_transaction);
        let result = MNListDiffResult {
            base_block_hash,
            block_hash,
            has_found_coinbase,
            has_valid_coinbase,
            has_valid_mn_list_root,
            has_valid_llmq_list_root,
            has_valid_quorums,
            has_added_quorums,
            has_added_rotated_quorums,
            // has_missed_masternode_lists,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            needed_masternode_lists: missed_lists
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
    ) {
        let (mut modified_masternodes, added_masternodes): (BTreeMap<[u8; 32], MasternodeEntry>, BTreeMap<[u8; 32], MasternodeEntry>) =
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
        quorums_cl_sigs: &BTreeMap<[u8; 96], HashSet<u16>>,
    ) -> (bool, HashSet<[u8; 32]>) {
        let mut has_valid_quorums = true;
        let mut block_hashes_for_missed_lists: HashSet<[u8; 32]> = HashSet::new();
        if verification_context.should_validate_quorums() {
            added_quorums
                .iter_mut()
                .enumerate()
                .for_each(|(index, quorum)| {
                    if let Some(signature) = find_cl_signature_at_index(quorums_cl_sigs, index as u16) {
                        let llmq_height = self.height_for_block_hash(quorum.llmq_hash);
                        if llmq_height != u32::MAX {
                            let work_block_height = llmq_height - 8;
                            if let Ok(work_block_hash) = self.provider.lookup_block_hash_by_height(work_block_height) {
                                let mut cl_signatures_lock = self.cache.cl_signatures.write().unwrap();
                                cl_signatures_lock.insert(work_block_hash, signature);
                                drop(cl_signatures_lock);
                            } else {
                                warn!("unknown hash for {}", work_block_height);
                            }
                        } else {
                            warn!("unknown height for {}", quorum.llmq_hash.to_hex());
                        }
                    }
                    if verification_context.should_validate_quorum_of_type(quorum.llmq_type, self.provider.chain_type()) {
                        match self.validate_quorum(quorum, skip_removed_masternodes) {
                            Ok(LLMQValidationStatus::Verified | LLMQValidationStatus::NoMasternodeList) |
                            Err(CoreProviderError::NoMasternodeList) => {
                                println!("[Processor] NoMasternodeList");
                                has_valid_quorums &= true;
                            },
                            Err(CoreProviderError::MissedMasternodeListAt(block_hash)) => {
                                println!("[Processor] MissedMasternodeListAt: ({})", block_hash.to_hex());
                                block_hashes_for_missed_lists.insert(block_hash);
                                has_valid_quorums &= true;
                            }
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
            self.get_rotated_masternodes_for_quorum(quorum.llmq_type, quorum.llmq_hash, block_height, skip_removed_masternodes)
        } else {
            self.get_non_rotated_masternodes_for_quorum(quorum.llmq_type, quorum.llmq_hash, block_height, quorum, masternodes)
        }
    }

    fn validate_quorum(&self, quorum: &mut LLMQEntry, skip_removed_masternodes: bool) -> Result<LLMQValidationStatus, CoreProviderError> {
        let llmq_block_hash = quorum.llmq_hash;
        let masternode_list = self.provider.find_masternode_list(llmq_block_hash, &self.cache)?;
        let block_height = self.height_for_block_hash(llmq_block_hash);
        let valid_masternodes = self.find_valid_masternodes_for_quorum(quorum, block_height, skip_removed_masternodes, &masternode_list.masternodes)?;
        llmq::verify(quorum, valid_masternodes, block_height)
    }

    fn get_non_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: [u8; 32],
        block_height: u32,
        quorum: &LLMQEntry,
        masternodes: &BTreeMap<[u8; 32], MasternodeEntry>,
    ) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
        Ok(llmq::valid_masternodes(quorum, self.provider.chain_type(), masternodes, block_height, self.llmq_modifier_type_for(llmq_type, block_hash, block_height - 8)))
    }

    fn quorum_quarter_members_by_reconstruction_type(
        &self,
        reconstruction_type: LLMQQuarterReconstructionType,
        llmq_params: &LLMQParams,
        work_block_height: u32,
        // cached_mn_lists: &BTreeMap<UInt256, MasternodeList>,
        // cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
        // unknown_mn_lists: &mut Vec<UInt256>,
    ) -> Result<Vec<Vec<MasternodeEntry>>, CoreProviderError> {
        let work_block_hash = self.provider.lookup_block_hash_by_height(work_block_height)
            .map_err(|err| CoreProviderError::BlockHashNotFoundAt(work_block_height))?;
        let masternode_list = self.provider.find_masternode_list(work_block_hash, &self.cache)?;
        let llmq_type = llmq_params.r#type;
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
            LLMQQuarterReconstructionType::Snapshot { cached_llmq_snapshots } => {
                let cache_lock = self.cache.llmq_snapshots.read().unwrap();
                let maybe_snapshot = cache_lock.get(&work_block_hash).cloned();
                drop(cache_lock);

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
        let llmq_snapshots_lock = self.cache.llmq_snapshots.read().unwrap();
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let work_block_height_for_index = |index: u32| (cycle_base_height - index * cycle_length) - 8;
        let reconstruction_type_snapshot = LLMQQuarterReconstructionType::Snapshot { cached_llmq_snapshots: &llmq_snapshots_lock };
        // Reconstruct quorum members at h - 3c from snapshot
        let q_h_m_3c = self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, work_block_height_for_index(3))?;
        // Reconstruct quorum members at h - 2c from snapshot
        let q_h_m_2c = self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, work_block_height_for_index(2))?;
        // Reconstruct quorum members at h - c from snapshot
        let q_h_m_c = self.quorum_quarter_members_by_reconstruction_type(reconstruction_type_snapshot, &llmq_params, work_block_height_for_index(1))?;
        // Determine quorum members at new index
        let quarter_new = self.quorum_quarter_members_by_reconstruction_type(
            LLMQQuarterReconstructionType::New { previous_quarters:  [&q_h_m_c, &q_h_m_2c, &q_h_m_3c], skip_removed_masternodes }, &llmq_params, work_block_height_for_index(0))?;
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
        // let mut cache_lock = self.cache.write().unwrap();
        let mut llmq_members_lock = self.cache.llmq_members.write().unwrap();
        // let cached_llmq_members = &mut cache_lock.llmq_members;
        // let cached_llmq_indexed_members = &mut cache_lock.llmq_indexed_members;
        let cached_members_of_llmq_type_opt = llmq_members_lock.get_mut(&llmq_type);
        if cached_members_of_llmq_type_opt.is_some() {
            if let Some(cached_members) = cached_members_of_llmq_type_opt.as_ref().unwrap().get(&block_hash) {
                return Ok(cached_members.clone());
            }
        } else {
            llmq_members_lock.insert(llmq_type, BTreeMap::new());
        }

        let cached_members_of_llmq_type = llmq_members_lock.get_mut(&llmq_type).unwrap();
        let llmq_params = llmq_type.params();
        let quorum_index = block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = block_height - quorum_index;
        // drop(cache_lock);
        let cycle_base_hash = self.provider.lookup_block_hash_by_height(cycle_base_height)?;
        let mut llmq_indexed_members_lock = self.cache.llmq_indexed_members.write().unwrap();
        if let Some(map_by_type_indexed) = llmq_indexed_members_lock.get(&llmq_type) {
            let indexed_hash = LLMQIndexedHash::from((cycle_base_hash, quorum_index));
            if let Some(cached_members) = map_by_type_indexed.get(&indexed_hash) {
                cached_members_of_llmq_type.insert(block_hash, cached_members.clone());
                return Ok(cached_members.clone());
            }
        } else {
            llmq_indexed_members_lock.insert(llmq_type, BTreeMap::new());
        }
        drop(llmq_indexed_members_lock);
        let rotated_members = self.rotate_members(cycle_base_height, llmq_params, skip_removed_masternodes)?;
        let result = if let Some(rotated_members_at_index) = rotated_members.get(quorum_index as usize) {
            cached_members_of_llmq_type.insert(block_hash, rotated_members_at_index.clone());
            Ok(rotated_members_at_index.clone())
        } else {
            Err(CoreProviderError::NullResult)
        };
        let mut llmq_indexed_members_lock = self.cache.llmq_indexed_members.write().unwrap();

        llmq_indexed_members_lock.get_mut(&llmq_type)
            .unwrap()
            .extend(rotated_members.into_iter()
                .enumerate()
                .map(|(index, members)|
                    (LLMQIndexedHash::from((cycle_base_hash, index)), members)));
        drop(llmq_indexed_members_lock);
        result
    }

    pub fn read_list_diff_from_message(&self, message: &[u8], offset: &mut usize, protocol_version: u32) -> Result<MNListDiff, byte::Error> {
        MNListDiff::new(message, offset, &*self.provider, protocol_version)
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

fn sort_scored_masternodes(scored_masternodes: BTreeMap<[u8; 32], MasternodeEntry>) -> Vec<MasternodeEntry> {
    let mut v = Vec::from_iter(scored_masternodes);
    v.sort_by(|(s1, _), (s2, _)| s2.reversed().cmp(&s1.reversed()));
    v.into_iter().map(|(s, node)| node).collect()
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
        .collect::<BTreeMap<_, _>>();
    sort_scored_masternodes(scored_masternodes)
}

