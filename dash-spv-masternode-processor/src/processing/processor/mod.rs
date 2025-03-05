pub mod processing_error;

use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use dashcore::{BlockHash, Network, ProTxHash};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::consensus::deserialize;
use dashcore::hashes::Hash;
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dashcore::sml::quorum_validation_error::{ClientDataRetrievalError, QuorumValidationError};
use dash_spv_crypto::crypto::byte_util::Zeroable;
use dash_spv_crypto::network::IHaveChainSettings;
use crate::processing::core_provider::CoreProvider;
use crate::processing::processor::processing_error::ProcessingError;

pub const QUORUM_VALIDATION_WINDOW: u32 = 4 * 576 + 100;

// https://github.com/rust-lang/rfcs/issues/2770
#[ferment_macro::opaque]
pub struct MasternodeProcessor {
    pub provider: Arc<dyn CoreProvider>,
    pub engine: MasternodeListEngine,
    // pub cache: Arc<MasternodeProcessorCache>,
    // pub dapi_address_handler: Option<Arc<dyn DAPIAddressHandler>>,
}
impl Debug for MasternodeProcessor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}] [PROC]", self.provider.chain_type().name()).as_str())
    }
}
impl MasternodeProcessor {
    pub fn new(provider: Arc<dyn CoreProvider>, network: Network) -> Self {
        Self { provider, engine: MasternodeListEngine {
            block_hashes: Default::default(),
            block_heights: Default::default(),
            masternode_lists: Default::default(),
            known_chain_locks: Default::default(),
            known_snapshots: Default::default(),
            rotated_quorums_per_cycle: Default::default(),
            quorum_statuses: Default::default(),
            network,
        } }
    }
}

#[ferment_macro::export]
impl MasternodeProcessor {
    pub fn current_masternode_list(&self) -> Option<MasternodeList> {
        self.engine.latest_masternode_list().cloned()
    }

    pub fn has_current_masternode_list(&self) -> bool {
        self.engine.latest_masternode_list().is_some()
    }

    pub fn current_masternode_list_masternode_with_pro_reg_tx_hash(&self, hash: &ProTxHash) -> Option<QualifiedMasternodeListEntry> {
        let list = self.current_masternode_list();
        list.and_then(|list| list.masternodes.get(hash).cloned())
    }
    pub fn current_masternode_list_masternode_count(&self) -> usize {
        let list = self.current_masternode_list();
        list.map(|list| list.masternodes.len())
            .unwrap_or_default()
    }
    pub fn current_masternode_list_quorum_count(&self) -> usize {
        let list = self.current_masternode_list();
        list.map(|list| list.quorums_count() as usize)
            .unwrap_or_default()
    }
    /// Processes a serialized `QRInfo` message received from the network.
    ///
    /// This function deserializes the given message, processes the QRInfo data,
    /// and determines the set of `mn_list_diff` block hashes required to verify
    /// the current and previous masternode list non-rotated quorums.
    ///
    /// The client should query and retrieve these `mn_list_diff` messages from the network
    /// and feed them back into the system using [`process_mn_list_diff_result_from_message`].
    ///
    /// The client should only verify the last two `mn_list_diff` messages to maintain efficiency.
    ///
    /// # Arguments
    /// * `message` - A byte slice containing the serialized `QRInfo` message.
    /// * `verify_rotated_quorums` - A boolean indicating whether rotated quorums should be verified.
    ///
    /// # Returns
    /// * `Ok(BTreeSet<BlockHash>)` - A set of block hashes for which `mn_list_diff` data is required.
    /// * `Err(ProcessingError)` - If deserialization fails or if any internal processing error occurs.
    ///
    /// # Errors
    /// This function will return an error if:
    /// * The provided message cannot be deserialized into a valid `QRInfo` object.
    /// * There is an issue fetching the required data from the provider.
    ///
    pub fn process_qr_info_result_from_message(
        &mut self,
        message: &[u8], verify_rotated_quorums: bool) -> Result<BTreeSet<BlockHash>, ProcessingError> {

        let qr_info: QRInfo = deserialize(message)?;

        let get_height_fn = {
            |block_hash: &BlockHash| {
                let height = self.provider.lookup_block_height_by_hash(block_hash.to_byte_array());
                if height == u32::MAX {
                    Err(ClientDataRetrievalError::RequiredBlockNotPresent(*block_hash))
                } else {
                    Ok(height)
                }
            }
        };

        let get_chain_lock_sig_fn = {
            |block_hash: &BlockHash| {
                match self.provider.lookup_cl_signature_by_block_hash(block_hash.to_byte_array()) {
                    Ok(sig) => {
                        if sig.is_zero() {
                            Ok(None)
                        } else {
                            Ok(Some(BLSSignature::from(sig)))
                        }
                    },
                    Err(_) => Err(ClientDataRetrievalError::RequiredBlockNotPresent(*block_hash)),
                }
            }
        };

        self.engine.feed_qr_info(
            qr_info,
            verify_rotated_quorums,
            Some(get_height_fn),
            Some(get_chain_lock_sig_fn),
        )?;

        let hashes = self.engine.latest_masternode_list_non_rotating_quorum_hashes(&[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85], false);
        Ok(hashes)
    }

    /// Processes a serialized `MnListDiff` message received from the network.
    ///
    /// This function deserializes the `MnListDiff` message, applies the masternode list
    /// difference to the internal state, and optionally verifies quorums.
    ///
    /// # Arguments
    /// * `message` - A byte slice containing the serialized `MnListDiff` message.
    /// * `diff_block_height` - An optional block height corresponding to the `MnListDiff`.
    /// * `verify_quorums` - A boolean indicating whether the quorums should be verified.
    ///
    /// # Returns
    /// * `Ok(())` - If the masternode list difference was successfully applied.
    /// * `Err(ProcessingError)` - If deserialization or quorum validation fails.
    ///
    /// # Errors
    /// This function will return an error if:
    /// * The provided message cannot be deserialized into a valid `MnListDiff` object.
    /// * There is an issue applying the masternode list difference.
    pub fn process_mn_list_diff_result_from_message(
        &mut self,
        message: &[u8], diff_block_height: Option<u32>, verify_quorums: bool) -> Option<ProcessingError> {
        let mn_list_diff : MnListDiff = match deserialize(message) {
            Ok(mn_list_diff) => mn_list_diff,
            Err(err) => return Some(err.into()),
        };
        self.engine
            .apply_diff(mn_list_diff, diff_block_height, verify_quorums).map_err(|e| ProcessingError::QuorumValidationError(QuorumValidationError::SMLError(e))).err()
    }
}
//
// #[ferment_macro::export]
// impl MasternodeProcessor {
//
//     pub fn add_to_mn_list_retrieval_queue(&self, block_hash: BlockHash) {
//         assert!(!block_hash.is_zero(), "the hash must not be empty");
//         self.cache.write_mn_list_retrieval_queue(|lock| {
//             lock.queue.insert(block_hash);
//             println!("{self:?} queue: {} added ", block_hash.to_hex());
//             lock.update_retrieval_queue(self);
//             self.provider.notify_sync_state(CacheState::queue(lock.queue.len(), lock.max_amount));
//         });
//     }
//     pub fn extend_mn_list_retrieval_queue(&self, block_hashes: Vec<[u8; 32]>) {
//         // assert!(!block_hash.is_zero(), "the hash must not be empty");
//         self.cache.write_mn_list_retrieval_queue(|lock| {
//             println!("{self:?} queue: extended {}", block_hashes.len());
//             lock.queue.extend(block_hashes);
//             lock.update_retrieval_queue(self);
//
//             self.provider.notify_sync_state(CacheState::queue(lock.queue.len(), lock.max_amount));
//         });
//     }
//     pub fn remove_from_mn_list_retrieval_queue(&self, block_hash: &[u8; 32]) {
//         // assert!(!block_hash.is_zero(), "the hash must not be empty");
//         self.cache.write_mn_list_retrieval_queue(|lock| {
//             lock.remove_one(block_hash);
//             lock.update_retrieval_queue(self);
//             println!("{self:?} queue: removed {} (remove_from_mn_list)", block_hash.to_hex());
//             self.provider.notify_sync_state(CacheState::queue(lock.queue.len(), lock.max_amount));
//         });
//     }
//
//     pub fn update_mn_list_retrieval_queue(&self) -> RetrievalQueue {
//         self.cache.write_mn_list_retrieval_queue(|lock| {
//             lock.update_retrieval_queue(self);
//             self.provider.notify_sync_state(CacheState::queue(lock.queue.len(), lock.max_amount));
//             lock.clone()
//         })
//     }
//     pub fn clean_mn_list_retrieval_queue(&self) {
//         self.cache.write_mn_list_retrieval_queue(|lock| {
//             lock.queue.clear();
//             lock.update_retrieval_queue(self);
//             println!("{self:?} Masternode list queue cleaned up: {}/{}", lock.queue.len(), lock.max_amount);
//             self.provider.notify_sync_state(CacheState::queue(lock.queue.len(), lock.max_amount));
//         });
//     }
//     pub fn add_to_qr_info_retrieval_queue(&self, block_hash: [u8; 32]) {
//         assert!(!block_hash.is_zero(), "the hash must not be empty");
//         self.cache.write_qr_info_retrieval_queue(|lock| {
//             lock.queue.insert(block_hash);
//             lock.update_retrieval_queue(self);
//         });
//     }
//     pub fn extend_qr_info_retrieval_queue(&self, block_hashes: Vec<[u8; 32]>) {
//         // assert!(!block_hash.is_zero(), "the hash must not be empty");
//         self.cache.write_qr_info_retrieval_queue(|lock| {
//             lock.queue.extend(block_hashes);
//             lock.update_retrieval_queue(self);
//         });
//     }
//     pub fn remove_from_qr_info_retrieval_queue(&self, block_hash: &[u8; 32]) {
//         assert!(!block_hash.is_zero(), "the hash must not be empty");
//         self.cache.write_qr_info_retrieval_queue(|lock| {
//             lock.queue.shift_remove(block_hash);
//             lock.update_retrieval_queue(self);
//         });
//     }
//     pub fn update_qr_info_retrieval_queue(&self) -> RetrievalQueue {
//         self.cache.write_qr_info_retrieval_queue(|lock| {
//             lock.update_retrieval_queue(self);
//             lock.clone()
//         })
//     }
//     pub fn clean_qr_info_retrieval_queue(&self) {
//         self.cache.write_qr_info_retrieval_queue(|lock| {
//             lock.queue.clear();
//             lock.update_retrieval_queue(self);
//             println!("{self:?} Quorum Rotation queue cleaned up: 0/{}", lock.max_amount);
//         });
//     }
//
//     pub fn merkle_root_for_block_hash(&self, block_hash: [u8; 32], peer: *const std::os::raw::c_void) -> Result<[u8; 32], ProcessingError> {
//         if block_hash.is_zero() {
//             Ok([0; 32])
//         } else {
//             self.provider.last_block_for_block_hash(block_hash, peer)
//                 .map(|b| b.merkle_root)
//                 .map_err(ProcessingError::from)
//         }
//     }
//
//     pub fn mn_list_diff_result_from_file(&self, message: &[u8], protocol_version: u32) -> Result<([u8; 32], [u8; 32], bool), ProcessingError> {
//         let list_diff = self.read_list_diff_from_message(message, &mut 0, protocol_version)?;
//         // println!("{self:?}: {}", list_diff);
//         let base_block_hash = list_diff.base_block_hash.clone();
//         let block_hash = list_diff.block_hash.clone();
//         let block = self.provider.block_by_hash(block_hash)
//             .map_err(ProcessingError::from)?;
//         // println!("block by block_hash {} is {}", block_hash.to_hex(), block);
//
//         let result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff, block.merkle_root).map_err(ProcessingError::from)?;
//         println!("{self:?} MNL diff from file: {}", result.short_description());
//         if result.is_valid() {
//             self.masternode_list_processed(
//                 result.masternode_list,
//                 result.added_masternodes,
//                 result.modified_masternodes,
//                 result.added_dapi_nodes,
//                 result.removed_dapi_nodes,
//                 |list_block_hash| self.cache.set_last_queried_mn_masternode_list(list_block_hash))
//                 .map_err(ProcessingError::from)?;
//             Ok((base_block_hash, block_hash, result.has_added_rotated_quorums))
//         } else {
//             Err(ProcessingError::InvalidResult(result.short_description()))
//         }
//     }
//
//     pub fn mn_list_diff_result_from_message(
//         &self,
//         message: &[u8],
//         is_from_snapshot: bool,
//         protocol_version: u32,
//         allow_invalid_merkle_roots: bool,
//         peer: *const std::os::raw::c_void
//     ) -> Result<([u8; 32], [u8; 32], bool), ProcessingError> {
//         let list_diff = self.read_list_diff_from_message(message, &mut 0, protocol_version)?;
//         // println!("{self:?}: {}", list_diff);
//         let base_block_hash = list_diff.base_block_hash;
//         let block_hash = list_diff.block_hash;
//         if !is_from_snapshot {
//             self.should_process_diff_with_range(false, base_block_hash, block_hash, peer)?;
//         }
//         let merkle_root = self.merkle_root_for_block_hash(block_hash, peer)?;
//         // println!("last block for block_hash {} is {}", block_hash.to_hex(), block);
//         let result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::MNListDiff, merkle_root)
//             .map_err(ProcessingError::from)?;
//
//         let should_process = is_from_snapshot || self.should_process_diff_result(&result, allow_invalid_merkle_roots, false);
//         let raise_peer_issue = !should_process;
//         println!("{self:?} MNL diff from msg: {}", result.short_description());
//         let MNListDiffResult {
//             block_hash,
//             masternode_list,
//             added_masternodes,
//             modified_masternodes,
//             needed_masternode_lists,
//             has_added_rotated_quorums,
//             added_dapi_nodes,
//             removed_dapi_nodes,
//             ..
//         } = result;
//         if should_process {
//             let need_validate_llmq = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//             if needed_masternode_lists.is_empty() || !need_validate_llmq {
//                 let result = self.masternode_list_processed(
//                     masternode_list,
//                     added_masternodes,
//                     modified_masternodes,
//                     added_dapi_nodes,
//                     removed_dapi_nodes,
//                     |list| {
//                         if self.cache.get_last_queried_block_hash().eq(&block_hash) {
//                             self.cache.set_last_queried_mn_masternode_list(block_hash);
//                             self.cache.remove_block_hash_for_list_needing_quorums_validated(block_hash);
//                         }
//                     }
//                 );
//                 result.map_err(ProcessingError::from)?;
//             } else {
//                 self.cache.add_needed_masternode_lists(needed_masternode_lists.clone());
//             }
//         }
//         self.cache.write_mn_list_retrieval_queue(|lock| {
//             let _removed = lock.remove_one(&block_hash);
//             println!("{self:?} queue: {} removed {_removed} (after processing)", block_hash.to_hex());
//         });
//         if !needed_masternode_lists.is_empty() {
//             let debug_info = needed_masternode_lists.format();
//             println!("{self:?} missing lists:\n {}", debug_info);
//             self.process_missing_masternode_lists(block_hash, needed_masternode_lists);
//             Err(ProcessingError::MissingLists(debug_info))
//         } else {
//             Ok((base_block_hash, block_hash, has_added_rotated_quorums))
//         }
//     }
//
//
//     pub fn qr_info_result_from_message(
//         &self,
//         message: &[u8],
//         is_from_snapshot: bool,
//         protocol_version: u32,
//         is_rotated_quorums_presented: bool,
//         allow_invalid_merkle_roots: bool,
//         peer: *const std::os::raw::c_void
//     ) -> Result<([u8; 32], [u8; 32]), ProcessingError> {
//         let qr_info = QRInfo::new(message, self, is_from_snapshot, protocol_version, peer)?;
//         //println!("{self:?}: {}", qr_info);
//         let QRInfo {
//             diff_h_4c,
//             diff_h_3c,
//             diff_h_2c,
//             diff_h_c,
//             diff_h,
//             diff_tip,
//             extra_share,
//             mn_list_diff_list,
//             quorum_snapshot_list,
//             snapshot_h_4c,
//             snapshot_h_3c,
//             snapshot_h_2c,
//             snapshot_h_c,
//             last_quorum_per_index
//         } = qr_info;
//         let result_at_h_4c = if let Some(diff_h_4c) = diff_h_4c {
//             let merkle_root_h_4c = self.merkle_root_for_block_hash(diff_h_4c.block_hash, peer)?;
//             Some(self.get_list_diff_result_with_base_lookup(diff_h_4c, LLMQVerificationContext::None, merkle_root_h_4c).map_err(ProcessingError::from)?)
//         } else { None };
//
//
//         let merkle_root_h_3c = self.merkle_root_for_block_hash(diff_h_3c.block_hash, peer)?;
//         let merkle_root_h_2c = self.merkle_root_for_block_hash(diff_h_2c.block_hash, peer)?;
//         let merkle_root_h_c = self.merkle_root_for_block_hash(diff_h_c.block_hash, peer)?;
//         let merkle_root_h = self.merkle_root_for_block_hash(diff_h.block_hash, peer)?;
//         let merkle_root_tip = self.merkle_root_for_block_hash(diff_tip.block_hash, peer)?;
//
//         let result_at_h_3c = self.get_list_diff_result_with_base_lookup(diff_h_3c, LLMQVerificationContext::None, merkle_root_h_3c).map_err(ProcessingError::from)?;
//         let result_at_h_2c = self.get_list_diff_result_with_base_lookup(diff_h_2c, LLMQVerificationContext::None, merkle_root_h_2c).map_err(ProcessingError::from)?;
//         let result_at_h_c = self.get_list_diff_result_with_base_lookup(diff_h_c, LLMQVerificationContext::None, merkle_root_h_c).map_err(ProcessingError::from)?;
//         let result_at_h = self.get_list_diff_result_with_base_lookup(diff_h, LLMQVerificationContext::QRInfo(is_rotated_quorums_presented), merkle_root_h).map_err(ProcessingError::from)?;
//         let result_at_tip = self.get_list_diff_result_with_base_lookup(diff_tip, LLMQVerificationContext::None, merkle_root_tip).map_err(ProcessingError::from)?;
//
//         println!("{self:?} h-4c: {}", result_at_h_4c.as_ref().map(MNListDiffResult::short_description).unwrap_or_else(|| "None".to_string()));
//         println!("{self:?} h-3c: {}", result_at_h_3c.short_description());
//         println!("{self:?} h-2c: {}", result_at_h_2c.short_description());
//         println!("{self:?}  h-c: {}", result_at_h_c.short_description());
//         println!("{self:?}   h: {}", result_at_h.short_description());
//         println!("{self:?} tip: {}", result_at_tip.short_description());
//
//         // if not present in retrieval queue -> should be treated as error
//         let mut error_info = String::new();
//
//         let maybe_save_snapshot = |block_hash, snapshot|
//             self.provider.save_llmq_snapshot_into_db(block_hash, snapshot)
//                 .map_err(ProcessingError::from);
//
//
//         if let Some(result) = result_at_h_4c {
//             let should_process = is_from_snapshot || self.should_process_diff_result(&result, allow_invalid_merkle_roots, true);
//             let MNListDiffResult {
//                 block_hash,
//                 masternode_list,
//                 added_masternodes,
//                 modified_masternodes,
//                 needed_masternode_lists,
//                 added_dapi_nodes,
//                 removed_dapi_nodes,
//                 ..
//             } = result;
//             let has_missed_lists = !needed_masternode_lists.is_empty();
//             if should_process {
//                 let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//                 if !has_missed_lists || !waiting_for_validation {
//                     self.masternode_list_processed(
//                         masternode_list,
//                         added_masternodes,
//                         modified_masternodes,
//                         added_dapi_nodes,
//                         removed_dapi_nodes,
//                         |list_block_hash| self.cache.set_last_queried_qr_masternode_list_at_h_4c(list_block_hash)
//                     )
//                         .map_err(ProcessingError::from)?;
//                 }
//             } else {
//                 error_info.push_str("Shouldn't process diff result at h - 4c\n");
//             }
//             if has_missed_lists {
//                 self.cache.add_needed_masternode_lists(needed_masternode_lists);
//             }
//             maybe_save_snapshot(block_hash, snapshot_h_4c.unwrap())?;
//         }
//
//         let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h_3c, allow_invalid_merkle_roots, true);
//         let MNListDiffResult {
//             block_hash,
//             masternode_list,
//             added_masternodes,
//             modified_masternodes,
//             needed_masternode_lists,
//             added_dapi_nodes,
//             removed_dapi_nodes,
//             ..
//         } = result_at_h_3c;
//         let has_missed_lists = !needed_masternode_lists.is_empty();
//
//         if should_process {
//             let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//             if !has_missed_lists || !waiting_for_validation {
//                 self.masternode_list_processed(
//                     masternode_list,
//                     added_masternodes,
//                     modified_masternodes,
//                     added_dapi_nodes,
//                     removed_dapi_nodes,
//                     |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h_3c(list_block_hash)
//                 )
//                     .map_err(ProcessingError::from)?;
//             }
//         } else {
//             error_info.push_str("Shouldn't process diff result at h - 3c\n");
//         }
//         if has_missed_lists {
//             self.cache.add_needed_masternode_lists(needed_masternode_lists);
//         }
//         maybe_save_snapshot(block_hash, snapshot_h_3c)?;
//
//         let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h_2c, allow_invalid_merkle_roots, true);
//         let MNListDiffResult {
//             block_hash,
//             masternode_list,
//             added_masternodes,
//             modified_masternodes,
//             needed_masternode_lists,
//             added_dapi_nodes,
//             removed_dapi_nodes,
//             ..
//         } = result_at_h_2c;
//         let has_missed_lists = !needed_masternode_lists.is_empty();
//         if should_process {
//             let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//             if !has_missed_lists || !waiting_for_validation {
//                 self.masternode_list_processed(
//                     masternode_list,
//                     added_masternodes,
//                     modified_masternodes,
//                     added_dapi_nodes,
//                     removed_dapi_nodes,
//                     |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h_2c(list_block_hash)
//                 )
//                     .map_err(ProcessingError::from)?;
//             }
//         } else {
//             error_info.push_str("Shouldn't process diff result at h - 2c\n");
//         }
//
//         if has_missed_lists {
//             self.cache.add_needed_masternode_lists(needed_masternode_lists);
//         }
//         maybe_save_snapshot(block_hash, snapshot_h_2c)?;
//
//         let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h_c, allow_invalid_merkle_roots, true);
//         let MNListDiffResult {
//             block_hash,
//             masternode_list,
//             added_masternodes,
//             modified_masternodes,
//             needed_masternode_lists,
//             added_dapi_nodes,
//             removed_dapi_nodes,
//             ..
//         } = result_at_h_c;
//         let has_missed_lists = !needed_masternode_lists.is_empty();
//         if should_process {
//             let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//             if !has_missed_lists || !waiting_for_validation {
//                 self.masternode_list_processed(
//                     masternode_list,
//                     added_masternodes,
//                     modified_masternodes,
//                     added_dapi_nodes,
//                     removed_dapi_nodes,
//                     |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h_c(list_block_hash)
//                 )
//                     .map_err(ProcessingError::from)?;
//             }
//         } else {
//             error_info.push_str("Shouldn't process diff result at h - c\n");
//         }
//         if has_missed_lists {
//             self.cache.add_needed_masternode_lists(needed_masternode_lists);
//         }
//         maybe_save_snapshot(block_hash, snapshot_h_c)?;
//
//
//         let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_h, allow_invalid_merkle_roots, true);
//         let MNListDiffResult {
//             block_hash,
//             masternode_list,
//             added_masternodes,
//             modified_masternodes,
//             needed_masternode_lists,
//             added_dapi_nodes,
//             removed_dapi_nodes,
//             ..
//         } = result_at_h;
//         let has_missed_lists = !needed_masternode_lists.is_empty();
//         if should_process {
//             let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//             if !has_missed_lists || !waiting_for_validation {
//                 self.masternode_list_processed(
//                     masternode_list,
//                     added_masternodes,
//                     modified_masternodes,
//                     added_dapi_nodes,
//                     removed_dapi_nodes,
//                     |list_block_hash | self.cache.set_last_queried_qr_masternode_list_at_h(list_block_hash)
//                 )
//                     .map_err(ProcessingError::from)?;
//             }
//         } else {
//             error_info.push_str("Shouldn't process diff result at h\n");
//         }
//         if has_missed_lists {
//             self.cache.add_needed_masternode_lists(needed_masternode_lists);
//         }
//         let should_process = is_from_snapshot || self.should_process_diff_result(&result_at_tip, allow_invalid_merkle_roots, true);
//         if !should_process {
//             error_info.push_str("Shouldn't process diff result at tip\n");
//         }
//         let MNListDiffResult {
//             base_block_hash,
//             block_hash,
//             masternode_list,
//             added_masternodes,
//             modified_masternodes,
//             needed_masternode_lists,
//             added_dapi_nodes,
//             removed_dapi_nodes,
//             ..
//         } = result_at_tip;
//         let has_missed_lists = !needed_masternode_lists.is_empty();
//         if should_process {
//             let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//             if !has_missed_lists || !waiting_for_validation {
//                 self.masternode_list_processed(
//                     masternode_list,
//                     added_masternodes,
//                     modified_masternodes,
//                     added_dapi_nodes,
//                     removed_dapi_nodes,
//                     |list_block_hash | {
//                         let last_queried_is_the_same = self.cache.get_last_queried_block_hash().eq(&block_hash);
//                         println!("{self:?} masternode at tip processed: {} same as queried? {}", block_hash.to_hex(), last_queried_is_the_same);
//                         if self.cache.get_last_queried_block_hash().eq(&block_hash) {
//                             self.cache.set_last_queried_qr_masternode_list_at_tip(list_block_hash);
//                             self.cache.remove_block_hash_for_list_needing_quorums_validated(block_hash);
//                         }
//                     }
//                 )
//                     .map_err(ProcessingError::from)?;
//             }
//             if has_missed_lists {
//                 self.cache.add_needed_masternode_lists(needed_masternode_lists);
//             }
//         }
//
//         for (list_diff, snapshot) in mn_list_diff_list.into_iter().zip(quorum_snapshot_list.into_iter()) {
//             let block = self.provider.last_block_for_block_hash(list_diff.block_hash, peer)
//                 .map_err(ProcessingError::from)?;
//             let diff_result = self.get_list_diff_result_with_base_lookup(list_diff, LLMQVerificationContext::None, block.merkle_root).map_err(ProcessingError::from)?;
//             let should_process = is_from_snapshot || self.should_process_diff_result(&diff_result, allow_invalid_merkle_roots, true);
//             let MNListDiffResult {
//                 block_hash,
//                 masternode_list,
//                 added_masternodes,
//                 modified_masternodes,
//                 needed_masternode_lists,
//                 added_dapi_nodes,
//                 removed_dapi_nodes,
//                 ..
//             } = diff_result;
//             if should_process {
//                 let waiting_for_validation = self.cache.has_list_at_block_hash_needing_quorums_validated(block_hash);
//                 if needed_masternode_lists.is_empty() || !waiting_for_validation {
//                     self.masternode_list_processed(
//                         masternode_list,
//                         added_masternodes,
//                         modified_masternodes,
//                         added_dapi_nodes,
//                         removed_dapi_nodes,
//                         |list | {}
//                     )
//                         .map_err(ProcessingError::from)?;
//                 }
//             }
//             maybe_save_snapshot(block_hash, snapshot)?;
//         }
//         // println!("qr_info_result_from_message: {}", raise_peer_issue);
//         if !error_info.is_empty() {
//             Err(ProcessingError::InvalidResult(error_info))
//         } else {
//             let missed = self.cache.read_needed_masternode_lists(Clone::clone);
//             self.cache.write_qr_info_retrieval_queue(|lock| lock.remove_one(&block_hash));
//             if missed.is_empty() {
//                 Ok((base_block_hash, block_hash))
//             } else {
//                 let debug_info = missed.format();
//                 self.process_missing_masternode_lists(block_hash, missed);
//                 Err(ProcessingError::MissingLists(debug_info))
//             }
//         }
//     }
//
//
//     // masternode list
//
//     pub fn load_masternode_list_at_block_hash(&self, block_hash: [u8; 32]) -> Result<MasternodeList, CoreProviderError> {
//         self.provider.load_masternode_list_from_db(block_hash)
//     }
//
//
//
//     pub fn closest_known_block_hash_for_block_hash(&self, block_hash: [u8; 32]) -> [u8; 32] {
//         // TODO: involve checkpoint here
//         self.masternode_list_before_block_hash(block_hash)
//             .map(|list| list.block_hash)
//             .unwrap_or_else(|| self.provider.chain_type().genesis_hash())
//     }
//
//     pub fn earliest_masternode_list_block_height(&self) -> u32 {
//         let mut earliest = u32::MAX;
//         self.cache.read_mn_list_stubs(|lock| {
//             for block_hash in lock.iter() {
//                 earliest = std::cmp::min(earliest, self.height_for_block_hash(block_hash.clone()));
//             }
//         });
//         self.cache.read_mn_lists(|lock| {
//             for block_hash in lock.keys() {
//                 earliest = std::cmp::min(earliest, self.height_for_block_hash(block_hash.clone()));
//             }
//         });
//         earliest
//     }
//     pub fn last_masternode_list_block_height(&self) -> u32 {
//         let mut last = 0;
//         self.cache.read_mn_list_stubs(|lock| {
//             for block_hash in lock.iter() {
//                 last = std::cmp::max(last, self.height_for_block_hash(block_hash.clone()));
//             }
//         });
//         self.cache.read_mn_lists(|lock| {
//             for block_hash in lock.keys() {
//                 last = std::cmp::max(last, self.height_for_block_hash(block_hash.clone()));
//             }
//         });
//         if last == 0 {
//             u32::MAX
//         } else {
//             last
//         }
//     }
//
//     pub fn load_masternode_list(
//         &self,
//         masternodes: Vec<MasternodeEntry>,
//         quorums: Vec<LLMQEntry>,
//         block_hash: [u8; 32],
//         block_height: u32,
//         quorums_active: bool
//     ) -> MasternodeList {
//         let masternodes_map = masternode_vec_to_map(masternodes);
//         let quorums_map = quorum_vec_to_map(quorums);
//         MasternodeList::new(masternodes_map, quorums_map, block_hash, block_height, quorums_active)
//     }
//
//     pub fn cache_query(&self, hash: [u8; 32]) {
//         self.cache.set_last_queried_block_hash(hash);
//         self.cache.add_block_hash_for_list_needing_quorums_validated(hash);
//     }
//
//     // find block height to which the lists can be safely removed from storage
//     pub fn calculate_outdated_height(&self) -> u32 {
//         let mut height_to_delete = u32::MAX;
//         if let Some(list) = self.cache.get_last_queried_mn_masternode_list() {
//             height_to_delete = if list.known_height == 0 || list.known_height == u32::MAX {
//                 self.height_for_block_hash(list.block_hash)
//             } else {
//                 list.known_height
//             };
//             if let Some(oldest_hash_in_mn_diff_queue) = self.cache.read_mn_list_retrieval_queue(RetrievalQueue::first) {
//                 let oldest_height = self.height_for_block_hash(oldest_hash_in_mn_diff_queue);
//                 if height_to_delete > oldest_height {
//                     height_to_delete = oldest_height;
//                 }
//             }
//         } else {
//             // Don't remove if we didn't get updates from mnlistdiff
//             return height_to_delete;
//         }
//         if let Some(list) = self.cache.get_last_queried_qr_masternode_list_at_h_4c()
//             .or_else(|| self.cache.get_last_queried_qr_masternode_list_at_h_3c()) {
//             let h = if list.known_height == 0 || list.known_height == u32::MAX {
//                 self.height_for_block_hash(list.block_hash)
//             } else {
//                 list.known_height
//             };
//             if height_to_delete > h {
//                 height_to_delete = h;
//             }
//             if let Some(oldest_hash_in_qr_info_queue) = self.cache.read_qr_info_retrieval_queue(RetrievalQueue::first) {
//                 let oldest_height = self.height_for_block_hash(oldest_hash_in_qr_info_queue);
//                 if height_to_delete > oldest_height {
//                     height_to_delete = oldest_height;
//                 }
//             }
//         } else {
//             // Don't remove if we didn't get updates from qrinfo
//             return height_to_delete;
//         }
//         height_to_delete
//     }
//
//     pub fn get_recent_mn_list(&self, block: Block) {
//         let Block { hash, height } = block;
//         if self.cache.has_latest_block_in_mn_list_retrieval_queue_with_hash(&hash) {
//             // We are asking for the same as the last one
//             println!("{self:?} Already have that request in mn_list queue {}", height);
//             return
//         }
//         let cached = self.cache.has_masternode_list_at(hash);
//         if cached {
//             println!("{self:?} Already have that masternode list (or in stub) {}", height);
//             return
//         }
//         self.cache_query(hash);
//         println!("{self:?} MasternodeListService: Getting masternode list {} ({})", height, hash.to_hex());
//         let has_empty_request_queue = self.cache.write_mn_list_retrieval_queue(|lock| {
//             let is_empty = lock.queue.is_empty();
//             assert!(!hash.is_zero(), "the hash data must not be empty");
//             lock.add(hash, self);
//             println!("{self:?} queue: added {} (get_recent_mn_list)", hash.to_hex());
//
//             self.provider.notify_sync_state(CacheState::queue(lock.queue.len(), lock.max_amount));
//             is_empty
//         });
//         if has_empty_request_queue {
//             self.provider.dequeue_masternode_list(false);
//         } else {
//             println!("{self:?} MasternodeListService: non-empty queue {} ({})", height, hash.to_hex());
//         }
//     }
//
//     pub fn get_recent_qr_info(&self, block: Block) {
//         let Block { hash, height } = block;
//         if self.cache.has_latest_block_in_qr_info_retrieval_queue_with_hash(&hash) {
//             // We are asking for the same as the last one
//             println!("{self:?} Already have that request in qr_info queue {}", height);
//             return
//         }
//         let chain_type = self.provider.chain_type();
//         let DKGParams { mining_window_end, interval, .. } = dkg_rotation_params(chain_type.clone());
//         let should_update_qr_info = if self.cache.has_last_queried_qr_masternode_list_at_h() {
//             match self.cache.get_last_queried_qr_masternode_list_at_h() {
//                 None => true,
//                 Some(last_queried) =>
//                     last_queried.has_unverified_rotated_quorums(chain_type) ||
//                         height % interval == mining_window_end && height >= self.height_for_block_hash(last_queried.block_hash) + mining_window_end
//             }
//         } else {
//             true
//         };
//
//         if !should_update_qr_info {
//             println!("{self:?} qrinfo at h has no unverified quorums and interval isn't enough to request {}", height);
//             return
//         }
//         let cached = self.cache.has_masternode_list_at(hash);
//         if cached {
//             println!("{self:?} Already have that masternode list (or in stub) {}", height);
//             return;
//         }
//         self.cache_query(hash);
//
//         println!("{self:?} QuorumRotationService: Getting masternode list {} ({})", height, hash.to_hex());
//         let has_empty_request_queue = self.cache.write_qr_info_retrieval_queue(|lock| {
//             let is_empty = lock.queue.is_empty();
//             assert!(!hash.is_zero(), "the hash data must not be empty");
//             lock.add(hash, self);
//             is_empty
//         });
//         if has_empty_request_queue {
//             self.provider.dequeue_masternode_list(true);
//         } else {
//             println!("{self:?} QuorumRotationService: non-empty queue {} ({})", height, hash.to_hex());
//         }
//     }
// }
//
// impl MasternodeProcessor {
//     pub fn should_process_diff_with_range(
//         &self,
//         is_dip24: bool,
//         base_block_hash: [u8; 32],
//         block_hash: [u8; 32],
//         peer: *const std::os::raw::c_void
//     ) -> Result<u8, ProcessingError> {
//         let block_height = self.height_for_block_hash(block_hash);
//         if block_height == u32::MAX {
//             warn!("{self:?} MNL unknown block_hash {}", block_hash.reversed().to_hex());
//             return Err(ProcessingError::UnknownBlockHash(block_hash))
//         }
//         if !self.provider.remove_request_in_retrieval(is_dip24, base_block_hash, block_hash) {
//             let base_block_height = self.height_for_block_hash(base_block_hash);
//             warn!("{self:?} MNL unexpected diff [{base_block_height}..{block_height}] ({}..{})", base_block_hash.reversed().to_hex(), block_hash.reversed().to_hex());
//             return Err(ProcessingError::PersistInRetrieval(base_block_hash, block_hash))
//         }
//         let list = self.masternode_list_for_block_hash(block_hash);
//         let need_verify_rotated_quorums = is_dip24 && (self.cache.get_last_queried_qr_masternode_list_at_h().is_none() || self.cache.get_last_queried_qr_masternode_list_at_h().unwrap().has_unverified_rotated_quorums(self.provider.chain_type()));
//         let need_verify_regular_quorums = !is_dip24 && list.is_none();
//         // let need_verify_regular_quorums = !is_dip24 && (list.is_none() || list.unwrap().has_unverified_regular_quorums(self.provider.chain_type()));
//         let no_need_to_verify_quorums = !(need_verify_rotated_quorums || need_verify_regular_quorums);
//         let has_locally_stored = self.cache.has_masternode_list_at(block_hash);
//         if has_locally_stored && no_need_to_verify_quorums {
//             warn!("{self:?} MNL already persist and doesn't contain unverified llmq: {block_height}: {}", block_hash.reversed().to_hex());
//             if is_dip24 {
//                 self.cache.write_qr_info_retrieval_queue(|lock| lock.queue.shift_remove(&block_hash));
//             } else {
//                 self.provider.notify_sync_state(self.cache.write_mn_list_retrieval_queue(|lock| {
//                     let _removed = lock.remove_one(&block_hash);
//                     println!("{self:?} queue: {} removed {_removed} (should process diff)", block_hash.to_hex());
//                     CacheState::queue(lock.queue.len(), lock.max_amount)
//                 }))
//             }
//             // TODO: notify sync state change
//             return Err(ProcessingError::LocallyStored(block_height, block_hash));
//         }
//         match self.masternode_list_for_block_hash(base_block_hash) {
//             None if !self.provider.chain_type().genesis_hash().eq(&base_block_hash) && !base_block_hash.is_zero() => {
//                 self.provider.issue_with_masternode_list_from_peer(is_dip24, peer);
//                 let base_block_height = self.height_for_block_hash(base_block_hash);
//                 warn!("{self:?} MNL has no base at: {base_block_height}: {}", base_block_hash.reversed().to_hex());
//                 Err(ProcessingError::HasNoBaseBlockHash(base_block_hash))
//             }
//             _ => Ok(0)
//         }
//     }
//
//     pub fn read_list_diff_from_message(&self, message: &[u8], offset: &mut usize, protocol_version: u32) -> Result<MNListDiff, ProcessingError> {
//         MNListDiff::new(message, offset, self, protocol_version)
//     }


// }
