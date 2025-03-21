pub mod processing_error;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "message_verification")]
use dashcore::{ephemerealdata::{chain_lock::ChainLock, instant_lock::InstantLock}, sml::message_verification_error::MessageVerificationError};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::consensus::deserialize;
use dashcore::hashes::Hash;
use dashcore::hash_types::{BlockHash, ProTxHash};
use dashcore::network::constants::Network;
#[cfg(feature = "std")]
use dashcore::network::message_qrinfo::QuorumSnapshot;
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dashcore::sml::quorum_validation_error::{ClientDataRetrievalError, QuorumValidationError};
use dash_spv_crypto::network::{ChainType, IHaveChainSettings};
use crate::processing::core_provider::CoreProvider;
use crate::processing::processor::processing_error::ProcessingError;

// https://github.com/rust-lang/rfcs/issues/2770
#[ferment_macro::opaque]
pub struct MasternodeProcessor {
    pub provider: Arc<dyn CoreProvider>,
    pub engine: MasternodeListEngine,
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

    pub fn clear(&mut self) {
        self.engine.clear();
    }
    pub fn current_masternode_list(&self) -> Option<MasternodeList> {
        self.engine.latest_masternode_list().cloned()
    }

    pub fn used_block_hashes(&self) -> Vec<[u8; 32]> {
        self.engine.block_hashes
            .values()
            .map(|hash| hash.to_byte_array())
            .collect()
    }

    pub fn known_masternode_lists_count(&self) -> usize {
        self.engine.masternode_lists.len()
    }

    pub fn has_current_masternode_list(&self) -> bool {
        self.engine.latest_masternode_list().is_some()
    }
    pub fn valid_masternodes_count(&self) -> usize {
        self.current_masternode_list()
            .map(|list| list.masternodes.values().filter(|entry| entry.masternode_list_entry.is_valid).count())
            .unwrap_or_default()
    }

    pub fn masternode_list_for_block_hash(&self, block_hash: [u8; 32]) -> Option<MasternodeList> {
        let block_hash = BlockHash::from_byte_array(block_hash);
        self.engine.masternode_list_for_block_hash(&block_hash).cloned()
    }

    pub fn has_masternode_at_location(&self, address: [u8; 16], port: u16) -> bool {
        self.engine.masternode_lists.values()
            .any(|list| list.has_masternode_at_location(address, port))
    }

    pub fn masternode_at_location(&self, location: SocketAddr) -> Option<QualifiedMasternodeListEntry> {
        self.engine.masternode_lists.values()
            .find_map(|list| list.masternodes.values().find(|node| location.eq(&node.masternode_list_entry.service_address)))
            .cloned()
    }

    pub fn current_masternode_list_masternode_with_pro_reg_tx_hash(&self, hash: &ProTxHash) -> Option<QualifiedMasternodeListEntry> {
        let list = self.current_masternode_list();
        list.and_then(|list| list.masternodes.get(hash).cloned())
    }
    pub fn current_masternode_list_height(&self) -> u32 {
        self.current_masternode_list()
            .map(|list| list.known_height)
            .unwrap_or(u32::MAX)
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

    pub fn closest_known_masternode_list_block_hash(
        &self,
        core_block_height: u32,
    ) -> [u8; 32] {
        let chain_type = ChainType::from(self.engine.network);
        self.engine.masternode_lists.range(..=core_block_height)
            .next_back()
            .map(|(_, list)| list.block_hash.to_byte_array())
                .unwrap_or(chain_type.genesis_hash())
    }

    pub fn masternode_lists(&self) -> BTreeMap<CoreBlockHeight, MasternodeList> {
        self.engine.masternode_lists.clone()
    }
    pub fn known_chain_locks(&self) -> BTreeMap<BlockHash, BLSSignature> {
        self.engine.known_chain_locks.clone()
    }
    pub fn known_block_hashes(&self) -> BTreeMap<u32, [u8; 32]> {
        self.engine.block_hashes.iter().map(|(h, hash)| (*h, hash.to_byte_array())).collect()
    }
    pub fn known_block_heights(&self) -> BTreeMap<[u8; 32], u32> {
        self.engine.block_heights.iter().map(|(hash, h)| (hash.to_byte_array(), *h)).collect()
    }

    #[cfg(feature = "std")]
    pub fn known_snapshots(&self) -> BTreeMap<BlockHash, QuorumSnapshot> {
        self.engine.known_snapshots.clone()
    }

    #[cfg(feature = "message_verification")]
    pub fn verify_is_lock(&self, instant_lock: &InstantLock) -> Result<bool, MessageVerificationError> {
        self.engine.verify_is_lock(instant_lock).map(|_| true)
    }

    #[cfg(feature = "message_verification")]
    pub fn verify_chain_lock(&self, chain_lock: &ChainLock) -> Result<bool, MessageVerificationError> {
        self.engine.verify_chain_lock(chain_lock).map(|_| true)
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
                        if sig.is_zeroed() {
                            Ok(None)
                        } else {
                            Ok(Some(sig))
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
    /// * `Ok((BlockHash, BlockHash))` - If the masternode list difference was successfully applied returns pair (base_block_hash, block_hash).
    /// * `Err(ProcessingError)` - If deserialization or quorum validation fails.
    ///
    /// # Errors
    /// This function will return an error if:
    /// * The provided message cannot be deserialized into a valid `MnListDiff` object.
    /// * There is an issue applying the masternode list difference.
    pub fn process_mn_list_diff_result_from_message(
        &mut self,
        message: &[u8], diff_block_height: Option<u32>, verify_quorums: bool) -> Result<(BlockHash, BlockHash), ProcessingError> {
        let mn_list_diff : MnListDiff = match deserialize(message) {
            Ok(mn_list_diff) => mn_list_diff,
            Err(err) => return Err(err.into()),
        };
        self.engine
            .apply_diff(mn_list_diff, diff_block_height, verify_quorums)
            .map_err(|e| ProcessingError::QuorumValidationError(QuorumValidationError::SMLError(e)))
    }

    pub fn serialize_engine(&self) -> Result<Vec<u8>, ProcessingError> {
        bincode::encode_to_vec(&self.engine, bincode::config::standard())
            .map_err(|e| ProcessingError::EncodeError(e.to_string()))
    }

    pub fn deserialize_engine(&mut self, bytes: &[u8]) -> Result<usize, ProcessingError> {
        bincode::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| ProcessingError::DecodeError(e.to_string()))
            .map(|(engine, size)| {
                self.engine = engine;
                size
            })
    }
}
