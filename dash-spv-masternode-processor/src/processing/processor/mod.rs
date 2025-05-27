pub mod processing_error;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "message_verification")]
use dashcore::{ephemerealdata::{chain_lock::ChainLock, instant_lock::InstantLock}, sml::message_verification_error::MessageVerificationError};
use dashcore::consensus::deserialize;
use dashcore::hashes::Hash;
use dashcore::hash_types::{BlockHash, ProTxHash};
use dashcore::network::constants::Network;
#[cfg(feature = "std")]
use dashcore::network::message_qrinfo::QuorumSnapshot;
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::{DKGParams, LLMQType, DKG_60_75, DKG_DEVNET_DIP_0024};
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::{MasternodeListEngine, MasternodeListEngineBlockContainer};
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dashcore::sml::quorum_validation_error::{ClientDataRetrievalError, QuorumValidationError};
use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
use dash_spv_crypto::crypto::byte_util::Zeroable;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings};
use crate::processing::core_provider::CoreProvider;
use crate::processing::processor::processing_error::ProcessingError;

#[ferment_macro::export]
#[derive(Clone)]
pub struct DiffConfig {
    pub bytes: Vec<u8>,
    pub height: u32,
}


// https://github.com/rust-lang/rfcs/issues/2770
#[ferment_macro::opaque]
pub struct MasternodeProcessor {
    pub provider: Arc<dyn CoreProvider>,
    pub engine: MasternodeListEngine,
    pub last_known_qr_info_block_height: Option<u32>
    // pub dapi_address_handler: Option<Arc<dyn DAPIAddressHandler>>,
}
impl Debug for MasternodeProcessor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}] [PROC]", self.provider.chain_type().name()).as_str())
    }
}
impl MasternodeProcessor {
    pub fn new(provider: Arc<dyn CoreProvider>, network: Network) -> Self {
        Self { provider, engine: MasternodeListEngine::default_for_network(network), last_known_qr_info_block_height: None }
    }

    pub fn from_diff_config(provider: Arc<dyn CoreProvider>, network: Network, diff_config: Option<DiffConfig>) -> Self {
        diff_config
            .and_then(|DiffConfig { bytes, height }| Self::from_checkpoint(provider.clone(), network, &bytes, height))
            .unwrap_or(Self::new(provider.clone(), network))
    }

    pub fn from_checkpoint(provider: Arc<dyn CoreProvider>, network: Network, bytes: &[u8], expected_diff_height: u32) -> Option<Self> {
        maybe_engine_from_checkpoint(network, bytes, expected_diff_height)
            .map(|engine| Self { provider, engine, last_known_qr_info_block_height: None })
    }

}

fn maybe_engine_from_checkpoint(network: Network, bytes: &[u8], expected_diff_height: u32) -> Option<MasternodeListEngine> {
    match deserialize::<MnListDiff>(bytes) {
        Ok(diff) => match MasternodeListEngine::initialize_with_diff_to_height(diff, expected_diff_height, network) {
            Ok(engine) => Some(engine),
            Err(err) => {
                println!("[Processor] Failed to initialize engine: {}", err);
                None

            }
        }
        Err(err) => {
            println!("[Processor] Failed to deserialize checkpoint: {}", err);
            None
        }
    }
}

#[ferment_macro::export]
impl MasternodeProcessor {

    pub fn reinit_engine(&mut self, chain_type: ChainType, diff_config: Option<DiffConfig>) {
        let network = Network::from(chain_type);
        if let Some(engine) = diff_config.and_then(|DiffConfig { bytes, height }| maybe_engine_from_checkpoint(network, &bytes, height)) {
            self.engine = engine;
        } else {
            self.engine = MasternodeListEngine::default_for_network(network);
        }
    }

    pub fn clear(&mut self) {
        self.last_known_qr_info_block_height = None;
        self.engine.clear();
    }
    pub fn current_masternode_list(&self) -> Option<MasternodeList> {
        self.engine.latest_masternode_list().cloned()
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

    pub fn current_quorums_of_type_count(&self, quorum_type: &LLMQType) -> usize {
        self.current_masternode_list()
            .and_then(|list| list.quorums.get(quorum_type).map(|q| q.len()))
            .unwrap_or_default()
    }
    pub fn current_valid_quorums_of_type_count(&self, quorum_type: &LLMQType) -> usize {
        self.current_masternode_list()
            .and_then(|list| list.quorums.get(quorum_type).map(|q| q.values().filter(|q| q.verified == LLMQEntryVerificationStatus::Verified).count()))
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

    pub fn is_current_masternode_list_outdated(&self, tip_height: u32) -> bool {
        match self.current_masternode_list() {
            Some(list) => list.known_height == u32::MAX || tip_height > list.known_height + 8,
            None => true,
        }
    }

    pub fn is_qr_info_outdated(&self, tip_height: u32) -> bool {
        match self.last_known_qr_info_block_height {
            None => true,
            Some(last_qr_block_height) => {
                let DKGParams { mining_window_end, interval, .. } = if self.provider.chain_type().is_devnet_any() { DKG_DEVNET_DIP_0024 } else { DKG_60_75 };
                tip_height % interval == mining_window_end && tip_height >= last_qr_block_height + mining_window_end
            }
        }
    }

    pub fn masternode_lists(&self) -> BTreeMap<CoreBlockHeight, MasternodeList> {
        self.engine.masternode_lists.clone()
    }
    pub fn known_block_hashes(&self) -> BTreeMap<u32, [u8; 32]> {
        match &self.engine.block_container {
            MasternodeListEngineBlockContainer::BTreeMapContainer(map) => map.block_hashes.iter().map(|(h, hash)| (*h, hash.to_byte_array())).collect(),
        }
    }
    pub fn known_block_heights(&self) -> BTreeMap<[u8; 32], u32> {
        match &self.engine.block_container {
            MasternodeListEngineBlockContainer::BTreeMapContainer(map) => map.block_heights.iter().map(|(hash, h)| (hash.to_byte_array(), *h)).collect()
        }
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

    #[cfg(feature = "quorum_validation")]
    pub fn verify_current_masternode_list_quorums(&mut self) -> Result<bool, QuorumValidationError> {
        let current_list = self.current_masternode_list()
            .ok_or(QuorumValidationError::CorruptedCodeExecution("No current_masternode_list".to_string()))?;
        self.engine.verify_non_rotating_masternode_list_quorums(
            current_list.known_height,
            &[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85]
        )?;
        Ok(true)
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
        message: &[u8], verify_tip_non_rotated_quorums: bool, verify_rotated_quorums: bool) -> Result<BTreeSet<BlockHash>, ProcessingError> {

        let qr_info: QRInfo = deserialize(message)?;

        // let mut d = String::new();
        // d.push_str(format!("\ntip: {}", quorum_list_desc(&qr_info.mn_list_diff_h.new_quorums)).as_str());
        // d.push_str(format!("\n  h: {}", quorum_list_desc(&qr_info.mn_list_diff_h.new_quorums)).as_str());
        // d.push_str(format!("\n  h-c{}", quorum_list_desc(&qr_info.mn_list_diff_at_h_minus_c.new_quorums)).as_str());
        // d.push_str(format!("\n h-2c{}", quorum_list_desc(&qr_info.mn_list_diff_at_h_minus_2c.new_quorums)).as_str());
        // d.push_str(format!("\n h-3c{}", quorum_list_desc(&qr_info.mn_list_diff_at_h_minus_3c.new_quorums)).as_str());
        // d.push_str(format!("\n h-4c{}", qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.as_ref().map(|(q,qq)| quorum_list_desc(&qq.new_quorums)).unwrap_or_default()).as_str());
        // d.push_str(format!("\n lq/i{}", quorum_list_desc(&qr_info.last_commitment_per_index)).as_str());
        //
        // println!("QRINFO quorums: {d}");

        let get_height_fn = {
            |block_hash: &BlockHash| {
                if block_hash.as_byte_array().is_zero() {
                    return Ok(0);
                }
                let height = self.provider.lookup_block_height_by_hash(block_hash.to_byte_array());
                if height == u32::MAX {
                    Err(ClientDataRetrievalError::RequiredBlockNotPresent(*block_hash))
                } else {
                    Ok(height)
                }
            }
        };

        self.engine.feed_qr_info(
            qr_info,
            verify_tip_non_rotated_quorums,
            verify_rotated_quorums,
            Some(get_height_fn),
        )?;

        let hashes = self.engine.latest_masternode_list_non_rotating_quorum_hashes(
            match self.provider.chain_type() {
                ChainType::MainNet => &[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85],
                _ => &[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85, LLMQType::Llmqtype400_60],
            },
            true);
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

        println!("MNLDIFF quorums: {}", quorum_list_desc(&mn_list_diff.new_quorums));

        let base_block_hash = mn_list_diff.base_block_hash;
        let block_hash = mn_list_diff.block_hash;
        let base_block_height = self.provider.lookup_block_height_by_hash(base_block_hash.to_byte_array());
        let block_height = self.provider.lookup_block_height_by_hash(block_hash.to_byte_array());
        if base_block_height != u32::MAX {
            self.engine.feed_block_height(base_block_height, base_block_hash);
        }
        if block_height != u32::MAX {
            self.engine.feed_block_height(block_height, block_hash);
        }
        let signature = self.engine
            .apply_diff(mn_list_diff, diff_block_height, verify_quorums, None)
            .map_err(|e| ProcessingError::QuorumValidationError(QuorumValidationError::SMLError(e)))?;
        Ok((base_block_hash, block_hash))
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

    pub fn print_engine_status(&self) {
        let mut debug_string = format!("[{}] Engine Status:", self.engine.network);
        debug_string.push_str(format!("KnownLists ({}):\n", self.engine.masternode_lists.len()).as_str());
        debug_string.push_str(self.engine.masternode_lists.iter().fold(String::new(), |mut acc, (block_height, list)| {
            acc.push_str(format!("\t{}: {}\n", block_height, list.block_hash).as_str());
            acc
        }).as_str());
        debug_string.push_str("Quorums Statuses: \n");
        debug_string.push_str(self.engine.quorum_statuses.iter().fold(String::new(), |mut acc, (llmq_type, quorums)| {
            let quorums_of_type = quorums.iter().fold(String::new(), |mut acc, (quorum_hash, (set, key, status))| {
                acc.push_str(format!("\t\t{}: {}: {}\n", quorum_hash.to_string(), key.to_string(), status).as_str());
                acc
            });
            acc.push_str(format!("\t{llmq_type}:\n{quorums_of_type}\n").as_str());
            acc
        }).as_str());
        println!("{debug_string}");
    }
}

fn quorum_list_desc(q: &Vec<QuorumEntry>) -> String {
    q.iter().fold(String::new(), |mut acc, q| {
        acc.push_str(format!("\t{}: {}\n", q.llmq_type, q.quorum_hash.to_string()).as_str());
        acc
    })
}

#[cfg(all(test, feature = "test-helpers"))]
mod test {
    use dashcore::consensus::deserialize;
    use dashcore::network::message_sml::MnListDiff;
    use crate::test_helpers::message_from_file;

    #[test]
    fn test_testnet_qr_info() {
        let message = message_from_file("../files/QRINFO_MISSED_70235_766510624.244100.dat");
        let mn_list_diff : MnListDiff = deserialize(message.as_slice()).expect("message");
        let base_block_hash = mn_list_diff.base_block_hash;
        let block_hash = mn_list_diff.block_hash;
        println!("base block hash: {}, {}", base_block_hash.to_string(), block_hash.to_string());
    }
}