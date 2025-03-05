use std::collections::BTreeSet;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::consensus::deserialize;
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::BlockHash;
use dashcore::hashes::Hash;
use dashcore::network::message_sml::MnListDiff;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::quorum_validation_error::{ClientDataRetrievalError, QuorumValidationError};
use dash_spv_crypto::crypto::byte_util::Zeroable;
use crate::processing::MasternodeProcessor;
use crate::processing::processor::processing_error::ProcessingError;

#[ferment_macro::export]
impl MasternodeProcessor {
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
                self.provider.lookup_block_height_by_hash(block_hash.to_byte_array()).ok_or(ClientDataRetrievalError::RequiredBlockNotPresent(*block_hash))
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

        let hashes = self.engine.latest_masternode_list_non_rotating_quorum_hashes(&[LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_85]);
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