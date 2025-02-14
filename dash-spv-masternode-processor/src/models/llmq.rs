use std::cmp::min;
use std::fmt::{Display, Formatter};
use hashes::hex::ToHex;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_crypto::keys::BLSKey;
use dash_spv_crypto::llmq::entry::LLMQEntry;
use dash_spv_crypto::llmq::{LLMQEntryValidationSkipStatus, LLMQEntryValidationStatus};
use dash_spv_crypto::llmq::validation_error::LLMQValidationError;
use crate::models::MasternodeEntry;
use crate::processing::core_provider::CoreProviderError;

#[derive(PartialEq)]
pub enum LLMQVerificationContext {
    None,
    MNListDiff,
    QRInfo(bool),
}

impl Display for LLMQVerificationContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQVerificationContext::None => "None".to_string(),
            LLMQVerificationContext::MNListDiff => "MNListDiff".to_string(),
            LLMQVerificationContext::QRInfo(is_quorum_rotation_activated) => format!("QRInfo({is_quorum_rotation_activated})"),
        }.as_str())
    }
}

impl LLMQVerificationContext {
    pub fn should_validate_quorums(&self) -> bool {
        *self != Self::None
    }
    pub fn has_reason_to_skip_validation(&self, llmq_type: LLMQType, chain_type: ChainType, block_height: u32) -> Option<LLMQEntryValidationSkipStatus> {
        match self {
            LLMQVerificationContext::QRInfo(true) if !chain_type.isd_llmq_type().eq(&llmq_type) =>
                Some(LLMQEntryValidationSkipStatus::OtherContext(format!("Non-rotated LLMQ in {self} ({block_height})"))),
            LLMQVerificationContext::QRInfo(false) =>
                Some(LLMQEntryValidationSkipStatus::OtherContext(format!("Rotated llmq aren't activated yet ({block_height} {self})"))),
            LLMQVerificationContext::MNListDiff if chain_type.isd_llmq_type().eq(&llmq_type) =>
                Some(LLMQEntryValidationSkipStatus::OtherContext(format!("Rotated llmq in {self} ({block_height})"))),
            LLMQVerificationContext::MNListDiff if !chain_type.should_process_llmq_of_type(llmq_type) =>
                Some(LLMQEntryValidationSkipStatus::OtherContext(format!("Unappropriated llmq in {self} ({block_height})"))),
            LLMQVerificationContext::None =>
                Some(LLMQEntryValidationSkipStatus::OtherContext(format!("{self} ({block_height})"))),
            _ => None
        }
    }
}

pub fn validate(entry: &mut LLMQEntry, valid_masternodes: Vec<MasternodeEntry>, block_height: u32) -> Result<(), CoreProviderError> {
    let commitment_hash = entry.generate_commitment_hash();
    let use_legacy = entry.version.use_bls_legacy();
    let llmq_type = entry.llmq_type;
    let llmq_hash = entry.llmq_hash;
    let aggregated_signature = entry.all_commitment_aggregated_signature;
    let threshold_signature = entry.threshold_signature;
    let count = min(llmq_type.size() as usize, valid_masternodes.len());
    let operator_keys = valid_masternodes
        .iter()
        .enumerate()
        .filter_map(|(i, node)| (node.is_valid && entry.signers.bit_is_true_at_le_index(i))
            .then(|| node.operator_public_key_at(block_height)))
        .take(count)
        .collect::<Vec<_>>();
    let operator_keys_count = operator_keys.len();
    let all_commitment_aggregated_signature_validated = BLSKey::verify_secure_aggregated(
        commitment_hash,
        aggregated_signature,
        operator_keys,
        use_legacy,
    );
    if !all_commitment_aggregated_signature_validated {
        let error = LLMQValidationError::InvalidAggregatedSignature {
            block_height,
            operator_keys_count,
            valid_masternodes_count: valid_masternodes.len(),
            llmq_type,
            llmq_hash,
            aggregated_signature
        };
        warn!("INVALID AGGREGATED SIGNATURE {block_height} {} {} {} masternodes: {}, keys: {operator_keys_count}", llmq_type, llmq_hash.to_hex(), aggregated_signature.to_hex(), valid_masternodes.len());
        entry.verified = LLMQEntryValidationStatus::Invalid(error.clone());
        return Err(CoreProviderError::QuorumValidation(error));
    }
    // The sig must validate against the commitmentHash and all public keys determined by the signers bitvector.
    // This is an aggregated BLS signature verification.
    let quorum_signature_validated = BLSKey::verify_quorum_signature(
        &commitment_hash,
        &threshold_signature,
        &entry.public_key,
        use_legacy,
    );
    if !quorum_signature_validated {
        warn!("INVALID QUORUM SIGNATURE {}: {:?} ({})", block_height, llmq_type, threshold_signature.to_hex());
        let error = LLMQValidationError::InvalidQuorumSignature {
            block_height,
            llmq_type,
            llmq_hash,
            threshold_signature,
        };
        entry.verified = LLMQEntryValidationStatus::Invalid(error.clone());
        return Err(CoreProviderError::QuorumValidation(error));
    }
    println!("LLMQ of {} at {block_height}: {} verified", llmq_type, llmq_hash.to_hex());
    entry.verified = LLMQEntryValidationStatus::Verified;
    Ok(())
}

pub fn validate_payload(entry: &LLMQEntry) -> Result<(), LLMQValidationError> {
    // The quorumHash must match the current DKG session
    // todo
    let is_valid_signers =
        LLMQEntry::validate_bitset(&entry.signers);
    if !is_valid_signers {
        warn!("Error: signers_bitset is invalid ({:?})", entry.signers);
        return Err(LLMQValidationError::InvalidSigners(entry.signers.bitset.to_hex()));
    }
    let is_valid_members =
        LLMQEntry::validate_bitset(&entry.valid_members);
    if !is_valid_members {
        warn!("Error: valid_members_bitset is invalid ({:?})", entry.valid_members);
        return Err(LLMQValidationError::InvalidMembers(entry.valid_members.bitset.to_hex()));
    }
    let quorum_threshold = entry.llmq_type.threshold() as u64;
    // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
    let signers_bitset_true_bits_count = entry.signers.true_bits_count();
    if signers_bitset_true_bits_count < quorum_threshold {
        warn!("Error: The number of set bits in the signers {} must be >= quorumThreshold {}", signers_bitset_true_bits_count, quorum_threshold);
        return Err(LLMQValidationError::SignersBelowThreshold { actual: signers_bitset_true_bits_count, threshold: quorum_threshold });
    }
    let valid_members_bitset_true_bits_count = entry.valid_members.true_bits_count();
    if valid_members_bitset_true_bits_count < quorum_threshold {
        warn!("Error: The number of set bits in the valid members bitvector {} must be >= quorumThreshold {}", valid_members_bitset_true_bits_count, quorum_threshold);
        return Err(LLMQValidationError::SignersBelowThreshold { actual: valid_members_bitset_true_bits_count, threshold: quorum_threshold });
    }
    Ok(())
}
