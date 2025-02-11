use std::cmp::min;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use hashes::hex::ToHex;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_crypto::crypto::byte_util::Reversed;
use dash_spv_crypto::keys::BLSKey;
use dash_spv_crypto::llmq::entry::{LLMQEntry, LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus};
use dash_spv_crypto::llmq::status::{LLMQValidationError, LLMQPayloadValidationStatus};
use dash_spv_crypto::llmq::modifier::LLMQModifierType;
use crate::models::masternode_list::score_masternodes_map;
use crate::models::MasternodeEntry;
use crate::processing::core_provider::CoreProviderError;
use crate::util::formatter::CustomFormatter;

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
    pub fn has_reason_to_skip_validation(&self, llmq_type: LLMQType, chain_type: ChainType, block_height: u32) -> Option<LLMQEntryVerificationSkipStatus> {
        match self {
            LLMQVerificationContext::QRInfo(true) if !chain_type.isd_llmq_type().eq(&llmq_type) =>
                Some(LLMQEntryVerificationSkipStatus::OtherContext(format!("Non-rotated LLMQ in {self} ({block_height})"))),
            LLMQVerificationContext::QRInfo(false) =>
                Some(LLMQEntryVerificationSkipStatus::OtherContext(format!("Rotated llmq aren't activated yet ({block_height} {self})"))),
            LLMQVerificationContext::MNListDiff if chain_type.isd_llmq_type().eq(&llmq_type) =>
                Some(LLMQEntryVerificationSkipStatus::OtherContext(format!("Rotated llmq in {self} ({block_height})"))),
            LLMQVerificationContext::MNListDiff if !chain_type.should_process_llmq_of_type(llmq_type) =>
                Some(LLMQEntryVerificationSkipStatus::OtherContext(format!("Unappropriated llmq in {self} ({block_height})"))),
            LLMQVerificationContext::None =>
                Some(LLMQEntryVerificationSkipStatus::OtherContext(format!("{self} ({block_height})"))),
            _ => None
        }
    }
}

pub fn validate(entry: &mut LLMQEntry, valid_masternodes: Vec<MasternodeEntry>, block_height: u32) -> Result<(), CoreProviderError> {
    let commitment_hash = entry.generate_commitment_hash();
    let use_legacy = entry.version.use_bls_legacy();
    let operator_keys = valid_masternodes
        .iter()
        .enumerate()
        .filter_map(|(i, node)| {
            if !node.is_valid {
                None
            } else if entry.signers.bit_is_true_at_le_index(i) {
                Some(node.operator_public_key_at(block_height))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let valid_masternodes_count = valid_masternodes.len();
    let operator_keys_count = operator_keys.len();
    let all_commitment_aggregated_signature_validated = BLSKey::verify_secure_aggregated(
        commitment_hash,
        entry.all_commitment_aggregated_signature,
        operator_keys.clone(),
        use_legacy,
    );
    if !all_commitment_aggregated_signature_validated {
        warn!("INVALID AGGREGATED SIGNATURE {block_height} {} {} {} masternodes: {valid_masternodes_count}, keys: {operator_keys_count}", entry.llmq_type, entry.llmq_hash.to_hex(), entry.all_commitment_aggregated_signature.to_hex());
        entry.verified = LLMQEntryVerificationStatus::Invalid(LLMQValidationError::InvalidAggregatedSignature);
        return Err(CoreProviderError::QuorumValidation(LLMQValidationError::InvalidAggregatedSignature));
    }
    // The sig must validate against the commitmentHash and all public keys determined by the signers bitvector.
    // This is an aggregated BLS signature verification.
    let quorum_signature_validated = BLSKey::verify_quorum_signature(
        &commitment_hash,
        &entry.threshold_signature,
        &entry.public_key,
        use_legacy,
    );
    if !quorum_signature_validated {
        warn!("INVALID QUORUM SIGNATURE {}: {:?} ({})", block_height, entry.llmq_type, entry.threshold_signature.to_hex());
        entry.verified = LLMQEntryVerificationStatus::Invalid(LLMQValidationError::InvalidQuorumSignature);
        return Err(CoreProviderError::QuorumValidation(LLMQValidationError::InvalidQuorumSignature));
    }
    println!("LLMQ of {} at {block_height}: {} verified", entry.llmq_type, entry.llmq_hash.to_hex());
    Ok(())
}

pub fn validate_payload(entry: &LLMQEntry) -> LLMQPayloadValidationStatus {
    // The quorumHash must match the current DKG session
    // todo
    let is_valid_signers =
        LLMQEntry::validate_bitset(&entry.signers);
    if !is_valid_signers {
        warn!("Error: signers_bitset is invalid ({:?})", entry.signers);
        return LLMQPayloadValidationStatus::InvalidSigners(entry.signers.bitset.to_hex());
    }
    let is_valid_members =
        LLMQEntry::validate_bitset(&entry.valid_members);
    if !is_valid_members {
        warn!("Error: valid_members_bitset is invalid ({:?})", entry.valid_members);
        return LLMQPayloadValidationStatus::InvalidMembers(entry.valid_members.bitset.to_hex());
    }
    let quorum_threshold = entry.llmq_type.threshold() as u64;
    // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
    let signers_bitset_true_bits_count = entry.signers.true_bits_count();
    if signers_bitset_true_bits_count < quorum_threshold {
        warn!("Error: The number of set bits in the signers {} must be >= quorumThreshold {}", signers_bitset_true_bits_count, quorum_threshold);
        return LLMQPayloadValidationStatus::SignersBelowThreshold { actual: signers_bitset_true_bits_count, threshold: quorum_threshold };
    }
    let valid_members_bitset_true_bits_count = entry.valid_members.true_bits_count();
    if valid_members_bitset_true_bits_count < quorum_threshold {
        warn!("Error: The number of set bits in the valid members bitvector {} must be >= quorumThreshold {}", valid_members_bitset_true_bits_count, quorum_threshold);
        return LLMQPayloadValidationStatus::SignersBelowThreshold { actual: valid_members_bitset_true_bits_count, threshold: quorum_threshold };
    }
    LLMQPayloadValidationStatus::Ok
}


pub fn valid_masternodes(
    entry: &LLMQEntry,
    chain_type: ChainType,
    masternodes: &BTreeMap<[u8; 32], MasternodeEntry>,
    block_height: u32,
    llmq_modifier: LLMQModifierType
) -> Vec<MasternodeEntry> {
    // println!("•••••••••••••••••••");
    // println!("•••••••••••••••••••");
    // println!("•••••••••••••••••••");
    // println!("llmq_modifier: {}", llmq_modifier.build_llmq_hash().to_hex());
    // println!("•••••••••••••••••••");
    // println!("get_masternodes_for_quorum: \n{}", entry);
    // println!("•••••••••••••••••••");
    // println!("masternodes: \n{}", format_masternodes_map(&masternodes));
    // println!("•••••••••••••••••••");
    let llmq_type = entry.llmq_type.clone();
    let hpmn_only = llmq_type == chain_type.platform_type() && !entry.version.use_bls_legacy();
    let quorum_modifier = llmq_modifier.build_llmq_hash();
    let quorum_count = llmq_type.size();
    let masternode_count = masternodes.len();
    let mut score_dictionary = score_masternodes_map(masternodes, quorum_modifier, block_height, hpmn_only);
    let count = min(quorum_count as usize, score_dictionary.len());
    // println!("score_dictionary: \n{}", format_masternodes_map(&score_dictionary));
    // println!("•••••••••••••••••••");
    score_dictionary.sort_by(|(s1, _), (s2, _)| s2.reversed().cmp(&s1.reversed()));
    // println!("scores: \n{}", format_hash_vec(&scores));
    // println!("•••••••••••••••••••");
    score_dictionary.into_iter().take(count).map(|(_,masternode_entry)| masternode_entry).collect()
    // println!("valid_masternodes: \n{}", format_masternodes_vec(&valid_masternodes));
    // println!("•••••••••••••••••••");
    // println!("•••••••••••••••••••");
    // println!("•••••••••••••••••••");
}

