use std::cmp::min;
use std::collections::BTreeMap;
use hashes::hex::ToHex;
#[cfg(feature = "generate-dashj-tests")]
use serde::ser::SerializeStruct;
#[cfg(feature = "generate-dashj-tests")]
use serde::{Serialize, Serializer};
use dash_spv_crypto::network::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_crypto::crypto::byte_util::Reversed;
use dash_spv_crypto::keys::BLSKey;
use dash_spv_crypto::llmq::entry::LLMQEntry;
use dash_spv_crypto::llmq::modifier::LLMQModifierType;
use crate::models::masternode_list::score_masternodes_map;
use crate::models::MasternodeEntry;
use crate::processing::core_provider::CoreProviderError;
use crate::processing::llmq_validation_status::{LLMQValidationStatus, LLMQPayloadValidationStatus};

#[derive(PartialEq)]
pub enum LLMQVerificationContext {
    None,
    MNListDiff,
    QRInfo(bool),
}

impl LLMQVerificationContext {
    pub fn should_validate_quorums(&self) -> bool {
        *self != Self::None
    }
    pub fn should_validate_quorum_of_type(&self, llmq_type: LLMQType, chain_type: ChainType) -> bool {
        match self {
            LLMQVerificationContext::None => false,
            LLMQVerificationContext::MNListDiff =>
                chain_type.isd_llmq_type() != llmq_type && chain_type.should_process_llmq_of_type(llmq_type),
            LLMQVerificationContext::QRInfo(is_quorum_rotation_activated) =>
                chain_type.isd_llmq_type() == llmq_type && *is_quorum_rotation_activated == true
        }
    }
}




pub struct VecHex(pub Vec<u8>);
impl std::fmt::Debug for VecHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vec::from_hex(\"{}\").unwrap()", self.0.to_hex())
    }
}


// impl LLMQEntry {
//     #[allow(clippy::too_many_arguments)]
//     pub fn new(
//         version: LLMQVersion,
//         llmq_type: LLMQType,
//         llmq_hash: UInt256,
//         index: Option<u16>,
//         signers: Bitset,
//         valid_members: Bitset,
//         public_key: UInt384,
//         verification_vector_hash: UInt256,
//         threshold_signature: UInt768,
//         all_commitment_aggregated_signature: UInt768,
//     ) -> Self {
//         let q_data = generate_data(
//             version,
//             llmq_type,
//             llmq_hash,
//             index,
//             &signers,
//             &valid_members,
//             public_key,
//             verification_vector_hash,
//             threshold_signature,
//             all_commitment_aggregated_signature,
//         );
//         Self {
//             version,
//             llmq_hash,
//             index,
//             public_key,
//             threshold_signature,
//             verification_vector_hash,
//             all_commitment_aggregated_signature,
//             llmq_type,
//             signers,
//             valid_members,
//             entry_hash: UInt256::sha256d(q_data),
//             verified: false,
//             saved: false,
//             commitment_hash: None,
//         }
//     }
//
//
//     pub fn to_data(&self) -> Vec<u8> {
//         generate_data(
//             self.version,
//             self.llmq_type,
//             self.llmq_hash,
//             self.index,
//             &self.signers,
//             &self.valid_members,
//             self.public_key,
//             self.verification_vector_hash,
//             self.threshold_signature,
//             self.all_commitment_aggregated_signature,
//         )
//     }
//     pub fn valid_masternodes(&self, chain_type: ChainType, masternodes: BTreeMap<UInt256, MasternodeEntry>, block_height: u32, llmq_modifier: LLMQModifierType) -> Vec<MasternodeEntry> {
//         let llmq_type = self.llmq_type;
//         let hpmn_only = llmq_type == chain_type.platform_type() && !self.version.use_bls_legacy();
//         let quorum_modifier = llmq_modifier.build_llmq_hash();
//         let quorum_count = llmq_type.size();
//         let masternode_count = masternodes.len();
//         let score_dictionary = score_masternodes_map(masternodes, quorum_modifier, block_height, hpmn_only);
//         let count = min(masternode_count, score_dictionary.len());
//         let mut scores: Vec<UInt256> = score_dictionary.clone().into_keys().collect();
//         scores.sort_by(|&s1, &s2| s2.reversed().cmp(&s1.reversed()));
//         let mut valid_masternodes: Vec<MasternodeEntry> = Vec::new();
//         // TODO: is that correct to take count here before checking validity?
//         for score in scores.iter().take(count) {
//             if let Some(masternode) = score_dictionary.get(score) {
//                 if masternode.is_valid_at(block_height) {
//                     valid_masternodes.push(masternode.clone());
//                 }
//             }
//             if valid_masternodes.len() == quorum_count as usize {
//                 break;
//             }
//         }
//         valid_masternodes
//     }
//
//     pub fn commitment_data(&self) -> Vec<u8> {
//         let mut buffer: Vec<u8> = Vec::new();
//         let offset: &mut usize = &mut 0;
//         let llmq_type = VarInt(self.llmq_type as u64);
//         *offset += llmq_type.enc(&mut buffer);
//         *offset += self.llmq_hash.enc(&mut buffer);
//         *offset += self.valid_members.enc(&mut buffer);
//         *offset += self.public_key.enc(&mut buffer);
//         *offset += self.verification_vector_hash.enc(&mut buffer);
//         buffer
//     }
//
//     pub fn ordering_hash_for_request_id(
//         &self,
//         request_id: UInt256,
//         llmq_type: LLMQType,
//     ) -> UInt256 {
//         let llmq_type = VarInt(llmq_type as u64);
//         let mut buffer: Vec<u8> = Vec::with_capacity(llmq_type.len() + 64);
//         llmq_type.enc(&mut buffer);
//         self.llmq_hash.enc(&mut buffer);
//         request_id.enc(&mut buffer);
//         UInt256::sha256d(buffer)
//     }
//
//     pub fn generate_commitment_hash(&mut self) -> UInt256 {
//         if self.commitment_hash.is_none() {
//             self.commitment_hash = Some(UInt256::sha256d(self.commitment_data()));
//         }
//         self.commitment_hash.unwrap()
//     }
//
//     fn validate_bitset(bitset: &Bitset) -> bool {
//         let Bitset { bitset, count } = bitset;
//         if bitset.len() != (count + 7) / 8 {
//             warn!(
//                 "Error: The byte size of the bitvectors ({}) must match “(quorumSize + 7) / 8 ({})",
//                 bitset.len(),
//                 (count + 7) / 8
//             );
//             return false;
//         }
//         let len = (bitset.len() * 8) as i32;
//         let size = *count as i32;
//         if len != size {
//             let rem = len - size;
//             let mask = !(0xff >> rem);
//             let last_byte = match bitset.last() {
//                 Some(&last) => last as i32,
//                 None => 0,
//             };
//             if last_byte & mask != 0 {
//                 warn!("Error: No out-of-range bits should be set in byte representation of the bitvector");
//                 return false;
//             }
//         }
//         true
//     }
//
//     pub fn validate_payload(&self) -> LLMQPayloadValidationStatus {
//         // The quorumHash must match the current DKG session
//         // todo
//         let is_valid_signers =
//             Self::validate_bitset(&self.signers);
//         if !is_valid_signers {
//             warn!("Error: signers_bitset is invalid ({:?})", self.signers);
//             return LLMQPayloadValidationStatus::InvalidSigners(self.signers.bitset.to_hex());
//         }
//         let is_valid_members =
//             Self::validate_bitset(&self.valid_members);
//         if !is_valid_members {
//             warn!("Error: valid_members_bitset is invalid ({:?})", self.valid_members);
//             return LLMQPayloadValidationStatus::InvalidMembers(self.valid_members.bitset.to_hex());
//         }
//         let quorum_threshold = self.llmq_type.threshold() as u64;
//         // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
//         let signers_bitset_true_bits_count = self.signers.true_bits_count();
//         if signers_bitset_true_bits_count < quorum_threshold {
//             warn!("Error: The number of set bits in the signers {} must be >= quorumThreshold {}", signers_bitset_true_bits_count, quorum_threshold);
//             return LLMQPayloadValidationStatus::SignersBelowThreshold { actual: signers_bitset_true_bits_count, threshold: quorum_threshold };
//         }
//         let valid_members_bitset_true_bits_count = self.valid_members.true_bits_count();
//         if valid_members_bitset_true_bits_count < quorum_threshold {
//             warn!("Error: The number of set bits in the valid members bitvector {} must be >= quorumThreshold {}", valid_members_bitset_true_bits_count, quorum_threshold);
//             return LLMQPayloadValidationStatus::SignersBelowThreshold { actual: valid_members_bitset_true_bits_count, threshold: quorum_threshold };
//         }
//         LLMQPayloadValidationStatus::Ok
//     }
// }

pub fn verify(entry: &mut LLMQEntry, valid_masternodes: Vec<MasternodeEntry>, block_height: u32) -> Result<LLMQValidationStatus, CoreProviderError> {
    let payload_status = validate_payload(entry);
    if !payload_status.is_ok() {
        return Ok(LLMQValidationStatus::InvalidPayload(payload_status));
    }
    let status = validate(entry, valid_masternodes, block_height);
    entry.verified = status == LLMQValidationStatus::Verified;
    Ok(status)
}

pub fn validate(entry: &mut LLMQEntry, valid_masternodes: Vec<MasternodeEntry>, block_height: u32) -> LLMQValidationStatus {
    let commitment_hash = entry.generate_commitment_hash();
    let use_legacy = entry.version.use_bls_legacy();
    let operator_keys = valid_masternodes
        .iter()
        .enumerate()
        .filter_map(|(i, node)|
            entry.signers.bit_is_true_at_le_index(i)
                .then_some(node.operator_public_key_at(block_height)))
        .collect::<Vec<_>>();
    // info!("let operator_keys = vec![{:?}];", operator_keys);
    let all_commitment_aggregated_signature_validated = BLSKey::verify_secure_aggregated(
        commitment_hash,
        entry.all_commitment_aggregated_signature,
        operator_keys,
        use_legacy,
    );
    if !all_commitment_aggregated_signature_validated {
        println!("••• INVALID AGGREGATED SIGNATURE {}: {:?} ({})", block_height, entry.llmq_type, entry.all_commitment_aggregated_signature.to_hex());
        return LLMQValidationStatus::InvalidAggregatedSignature;
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
        println!("••• INVALID QUORUM SIGNATURE {}: {:?} ({})", block_height, entry.llmq_type, entry.threshold_signature.to_hex());
        return LLMQValidationStatus::InvalidQuorumSignature;
    }
    println!("••• quorum {:?} validated at {}", entry.llmq_type, block_height);
    LLMQValidationStatus::Verified
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


pub fn valid_masternodes(entry: &LLMQEntry, chain_type: ChainType, masternodes: BTreeMap<[u8; 32], MasternodeEntry>, block_height: u32, llmq_modifier: LLMQModifierType) -> Vec<MasternodeEntry> {
    let llmq_type = entry.llmq_type;
    let hpmn_only = llmq_type == chain_type.platform_type() && !entry.version.use_bls_legacy();
    let quorum_modifier = llmq_modifier.build_llmq_hash();
    let quorum_count = llmq_type.size();
    let masternode_count = masternodes.len();
    let score_dictionary = score_masternodes_map(masternodes, quorum_modifier, block_height, hpmn_only);
    let count = min(masternode_count, score_dictionary.len());
    let mut scores: Vec<[u8; 32]> = score_dictionary.clone().into_keys().collect();
    scores.sort_by(|&s1, &s2| s2.reversed().cmp(&s1.reversed()));
    let mut valid_masternodes: Vec<MasternodeEntry> = Vec::new();
    // TODO: is that correct to take count here before checking validity?
    for score in scores.iter().take(count) {
        if let Some(masternode) = score_dictionary.get(score) {
            if masternode.is_valid_at(block_height) {
                valid_masternodes.push(masternode.clone());
            }
        }
        if valid_masternodes.len() == quorum_count as usize {
            break;
        }
    }
    valid_masternodes
}

