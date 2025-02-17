use std::fmt::{Display, Formatter};
use hashes::hex::ToHex;
use crate::network::LLMQType;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[ferment_macro::export]
pub enum LLMQValidationError {
    InvalidAggregatedSignature {
        block_height: u32,
        operator_keys_count: usize,
        valid_masternodes_count: usize,
        llmq_type: LLMQType,
        llmq_hash: [u8; 32],
        aggregated_signature: [u8; 96]
    },
    InvalidQuorumSignature {
        block_height: u32,
        llmq_type: LLMQType,
        llmq_hash: [u8; 32],
        threshold_signature: [u8; 96]
    },
    InvalidSigners(String),
    InvalidMembers(String),
    SignersBelowThreshold {
        actual: u64,
        threshold: u64,
    },
    MembersBelowThreshold {
        actual: u64,
        threshold: u64,
    },

}

impl Display for LLMQValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQValidationError::InvalidAggregatedSignature { block_height, operator_keys_count, valid_masternodes_count, llmq_type, llmq_hash, aggregated_signature } =>
                format!("InvalidAggregatedSignature({block_height}: {llmq_type}: {}: {}: {operator_keys_count}/{valid_masternodes_count})", llmq_hash.to_hex(), aggregated_signature.to_hex()),
            LLMQValidationError::InvalidQuorumSignature { block_height, llmq_type, llmq_hash, threshold_signature } =>
                format!("InvalidQuorumSignature({block_height}: {llmq_type}: {}: {})", llmq_hash.to_hex(), threshold_signature.to_hex()),
            LLMQValidationError::InvalidSigners(message) =>
                format!("InvalidSigners({message})"),
            LLMQValidationError::InvalidMembers(message) =>
                format!("InvalidMembers({message})"),
            LLMQValidationError::SignersBelowThreshold { actual, threshold } =>
                format!("SignersBelowThreshold({actual}/{threshold})"),
            LLMQValidationError::MembersBelowThreshold { actual, threshold } =>
                format!("MembersBelowThreshold({actual}/{threshold})"),
        }.as_str())
    }
}
