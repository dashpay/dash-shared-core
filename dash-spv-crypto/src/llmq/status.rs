use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[ferment_macro::export]
pub enum LLMQValidationError {
    InvalidPayload(LLMQPayloadValidationStatus),
    InvalidAggregatedSignature,
    InvalidQuorumSignature,
}

impl Display for LLMQValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQValidationError::InvalidPayload(status) => format!("InvalidPayload({status})"),
            LLMQValidationError::InvalidAggregatedSignature => "InvalidAggregatedSignature".to_string(),
            LLMQValidationError::InvalidQuorumSignature => "InvalidQuorumSignature".to_string(),
        }.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
#[ferment_macro::export]
pub enum LLMQPayloadValidationStatus {
    Ok,
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
impl Display for LLMQPayloadValidationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQPayloadValidationStatus::Ok => "Ok".to_string(),
            LLMQPayloadValidationStatus::InvalidSigners(message) => format!("InvalidSigners({message})"),
            LLMQPayloadValidationStatus::InvalidMembers(message) => format!("InvalidMembers({message})"),
            LLMQPayloadValidationStatus::SignersBelowThreshold { actual, threshold } => format!("SignersBelowThreshold({actual}/{threshold})"),
            LLMQPayloadValidationStatus::MembersBelowThreshold { actual, threshold } => format!("MembersBelowThreshold({actual}/{threshold})"),
        }.as_str())
    }
}
impl LLMQPayloadValidationStatus {
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }
}
