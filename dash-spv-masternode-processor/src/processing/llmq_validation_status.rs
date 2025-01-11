#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LLMQValidationError {
    InvalidPayload(LLMQPayloadValidationStatus),
    InvalidAggregatedSignature,
    InvalidQuorumSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
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

impl LLMQPayloadValidationStatus {
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }
}
