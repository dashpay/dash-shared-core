#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub enum LLMQValidationStatus {
    Verified,
    InvalidPayload(LLMQPayloadValidationStatus),
    InvalidAggregatedSignature,
    InvalidQuorumSignature,
    NoMasternodeList
}

impl LLMQValidationStatus {
    pub fn is_not_critical(&self) -> bool {
        match self {
            Self::Verified | Self::NoMasternodeList => true,
            _ => false
        }
    }
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
