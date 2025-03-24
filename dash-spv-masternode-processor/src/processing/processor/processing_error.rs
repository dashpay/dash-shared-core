use dashcore::consensus;
use dashcore::secp256k1::hashes::hex::DisplayHex;
use dashcore::sml::quorum_validation_error::QuorumValidationError;
use crate::processing::CoreProviderError;

#[warn(non_camel_case_types)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[ferment_macro::export]
pub enum ProcessingError {
    PersistInRetrieval([u8; 32], [u8; 32]),
    LocallyStored(u32, [u8; 32]),
    ParseError(String),
    HasNoBaseBlockHash([u8; 32]),
    UnknownBlockHash([u8; 32]),
    InvalidResult(String),
    CoreProvider(CoreProviderError),
    MissingLists(String),
    EncodeError(String),
    DecodeError(String),
    QuorumValidationError(QuorumValidationError),
}
impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string_value())
    }
}

impl std::error::Error for ProcessingError {}

// impl From<bls_signatures::BlsError> for ProcessingError {
//     fn from(value: bls_signatures::BlsError) -> Self {
//         ProcessingError::ParseError(format!("{value}"))
//     }
// }

impl From<dashcore::secp256k1::Error> for ProcessingError {
    fn from(value: dashcore::secp256k1::Error) -> Self {
        ProcessingError::ParseError(format!("{value}"))
    }
}

impl From<dashcore::hashes::hex::Error> for ProcessingError {
    fn from(value: dashcore::hashes::hex::Error) -> Self {
        ProcessingError::ParseError(format!("{value}"))
    }
}

impl From<CoreProviderError> for ProcessingError {
    fn from(value: CoreProviderError) -> Self {
        ProcessingError::CoreProvider(value)
    }
}

impl From<QuorumValidationError> for ProcessingError {
    fn from(value: QuorumValidationError) -> Self {
        ProcessingError::QuorumValidationError(value)
    }
}

impl From<consensus::encode::Error> for ProcessingError {
    fn from(value: consensus::encode::Error) -> Self {
        ProcessingError::EncodeError(value.to_string())
    }
}

#[ferment_macro::export]
impl ProcessingError {
    pub fn string_value(&self) -> String {
        match self {
            ProcessingError::PersistInRetrieval(base_block_hash, block_hash) =>
                format!("PersistInRetrieval({}..{})", base_block_hash.to_lower_hex_string(), block_hash.to_lower_hex_string()),
            ProcessingError::LocallyStored(block_height, block_hash) =>
                format!("LocallyStored({}: {})", block_height, block_hash.to_lower_hex_string()),
            ProcessingError::ParseError(message) =>
                format!("ParseError({message})"),
            ProcessingError::HasNoBaseBlockHash(block_hash) =>
                format!("HasNoBaseBlockHash({}", block_hash.to_lower_hex_string()),
            ProcessingError::UnknownBlockHash(block_hash) =>
                format!("UnknownBlockHash({})", block_hash.to_lower_hex_string()),
            ProcessingError::InvalidResult(message) =>
                format!("InvalidResult({message})"),
            ProcessingError::CoreProvider(err) =>
                format!("CoreProvider({err})"),
            ProcessingError::MissingLists(message) =>
                format!("MissingLists({message})"),
            ProcessingError::QuorumValidationError(quorum_validation_error) =>
                format!("QuorumValidationError({quorum_validation_error})"),
            ProcessingError::EncodeError(encode_error) =>
                format!("EncodeError({encode_error})"),
            ProcessingError::DecodeError(encode_error) =>
                format!("DecodeError({encode_error})"),
        }
    }
}