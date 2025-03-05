use dashcore::consensus;
use dashcore::sml::quorum_validation_error::QuorumValidationError;
use hashes::hex::ToHex;
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
    QuorumValidationError(QuorumValidationError),
}
impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string_value())
    }
}

impl std::error::Error for ProcessingError {}

impl From<byte::Error> for ProcessingError {
    fn from(value: byte::Error) -> Self {
        ProcessingError::ParseError(match value {
            byte::Error::Incomplete => "Incomplete".to_string(),
            byte::Error::BadOffset(offset) => format!("BadOffset({offset})"),
            byte::Error::BadInput { err } => format!("BadInput({err})"),
        })
    }
}

impl From<bls_signatures::BlsError> for ProcessingError {
    fn from(value: bls_signatures::BlsError) -> Self {
        ProcessingError::ParseError(format!("{value}"))
    }
}

impl From<secp256k1::Error> for ProcessingError {
    fn from(value: secp256k1::Error) -> Self {
        ProcessingError::ParseError(format!("{value}"))
    }
}

impl From<hashes::hex::Error> for ProcessingError {
    fn from(value: hashes::hex::Error) -> Self {
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

//
// impl From<u8> for ProcessingError {
//     fn from(orig: u8) -> Self {
//         match orig {
//             // 0 => ProcessingError::None,
//             1 => ProcessingError::PersistInRetrieval,
//             2 => ProcessingError::LocallyStored,
//             3 => ProcessingError::ParseError,
//             4 => ProcessingError::HasNoBaseBlockHash,
//             5 => ProcessingError::UnknownBlockHash,
//             6 => ProcessingError::InvalidResult,
//             7 => ProcessingError::CoreProvider,
//             8 => ProcessingError::MissingLists,
//             _ => panic!("unknown error type")
//             // _ => ProcessingError::None,
//         }
//     }
// }
//
// impl From<&ProcessingError> for u8 {
//     fn from(error: &ProcessingError) -> Self {
//         match error {
//             // ProcessingError::None => 0,
//             ProcessingError::PersistInRetrieval => 1,
//             ProcessingError::LocallyStored => 2,
//             ProcessingError::ParseError => 3,
//             ProcessingError::HasNoBaseBlockHash => 4,
//             ProcessingError::UnknownBlockHash => 5,
//             ProcessingError::InvalidResult => 6,
//             ProcessingError::CoreProvider => 7,
//             ProcessingError::MissingLists => 8,
//         }
//     }
// }

#[ferment_macro::export]
impl ProcessingError {
    // pub fn index(&self) -> u8 {
    //     u8::from(self)
    // }
    pub fn string_value(&self) -> String {
        match self {
            ProcessingError::PersistInRetrieval(base_block_hash, block_hash) =>
                format!("PersistInRetrieval({}..{})", base_block_hash.to_hex(), block_hash.to_hex()),
            ProcessingError::LocallyStored(block_height, block_hash) =>
                format!("LocallyStored({}: {})", block_height, block_hash.to_hex()),
            ProcessingError::ParseError(message) =>
                format!("ParseError({message})"),
            ProcessingError::HasNoBaseBlockHash(block_hash) =>
                format!("HasNoBaseBlockHash({}", block_hash.to_hex()),
            ProcessingError::UnknownBlockHash(block_hash) =>
                format!("UnknownBlockHash({})", block_hash.to_hex()),
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
        }
    }
}