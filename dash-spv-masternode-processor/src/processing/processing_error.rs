use crate::processing::CoreProviderError;

#[warn(non_camel_case_types)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
#[ferment_macro::export]
pub enum ProcessingError {
    PersistInRetrieval = 1,
    LocallyStored = 2,
    ParseError = 3,
    HasNoBaseBlockHash = 4,
    UnknownBlockHash = 5,
    InvalidResult = 6,
    CoreProvider = 7,
    MissingLists = 8,
}
impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string_value())
    }
}

impl std::error::Error for ProcessingError {}

impl From<byte::Error> for ProcessingError {
    fn from(value: byte::Error) -> Self {
        ProcessingError::ParseError
    }
}

impl From<bls_signatures::BlsError> for ProcessingError {
    fn from(value: bls_signatures::BlsError) -> Self {
        ProcessingError::ParseError
    }
}

impl From<secp256k1::Error> for ProcessingError {
    fn from(value: secp256k1::Error) -> Self {
        ProcessingError::ParseError
    }
}

impl From<hashes::hex::Error> for ProcessingError {
    fn from(value: hashes::hex::Error) -> Self {
        ProcessingError::ParseError
    }
}

impl From<CoreProviderError> for ProcessingError {
    fn from(value: CoreProviderError) -> Self {
        ProcessingError::CoreProvider
    }
}

impl From<u8> for ProcessingError {
    fn from(orig: u8) -> Self {
        match orig {
            // 0 => ProcessingError::None,
            1 => ProcessingError::PersistInRetrieval,
            2 => ProcessingError::LocallyStored,
            3 => ProcessingError::ParseError,
            4 => ProcessingError::HasNoBaseBlockHash,
            5 => ProcessingError::UnknownBlockHash,
            6 => ProcessingError::InvalidResult,
            7 => ProcessingError::CoreProvider,
            8 => ProcessingError::MissingLists,
            _ => panic!("unknown error type")
            // _ => ProcessingError::None,
        }
    }
}

impl From<&ProcessingError> for u8 {
    fn from(error: &ProcessingError) -> Self {
        match error {
            // ProcessingError::None => 0,
            ProcessingError::PersistInRetrieval => 1,
            ProcessingError::LocallyStored => 2,
            ProcessingError::ParseError => 3,
            ProcessingError::HasNoBaseBlockHash => 4,
            ProcessingError::UnknownBlockHash => 5,
            ProcessingError::InvalidResult => 6,
            ProcessingError::CoreProvider => 7,
            ProcessingError::MissingLists => 8,
        }
    }
}

#[ferment_macro::export]
impl ProcessingError {
    pub fn index(&self) -> u8 {
        u8::from(self)
    }
    pub fn string_value(&self) -> String {
        match self {
            ProcessingError::PersistInRetrieval => "PersistInRetrieval",
            ProcessingError::LocallyStored => "LocallyStored",
            ProcessingError::ParseError => "ParseError",
            ProcessingError::HasNoBaseBlockHash => "HasNoBaseBlockHash",
            ProcessingError::UnknownBlockHash => "UnknownBlockHash",
            ProcessingError::InvalidResult => "InvalidResult",
            ProcessingError::CoreProvider => "CoreProvider",
            ProcessingError::MissingLists => "MissingLists",
        }.to_string()
    }
}