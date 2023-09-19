
#[warn(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
#[rs_ffi_macro_derive::impl_ffi_conv]
pub enum ProcessingError {
    None = 0,
    PersistInRetrieval = 1,
    LocallyStored = 2,
    ParseError = 3,
    HasNoBaseBlockHash = 4,
    UnknownBlockHash = 5,
}
impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
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

impl From<u8> for ProcessingError {
    fn from(orig: u8) -> Self {
        match orig {
            0 => ProcessingError::None,
            1 => ProcessingError::PersistInRetrieval,
            2 => ProcessingError::LocallyStored,
            3 => ProcessingError::ParseError,
            4 => ProcessingError::HasNoBaseBlockHash,
            5 => ProcessingError::UnknownBlockHash,
            _ => ProcessingError::None,
        }
    }
}

impl From<ProcessingError> for u8 {
    fn from(error: ProcessingError) -> Self {
        match error {
            ProcessingError::None => 0,
            ProcessingError::PersistInRetrieval => 1,
            ProcessingError::LocallyStored => 2,
            ProcessingError::ParseError => 3,
            ProcessingError::HasNoBaseBlockHash => 4,
            ProcessingError::UnknownBlockHash => 5,
        }
    }
}

