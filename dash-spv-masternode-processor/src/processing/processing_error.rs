#[warn(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub enum ProcessingError {
    None = 0,
    PersistInRetrieval = 1,
    LocallyStored = 2,
    ParseError = 3,
    HasNoBaseBlockHash = 4,
    UnknownBlockHash = 5,
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

