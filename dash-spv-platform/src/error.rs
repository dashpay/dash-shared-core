use dash_spv_crypto::keys::KeyError;
use dpp::errors::ProtocolError;
use http::uri::InvalidUri;
use crate::util::{MaxRetryError, ValidationError};

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum Error {
    KeyError(KeyError),
    DashSDKError(String),
    Any(i32, String),
    MaxRetryExceeded(String),
}


impl From<dash_sdk::Error> for Error {
    fn from(e: dash_sdk::Error) -> Self {
        Error::DashSDKError(format!("{e:?}"))
    }
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Error::DashSDKError(e.to_string())
    }
}
impl From<InvalidUri> for Error {
    fn from(e: InvalidUri) -> Self {
        Error::DashSDKError(e.to_string())
    }
}

impl MaxRetryError for Error {
    fn max_retry_error() -> Self {
        Error::MaxRetryExceeded("".to_string())
    }
}
impl MaxRetryError for dash_sdk::Error {
    fn max_retry_error() -> Self {
        dash_sdk::Error::Generic("max retry exceeded".to_string())
    }
}
impl ValidationError for dash_sdk::Error {
    fn validation_error() -> Self {
        dash_sdk::Error::Generic("Validation failed".to_string())
    }
}