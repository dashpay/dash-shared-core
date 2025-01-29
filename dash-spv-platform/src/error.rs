use dash_sdk::dapi_client::{AddressListError, DapiClientError, ExecutionError};
use dpp::data_contract::errors::DataContractError;
use dash_spv_crypto::keys::KeyError;
use dpp::errors::ProtocolError;
use http::uri::InvalidUri;
use dash_spv_crypto::consensus::encode;
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
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::DashSDKError(e.to_string())
    }
}
impl From<InvalidUri> for Error {
    fn from(e: InvalidUri) -> Self {
        Error::DashSDKError(e.to_string())
    }
}
impl From<AddressListError> for Error {
    fn from(value: AddressListError) -> Self {
        Error::DashSDKError(value.to_string())
    }
}

impl From<ExecutionError<DapiClientError>> for Error {
    fn from(value: ExecutionError<DapiClientError>) -> Self {
        Error::DashSDKError(value.to_string())
    }
}
impl From<DataContractError> for Error {
    fn from(value: DataContractError) -> Self {
        Error::DashSDKError(value.to_string())
    }
}
impl From<encode::Error> for Error {
    fn from(value: encode::Error) -> Self {
        Error::DashSDKError(value.to_string())
    }
}
impl From<dashcore::consensus::encode::Error> for Error {
    fn from(value: dashcore::consensus::encode::Error) -> Self {
        Error::DashSDKError(value.to_string())
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
