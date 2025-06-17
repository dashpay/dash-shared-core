use dash_sdk::dapi_client::{AddressListError, DapiClientError, ExecutionError};
use dpp::data_contract::errors::DataContractError;
use dpp::errors::consensus::basic::BasicError;
use dpp::errors::consensus::ConsensusError;
use dash_spv_crypto::keys::KeyError;
use dpp::errors::ProtocolError;
use http::uri::InvalidUri;
use dash_spv_chain::ChainError;
use dash_spv_keychain::KeyChainError;
use dash_spv_storage::error::StorageError;
use crate::identity::model::AssetLockSubmissionError;
use crate::identity::username_registration_error::UsernameRegistrationError;
use crate::util::{MaxRetryError, ValidationError};

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum Error {
    KeyError(KeyError),
    KeychainError(KeyChainError),
    Chain(ChainError),
    StorageError(StorageError),
    DashSDKError(String),
    Any(i32, String),
    MaxRetryExceeded(String),
    InstantSendSignatureVerificationError(String),
    UsernameRegistrationError(UsernameRegistrationError),
    RegisterKeysBeforeIdentity(u32),
    AttemptQueryWithoutKeys,
    IdentityIsNoLongerActive([u8; 32]),
    AssetLockSubmission(AssetLockSubmissionError),
    AssetLockTransactionShouldBeKnown,
    AssetLockInstantLockShouldBeKnownWhenTxUnconfirmed,
    AssetLockNoCreditBurnPubKeyHash,
    DerivationIndexesDoesntMatch,
    CannotSignIdentityWithoutWallet
}


impl From<dash_sdk::Error> for Error {
    fn from(e: dash_sdk::Error) -> Self {
        if let dash_sdk::Error::Protocol(ProtocolError::ConsensusError(ref err)) = e {
            if let ConsensusError::BasicError(BasicError::InvalidInstantAssetLockProofSignatureError(err)) = &**err {
                return Error::InstantSendSignatureVerificationError(format!("{err:?}"));
            }
        }
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
impl From<dashcore::consensus::encode::Error> for Error {
    fn from(value: dashcore::consensus::encode::Error) -> Self {
        Error::DashSDKError(value.to_string())
    }
}

impl From<Box<ConsensusError>> for Error {
    fn from(value: Box<ConsensusError>) -> Self {
        Error::DashSDKError(format!("{value:?}"))
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
