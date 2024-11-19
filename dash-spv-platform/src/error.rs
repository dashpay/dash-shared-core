use dash_spv_crypto::keys::KeyError;

pub trait RetryError {
    fn on_exceeded<T>(&self) -> T;
}
#[derive(Clone)]
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
