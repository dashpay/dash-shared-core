use std::ffi::c_void;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use dash_sdk::dpp;
use dpp::identity::{identity_public_key::IdentityPublicKey, signer::Signer};
use dash_sdk::dpp::ProtocolError;
use platform_value::BinaryData;
use crate::FFIThreadSafeContext;


#[derive(Clone)]
pub struct CallbackSigner {
    pub signer: Arc<dyn Fn(*const c_void, &IdentityPublicKey, Vec<u8>) -> Result<BinaryData, ProtocolError> + Send + Sync>,
    pub can_sign: Arc<dyn Fn(*const c_void, &IdentityPublicKey) -> bool + Send + Sync>,
    pub context: Arc<FFIThreadSafeContext>
}

impl CallbackSigner {
    pub fn new<T, U>(signer: T, can_sign: U, context: Arc<FFIThreadSafeContext>) -> Self
        where T: Fn(*const c_void, &IdentityPublicKey, Vec<u8>) -> Result<BinaryData, ProtocolError> + Send + Sync + 'static,
              U: Fn(*const c_void, &IdentityPublicKey) -> bool + Send + Sync + 'static,
    U: Fn(*const c_void, &IdentityPublicKey) -> bool {
        Self { signer: Arc::new(signer), can_sign: Arc::new(can_sign), context }
    }
}

impl Debug for CallbackSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("{:?}", self.context).as_str())
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, identity_public_key: &IdentityPublicKey, data: &[u8]) -> Result<BinaryData, ProtocolError> {
        (self.signer)(self.context.get(), identity_public_key, Vec::from(data))
    }

    fn can_sign_with(&self, identity_public_key: &IdentityPublicKey) -> bool {
        (self.can_sign)(self.context.get(), identity_public_key)
    }
}
