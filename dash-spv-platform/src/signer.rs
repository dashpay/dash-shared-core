use std::ffi::c_void;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use dash_sdk::dpp::ProtocolError;
use drive::dpp::identity::IdentityPublicKey;
use drive::dpp::identity::signer::Signer;
use platform_value::BinaryData;
use crate::FFIThreadSafeContext;


#[derive(Clone)]
pub struct CallbackSigner {
    pub signer: Arc<dyn Fn(*const c_void, IdentityPublicKey, Vec<u8>) -> Result<BinaryData, ProtocolError> + Send + Sync>,
    pub context: Arc<FFIThreadSafeContext>
}

impl CallbackSigner {
    pub fn new<T>(signer: T, context: Arc<FFIThreadSafeContext>) -> Self
        where T: Fn(*const c_void, IdentityPublicKey, Vec<u8>) -> Result<BinaryData, ProtocolError> + Send + Sync + 'static {
        Self { signer: Arc::new(signer), context }
    }
}

impl Debug for CallbackSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("{:?}", self.context).as_str())
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, identity_public_key: &IdentityPublicKey, data: &[u8]) -> Result<BinaryData, ProtocolError> {
        (self.signer)(self.context.get(), identity_public_key.clone(), Vec::from(data))
    }
}
