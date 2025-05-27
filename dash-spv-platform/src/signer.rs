use std::os::raw::c_void;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use dash_sdk::dpp;
use dpp::identity::{identity_public_key::IdentityPublicKey, signer::Signer};
use dash_sdk::dpp::ProtocolError;
use dashcore::hashes::{sha256d, Hash};
use platform_value::BinaryData;
use dash_spv_crypto::keys::{IKey, OpaqueKey};
use crate::FFIThreadSafeContext;


#[derive(Clone)]
pub struct CallbackSigner {
    pub signer: Arc<dyn Fn(*const c_void, IdentityPublicKey) -> Option<OpaqueKey> + Send + Sync>,
    pub can_sign: Arc<dyn Fn(*const c_void, IdentityPublicKey) -> bool + Send + Sync>,
    pub context: Arc<FFIThreadSafeContext>
}

impl CallbackSigner {
    pub fn new<T, U>(signer: T, can_sign: U, context: Arc<FFIThreadSafeContext>) -> Self
        where T: Fn(*const c_void, IdentityPublicKey) -> Option<OpaqueKey> + Send + Sync + 'static,
              U: Fn(*const c_void, IdentityPublicKey) -> bool + Send + Sync + 'static {
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
        let context = self.context.inner.lock().unwrap();
        let maybe_private_key = (self.signer)(*context, identity_public_key.clone());
        drop(context);

        match maybe_private_key {
            None => Err(ProtocolError::Generic(format!("Can't find a signer for identity public key: {:?}", identity_public_key))),
            Some(private_key) => {
                let hash = sha256d::Hash::hash(data);
                let signed = private_key.sign(hash.as_byte_array());
                Ok(BinaryData::new(signed))
            },
        }
    }

    fn can_sign_with(&self, identity_public_key: &IdentityPublicKey) -> bool {
        let context = self.context.inner.lock().unwrap();
        let can_sign = (self.can_sign)(*context, identity_public_key.clone());
        drop(context);
        can_sign
    }
}
