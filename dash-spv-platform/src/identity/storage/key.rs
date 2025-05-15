use std::os::raw::c_void;
use dpp::identity::identity_public_key::{Purpose, SecurityLevel};
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::keys::OpaqueKey;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum SaveKeyContext {
    Full(IdentityKeyPlacement, OpaqueKey, SecurityLevel, Purpose),
    Status(IdentityKeyPlacement),
    CreateNew(IdentityKeyPlacement, KeyKind, u32, SecurityLevel, Purpose, bool),
}
#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub enum IdentityKeyPlacement {
    Local(*const c_void),
    Remote(u32),
}
#[ferment_macro::export]
impl IdentityKeyPlacement {
    pub fn maybe_derivation_context(&self) -> Option<*const c_void> {
        match self {
            IdentityKeyPlacement::Local(derivation_context) => Some(*derivation_context),
            _ => None
        }
    }
    pub fn maybe_key_id(&self) -> Option<u32> {
        match self {
            IdentityKeyPlacement::Remote(index) => Some(*index),
            _ => None
        }
    }
}