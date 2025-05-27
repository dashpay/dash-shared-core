use dash_spv_crypto::keys::{IKey, OpaqueKey};
use dpp::identity::identity_public_key::purpose::Purpose;
use dpp::identity::identity_public_key::security_level::SecurityLevel;
use dash_spv_crypto::keys::key::KeyKind;
use crate::identity::key_status::IdentityKeyStatus;

#[derive(Clone)]
#[ferment_macro::export]
pub struct KeyInfo {
    pub key: OpaqueKey,
    pub key_status: IdentityKeyStatus,
    pub security_level: SecurityLevel,
    pub purpose: Purpose,
}

#[ferment_macro::export]
impl KeyInfo {

    pub fn kind(&self) -> KeyKind {
        self.key.kind()
    }
    pub fn registered(key: OpaqueKey, security_level: SecurityLevel, purpose: Purpose) -> KeyInfo {
        Self {
            key,
            key_status: IdentityKeyStatus::Registered,
            security_level,
            purpose,
        }
    }
    pub fn registering(key: OpaqueKey, security_level: SecurityLevel, purpose: Purpose) -> KeyInfo {
        Self {
            key,
            key_status: IdentityKeyStatus::Registering,
            security_level,
            purpose,
        }
    }

    pub fn has_key_with_public_key_data(&self, data: &[u8]) -> bool {
        self.key.public_key_data().eq(data)
    }
}