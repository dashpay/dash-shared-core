use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::keys::OpaqueKey;
use dpp::identity::identity_public_key::purpose::Purpose;
use dpp::identity::identity_public_key::security_level::SecurityLevel;
use crate::identity::key_status::IdentityKeyStatus;

#[ferment_macro::export]
#[derive(Clone)]
pub struct KeyInfo {
    pub key: OpaqueKey,
    pub key_type: KeyKind,
    pub key_status: IdentityKeyStatus,
    pub security_level: SecurityLevel,
    pub purpose: Purpose,
}

impl KeyInfo {
    pub fn registered(key: OpaqueKey, key_type: KeyKind, security_level: SecurityLevel, purpose: Purpose) -> Self {
        Self {
            key,
            key_type,
            key_status: IdentityKeyStatus::Registered,
            security_level,
            purpose,
        }
    }
}