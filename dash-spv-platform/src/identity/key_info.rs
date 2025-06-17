use dash_spv_crypto::keys::{IKey, OpaqueKey};
use dpp::identity::identity_public_key::purpose::Purpose;
use dpp::identity::identity_public_key::security_level::SecurityLevel;
use dash_spv_crypto::keys::key::KeyKind;
use crate::identity::key_status::IdentityKeyStatus;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct KeyInfo {
    pub key: OpaqueKey,
    pub key_status: IdentityKeyStatus,
    pub security_level: SecurityLevel,
    pub purpose: Purpose,
}

#[ferment_macro::export]
impl KeyInfo {

    pub fn of_purpose(&self, purpose: Purpose) -> bool {
        purpose.eq(&self.purpose)
    }
    pub fn of_security_level(&self, security_level: SecurityLevel) -> bool {
        security_level.eq(&self.security_level)
    }
    pub fn of_key_status(&self, key_status: IdentityKeyStatus) -> bool {
        key_status.eq(&self.key_status)
    }

    pub fn is_ecdsa(&self) -> bool {
        self.kind() == KeyKind::ECDSA
    }

    pub fn kind(&self) -> KeyKind {
        self.key.kind()
    }
    pub fn kind_index(&self) -> i16 {
        i16::from(self.key.kind())
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