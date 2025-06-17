use crate::entities::identity::IdentityEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct IdentityUsernameEntity {
    pub domain: String,
    pub salt: [u8; 32],
    pub status: u8,
    pub string_value: String,
    // Relationships
    pub identity: Option<Box<IdentityEntity>>,
    pub identity_for_dashpay: Option<Box<IdentityEntity>>,
}
