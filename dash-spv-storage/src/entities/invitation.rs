use crate::entities::chain::ChainEntity;
use crate::entities::identity::IdentityEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct InvitationEntity {
    pub link: String,
    pub name: Option<String>,
    pub tag: Option<String>,
    // Relationships
    pub identity: Option<Box<IdentityEntity>>,
    pub chain: Option<ChainEntity>,

}