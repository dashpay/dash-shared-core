use crate::entities::chain::ChainEntity;
use crate::entities::governance_object::GovernanceObjectEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct GovernanceObjectHashEntity {
    pub governance_object_hash: Vec<u8>,
    pub timestamp: i64,
    pub chain: Option<Box<ChainEntity>>,
    pub governance_object: Option<Box<GovernanceObjectEntity>>,
}
