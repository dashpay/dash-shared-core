use crate::entities::chain::ChainEntity;
use crate::entities::governance_object::GovernanceObjectEntity;
use crate::entities::governance_vote::GovernanceVoteEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct GovernanceVoteHashEntity {
    pub governance_vote_hash: Vec<u8>,
    pub timestamp: i64,
    pub chain: Option<Box<ChainEntity>>,
    pub governance_object: Option<Box<GovernanceObjectEntity>>,
    pub governance_vote: Option<Box<GovernanceVoteEntity>>,
}
