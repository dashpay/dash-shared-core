use crate::entities::governance_vote_hash::GovernanceVoteHashEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct GovernanceVoteEntity {
    pub masternode_hash: Vec<u8>,
    pub masternode_index: i32,
    pub outcome: i32,
    pub parent_hash: Vec<u8>,
    pub signal: i32,
    pub signature: Vec<u8>,
    pub timestamp_created: i64,
    pub governance_vote_hash: Option<Box<GovernanceVoteHashEntity>>,
}
