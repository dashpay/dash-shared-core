use crate::entities::governance_object_hash::GovernanceObjectHashEntity;
use crate::entities::governance_vote_hash::GovernanceVoteHashEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct GovernanceObjectEntity {
    pub amount: i64,
    pub collateral_hash: Vec<u8>,
    pub end_epoch: i64,
    pub identifier: String,
    pub parent_hash: Vec<u8>,
    pub payment_address: String,
    pub revision: i32,
    pub signature: Vec<u8>,
    pub start_epoch: i64,
    pub timestamp: i64,
    pub total_votes_count: i64,
    pub r#type: i32,
    pub url: String,
    // Relationships
    pub governance_object_hash: Option<GovernanceObjectHashEntity>,
    pub vote_hashes: Vec<GovernanceVoteHashEntity>,
}
