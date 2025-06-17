use crate::entities::chain::ChainEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct PeerEntity {
    pub address: i32,
    pub last_requested_governance_sync: Option<u64>,
    pub last_requested_masternode_list: Option<u64>,
    pub low_preference_till: Option<u64>,
    pub misbehavin: i16,
    pub port: i16,
    pub priority: i32,
    pub services: i64,
    pub timestamp: Option<u64>,
    pub chain: Option<Box<ChainEntity>>,
}
