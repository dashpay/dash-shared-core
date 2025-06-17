use crate::entities::chain::ChainEntity;
use crate::entities::chain_lock::ChainLockEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct MerkleBlockEntity {
    pub block_hash: Vec<u8>,
    pub chain_work: Vec<u8>,
    pub flags: Vec<u8>,
    pub hashes: Vec<u8>,
    pub height: i32,
    pub merkle_root: Vec<u8>,
    pub nonce: i32,
    pub prev_block: Vec<u8>,
    pub target: i32,
    pub timestamp: Option<u64>,
    pub total_transactions: i32,
    pub version: i32,
    pub chain: Option<Box<ChainEntity>>,
    pub chain_lock: Option<Box<ChainLockEntity>>,
}
