use crate::entities::chain::ChainEntity;
use crate::entities::merkle_block::MerkleBlockEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ChainLockEntity {
    pub signature: Vec<u8>,
    pub valid_signature: bool,
    // Relationships
    pub chain_if_last_chain_lock: Option<Box<ChainEntity>>,
    pub merkle_block: Option<MerkleBlockEntity>,
}
