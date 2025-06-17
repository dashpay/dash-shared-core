use crate::entities::chain::ChainEntity;
use crate::entities::spork::SporkEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct SporkHashEntity {
    pub spork_hash: Option<Vec<u8>>,

    pub chain: Option<Box<ChainEntity>>,
    pub spork: Option<Box<SporkEntity>>,
}
