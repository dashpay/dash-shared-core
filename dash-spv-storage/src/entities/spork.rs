use crate::entities::spork_hash::SporkHashEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct SporkEntity {
    pub identifier: i32,
    pub signature: Option<Vec<u8>>,
    pub time_signed: i64,
    pub value: i64,

    pub spork_hash: Option<Box<SporkHashEntity>>,
}
