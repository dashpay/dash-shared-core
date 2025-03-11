extern crate simplelog;

pub mod bip;
pub mod blockdata;
#[macro_use]
pub mod consensus;
pub mod crypto;
pub mod derivation;
pub(crate) mod hash_types;
#[macro_use]
pub(crate) mod internal_macros;
pub mod keys;
// pub mod llmq;
pub mod network;
pub mod tx;
pub mod util;

use crate::network::DevnetType;
use crate::util::data_append::DataAppend;

#[ferment_macro::export]
pub fn x11(data: &[u8]) -> [u8; 32] {
    rs_x11_hash::get_x11_hash(data)
}

#[ferment_macro::export]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}
#[ferment_macro::export]
pub fn devnet_genesis_coinbase_message(devnet_type: DevnetType, protocol_version: u32) -> Vec<u8> {
    Vec::<u8>::devnet_genesis_coinbase_message(devnet_type, protocol_version)
}
