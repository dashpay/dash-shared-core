pub extern crate bitcoin_hashes as hashes;
pub extern crate secp256k1;
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
pub mod llmq;
pub mod network;
pub mod tx;
pub mod util;

#[cfg(feature = "std")]
use std::io;
#[cfg(not(feature = "std"))]
use core2::io;
