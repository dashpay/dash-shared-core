#![allow(dead_code)]
#![allow(unused_variables)]

mod address;
mod chain;
mod common;
mod crypto;
mod fermented;
mod keys;
mod masternode;
mod tx;

#[cfg(test)]
mod tests;
mod ffi_core_provider;
mod ffi;
mod types;

pub extern crate dash_spv_masternode_processor;
pub extern crate merk;

use dash_spv_masternode_processor::crypto::byte_util::{UInt128, UInt160, UInt256, UInt384, UInt512, UInt768};

#[macro_export]
macro_rules! impl_ffi_bytearray {
    ($var_type: ident) => {
        impl From<$var_type> for crate::ffi::common::ByteArray {
            fn from(value: $var_type) -> Self {
                let vec = value.0.to_vec();
                vec.into()
            }
        }
        impl From<Option<$var_type>> for crate::ffi::common::ByteArray {
            fn from(value: Option<$var_type>) -> Self {
                if let Some(v) = value {
                    v.into()
                } else {
                    crate::ffi::common::ByteArray::default()
                }
            }
        }
    }
}

impl_ffi_bytearray!(UInt128);
impl_ffi_bytearray!(UInt160);
impl_ffi_bytearray!(UInt256);
impl_ffi_bytearray!(UInt384);
impl_ffi_bytearray!(UInt512);
impl_ffi_bytearray!(UInt768);
