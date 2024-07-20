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
mod custom_conversions;

pub extern crate dash_spv_masternode_processor;
pub extern crate merk;

use dash_spv_masternode_processor::crypto::byte_util::{UInt128, UInt160, UInt256, UInt384, UInt512, UInt768};
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache};

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


#[derive(Debug)]
#[ferment_macro::opaque]
pub struct DashSharedCore {
    pub processor: *mut MasternodeProcessor,
    pub cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
}

//
// /// Initialize opaque context
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn register_core(
//     context: *const std::os::raw::c_void
//
// ) -> *mut DashSharedCore {
//     println!("register_core: {:?}", context);
//     ferment_interfaces::boxed(cache)
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn unregister_core(core: *mut DashSharedCore) {
//     println!("unregister_core: {:?}", core);
//     let unboxed = ferment_interfaces::unbox_any(core);
// }
