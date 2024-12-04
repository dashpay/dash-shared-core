#![allow(dead_code)]
#![allow(unused_variables)]

mod address;
// mod chain;
// mod common;
// mod crypto;
#[cfg(not(test))]
mod fermented;
#[cfg(not(test))]
mod fermented_extended;

// mod keys;
// mod masternode;
// mod tx;

#[cfg(test)]
mod tests;
mod ffi_core_provider;
// mod ffi;
// mod types;
pub mod custom;
mod bindings;

pub extern crate dash_spv_masternode_processor;
pub extern crate dash_spv_platform;
pub extern crate merk;
pub extern crate bitcoin_hashes as hashes;

use std::sync::Arc;
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache};
use dash_spv_platform::PlatformSDK;
use crate::ffi_core_provider::FFICoreProvider;

// #[macro_export]
// macro_rules! impl_ffi_bytearray {
//     ($var_type: ident) => {
//         impl From<$var_type> for crate::ffi::common::ByteArray {
//             fn from(value: $var_type) -> Self {
//                 let vec = value.0.to_vec();
//                 vec.into()
//             }
//         }
//         impl From<Option<$var_type>> for crate::ffi::common::ByteArray {
//             fn from(value: Option<$var_type>) -> Self {
//                 if let Some(v) = value {
//                     v.into()
//                 } else {
//                     crate::ffi::common::ByteArray::default()
//                 }
//             }
//         }
//     }
// }
//
// impl_ffi_bytearray!(UInt128);
// impl_ffi_bytearray!(UInt160);
// impl_ffi_bytearray!(UInt256);
// impl_ffi_bytearray!(UInt384);
// impl_ffi_bytearray!(UInt512);
// impl_ffi_bytearray!(UInt768);

// use test_mod::Clone;

#[derive(Debug)]
#[ferment_macro::opaque]
pub struct DashSPVCore {
    pub processor: Arc<MasternodeProcessor>,
    pub cache: Arc<MasternodeProcessorCache>,
    pub platform: *mut PlatformSDK,
    context: *const std::os::raw::c_void,
}

#[ferment_macro::export]
impl DashSPVCore {
    pub fn new(
        core_provider: *mut FFICoreProvider,
        // cache: *mut MasternodeProcessorCache,
        platform: *mut PlatformSDK,
        context: *const std::os::raw::c_void) -> Self {
        // let cache = unsafe { Arc::from_raw(cache) };
        let provider = unsafe { Arc::from_raw(core_provider) };
        // let provider_arc = Arc::new(provider);
        // let cache = unsafe { Box::from_raw(cache) };
        let cache = Arc::new(MasternodeProcessorCache::default());
        Self {
            processor: Arc::new(MasternodeProcessor::new(provider, Arc::clone(&cache))),
            cache,
            platform,
            context,
        }
    }

    pub fn cache(&self) -> Arc<MasternodeProcessorCache> {
        Arc::clone(&self.cache)
    }
    pub fn processor(&self) -> Arc<MasternodeProcessor> {
        Arc::clone(&self.processor)
    }
}

