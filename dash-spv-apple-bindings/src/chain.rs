use std::ffi::CStr;
use std::os::raw::c_char;
use dash_spv_masternode_processor::chain::common::{ChainType, DevnetType};
use crate::ffi::common::ByteArray;
use dash_spv_masternode_processor::util::data_append::DataAppend;

/// # Safety
#[no_mangle]
pub extern "C" fn chain_type_index(chain_type: ChainType) -> i16 {
    chain_type.into()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_type_from_index(index: i16) -> ChainType {
    ChainType::from(index)
}

#[no_mangle]
pub extern "C" fn chain_devnet_from_identifier(identifier: *const c_char) -> DevnetType {
    let c_str = unsafe { CStr::from_ptr(identifier) };
    DevnetType::from(c_str.to_str().unwrap())
}

// /// # Safety
// #[no_mangle]
// pub extern "C" fn chain_type_for_devnet_type(devnet_type: DevnetType) -> ChainType {
//     ChainType::from(devnet_type)
// }
//
// /// # Safety
// #[no_mangle]
// pub extern "C" fn chain_type_is_devnet_any(chain_type: ChainType) -> bool {
//     chain_type.is_devnet_any()
// }

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn devnet_identifier_for_chain_type(chain_type: ChainType) -> *mut c_char {
    ferment_interfaces::FFIConversionTo::ffi_to_opt(chain_type.devnet_identifier())
}

/// # Safety
#[no_mangle]
pub extern "C" fn devnet_version_for_chain_type(chain_type: ChainType) -> i16 {
    chain_type.devnet_version().unwrap_or(i16::MAX)
}

/// # Safety
#[no_mangle]
pub extern "C" fn devnet_type_for_chain_type(chain_type: ChainType) -> DevnetType {
    DevnetType::from(chain_type)
}

/// # Safety
#[no_mangle]
pub extern "C" fn devnet_genesis_coinbase_message(devnet_type: DevnetType, protocol_version: u32) -> ByteArray {
    Vec::<u8>::devnet_genesis_coinbase_message(devnet_type, protocol_version).into()
}
