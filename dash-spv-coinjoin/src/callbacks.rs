use std::ffi::c_void;
use dash_spv_masternode_processor::types;

use crate::models::InputValue;

pub type GetInputValueByPrevoutHash = unsafe extern "C" fn(
    prevout_hash: *mut [u8; 32],
    context: *const c_void,
) -> *mut InputValue;

pub type HasChainLock = unsafe extern "C" fn(
    block: types::Block,
    context: *const c_void,
) -> bool;
