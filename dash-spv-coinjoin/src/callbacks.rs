use std::ffi::c_void;
use crate::models::InputValue;

pub type GetInputValueByPrevoutHash = unsafe extern "C" fn(
    prevout_hash: *mut [u8; 32],
    context: *const c_void,
) -> *mut InputValue;
