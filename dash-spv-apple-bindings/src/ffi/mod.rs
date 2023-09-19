use crate::types::opaque_key::{OpaqueKey, OpaqueKeys, OpaqueSerializedKeys};

pub mod callbacks;
pub mod from;
pub mod to;

pub unsafe fn unbox_opaque_key(data: *mut OpaqueKey) {
    let k = rs_ffi_interfaces::unbox_any(data);
    match *k {
        OpaqueKey::ECDSA(key) => { let _ = rs_ffi_interfaces::unbox_any(key); },
        OpaqueKey::BLSLegacy(key) |
        OpaqueKey::BLSBasic(key) => { let _ = rs_ffi_interfaces::unbox_any(key); },
        OpaqueKey::ED25519(key) => { let _ = rs_ffi_interfaces::unbox_any(key); },
    };
}

/// # Safety
pub unsafe fn unbox_opaque_keys(data: *mut OpaqueKeys) {
    let res = rs_ffi_interfaces::unbox_any(data);
    let keys = rs_ffi_interfaces::unbox_vec_ptr(res.keys, res.len);
    for &x in keys.iter() {
        unbox_opaque_key(x);
    }
}

/// # Safety
pub unsafe fn unbox_opaque_serialized_keys(data: *mut OpaqueSerializedKeys) {
    let res = rs_ffi_interfaces::unbox_any(data);
    let keys = rs_ffi_interfaces::unbox_vec_ptr(res.keys, res.count);
    for &x in keys.iter() {
        rs_ffi_interfaces::unbox_string(x)
    }
}


