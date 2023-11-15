#![allow(unused_variables)]
#![allow(dead_code)]

use std::ffi::CString;
use std::os::raw::c_char;
use crate::types::opaque_key::{OpaqueKey, OpaqueKeys, OpaqueSerializedKeys};

/// # Safety
pub unsafe fn unbox_any<T: ?Sized>(any: *mut T) -> Box<T> {
    Box::from_raw(any)
}

/// # Safety
pub unsafe fn unbox_vec<T>(vec: Vec<*mut T>) -> Vec<Box<T>> {
    vec.iter().map(|&x| unbox_any(x)).collect()
}

/// # Safety
pub unsafe fn unbox_vec_ptr<T>(ptr: *mut T, count: usize) -> Vec<T> {
    Vec::from_raw_parts(ptr, count, count)
}

pub unsafe fn unbox_any_vec<T>(vec: Vec<*mut T>) {
    for &x in vec.iter() {
        unbox_any(x);
    }
}

pub unsafe fn unbox_any_vec_ptr<T>(ptr: *mut *mut T, count: usize) {
    unbox_any_vec(unbox_vec_ptr(ptr, count));
}

/// # Safety
pub unsafe fn unbox_string(data: *mut c_char) {
    let _ = CString::from_raw(data);
}

pub unsafe fn unbox_opaque_key(data: *mut OpaqueKey) {
    let k = unbox_any(data);
    match *k {
        OpaqueKey::ECDSA(key) => { let _ = unbox_any(key); },
        OpaqueKey::BLSLegacy(key) |
        OpaqueKey::BLSBasic(key) => { let _ = unbox_any(key); },
        OpaqueKey::ED25519(key) => { let _ = unbox_any(key); },
    };
}

/// # Safety
pub unsafe fn unbox_opaque_keys(data: *mut OpaqueKeys) {
    let res = unbox_any(data);
    let keys = unbox_vec_ptr(res.keys, res.len);
    for &x in keys.iter() {
        unbox_opaque_key(x);
    }
}

/// # Safety
pub unsafe fn unbox_opaque_serialized_keys(data: *mut OpaqueSerializedKeys) {
    let res = unbox_any(data);
    let keys = unbox_vec_ptr(res.keys, res.len);
    for &x in keys.iter() {
        unbox_string(x)
    }
}
