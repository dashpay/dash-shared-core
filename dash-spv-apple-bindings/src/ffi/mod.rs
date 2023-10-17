use std::os::raw::c_ulong;
use dash_spv_masternode_processor::chain::derivation::{IIndexPath, IndexPath};
use dash_spv_masternode_processor::crypto::UInt256;
use crate::types::opaque_key::{OpaqueKey, OpaqueKeys, OpaqueSerializedKeys};

pub mod callbacks;
pub mod common;
pub mod from;
pub mod to;


#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IndexPathData {
    pub indexes: *const c_ulong,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DerivationPathData {
    pub indexes: *const [u8; 32],
    pub hardened: *const u8,
    pub len: usize,
}


impl From<IndexPathData> for IndexPath<u32> {
    fn from(value: IndexPathData) -> Self {
        let indexes_slice = unsafe { std::slice::from_raw_parts(value.indexes, value.len) };
        IndexPath::new(indexes_slice.iter().map(|&index| index as u32).collect())
    }
}

pub unsafe fn decode_derivation_path(indexes: *const u8, hardened: *const bool, count: usize) -> IndexPath<UInt256> {
    let hashes_len = count * 32;
    let hashes = unsafe { std::slice::from_raw_parts(indexes, hashes_len) };
    let hardened = unsafe { std::slice::from_raw_parts(hardened, count) };
    let indexes = (0..hashes_len)
        .into_iter()
        .step_by(32)
        .map(|pos| UInt256::from(&hashes[pos..pos+32]))
        .collect::<Vec<_>>();
    IndexPath::new_hardened(indexes, hardened.to_vec())

}

pub unsafe fn unbox_opaque_key(data: *mut OpaqueKey) {
    let k = ferment_interfaces::unbox_any(data);
    match *k {
        OpaqueKey::ECDSA(key) => { let _ = ferment_interfaces::unbox_any(key); },
        OpaqueKey::BLSLegacy(key) |
        OpaqueKey::BLSBasic(key) => { let _ = ferment_interfaces::unbox_any(key); },
        OpaqueKey::ED25519(key) => { let _ = ferment_interfaces::unbox_any(key); },
    };
}

/// # Safety
pub unsafe fn unbox_opaque_keys(data: *mut OpaqueKeys) {
    let res = ferment_interfaces::unbox_any(data);
    let keys = ferment_interfaces::unbox_vec_ptr(res.keys, res.len);
    for &x in keys.iter() {
        unbox_opaque_key(x);
    }
}

/// # Safety
pub unsafe fn unbox_opaque_serialized_keys(data: *mut OpaqueSerializedKeys) {
    let res = ferment_interfaces::unbox_any(data);
    let keys = ferment_interfaces::unbox_vec_ptr(res.keys, res.count);
    for &x in keys.iter() {
        ferment_interfaces::unbox_string(x)
    }
}


