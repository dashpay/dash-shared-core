use std::os::raw::{c_char, c_void};
use std::ptr::null_mut;
use dash_spv_masternode_processor::keys::{BLSKey, ECDSAKey, ED25519Key, Key, KeyKind};
use ferment::boxed;

pub trait AsOpaqueKey {
    fn to_opaque_ptr(self) -> *mut OpaqueKey;
}

#[repr(C)]
#[derive(Clone, Debug)]
pub enum OpaqueKey {
    ECDSA(*mut ECDSAKey),
    BLSLegacy(*mut BLSKey),
    BLSBasic(*mut BLSKey),
    ED25519(*mut ED25519Key),
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpaqueKeys {
    pub keys: *mut *mut OpaqueKey,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpaqueSerializedKeys {
    pub count: usize,
    pub keys: *mut *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KeyWithUniqueId {
    pub key_type: KeyKind,
    pub unique_id: u64,
    // ECDSAKey, ED25519Key or BLSKey
    pub ptr: *mut c_void,
}

impl AsOpaqueKey for ECDSAKey {
    fn to_opaque_ptr(self) -> *mut OpaqueKey {
        boxed(OpaqueKey::ECDSA(boxed(self)))
    }
}

impl AsOpaqueKey for BLSKey {
    fn to_opaque_ptr(self) -> *mut OpaqueKey {
        boxed(if self.use_legacy {
            OpaqueKey::BLSLegacy(boxed(self))
        } else {
            OpaqueKey::BLSBasic(boxed(self))
        })
    }
}

impl AsOpaqueKey for ED25519Key {
    fn to_opaque_ptr(self) -> *mut OpaqueKey {
        boxed(OpaqueKey::ED25519(boxed(self)))
    }
}

impl AsOpaqueKey for Key {
    fn to_opaque_ptr(self) -> *mut OpaqueKey {
        match self {
            Key::ECDSA(key) => key.to_opaque_ptr(),
            Key::BLS(key) => key.to_opaque_ptr(),
            Key::ED25519(key) => key.to_opaque_ptr(),
        }
    }
}

impl<K, E: std::error::Error> AsOpaqueKey for Result<K, E> where K: AsOpaqueKey {
    fn to_opaque_ptr(self) -> *mut OpaqueKey {
        self.map_or(null_mut(), |key| key.to_opaque_ptr())
    }
}


