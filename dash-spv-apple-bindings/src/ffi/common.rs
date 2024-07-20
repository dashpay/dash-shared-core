use std::{mem, ptr};
use dash_spv_masternode_processor::util::sec_vec::SecVec;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ByteArray {
    pub ptr: *const u8,
    pub len: usize,
}

impl Default for ByteArray {
    fn default() -> Self {
        ByteArray { ptr: ptr::null(), len: 0 }
    }
}

impl From<blake3::Hash> for ByteArray {
    fn from(value: blake3::Hash) -> Self {
        let bytes: [u8; 32] = value.into();
        let vec = bytes.to_vec();
        vec.into()
    }
}

impl From<[u8; 32]> for ByteArray {
    fn from(value: [u8; 32]) -> Self {
        let vec = value.to_vec();
        vec.into()
    }
}


impl From<[u8; 48]> for ByteArray {
    fn from(value: [u8; 48]) -> Self {
        let vec = value.to_vec();
        vec.into()
    }
}


impl From<[u8; 65]> for ByteArray {
    fn from(value: [u8; 65]) -> Self {
        let vec = value.to_vec();
        vec.into()
    }
}

impl<T> From<Result<[u8; 48], T>> for ByteArray {
    fn from(value: Result<[u8; 48], T>) -> Self {
        if let Ok(v) = value {
            v.into()
        } else {
            ByteArray::default()
        }
    }
}

impl<T> From<Result<[u8; 65], T>> for ByteArray {
    fn from(value: Result<[u8; 65], T>) -> Self {
        if let Ok(v) = value {
            v.into()
        } else {
            ByteArray::default()
        }
    }
}

impl From<Option<[u8; 65]>> for ByteArray {
    fn from(value: Option<[u8; 65]>) -> Self {
        if let Some(v) = value {
            v.into()
        } else {
            ByteArray::default()
        }
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(value: Vec<u8>) -> Self {
        let ptr = value.as_ptr();
        let len = value.len();
        mem::forget(value);
        ByteArray { ptr, len }
    }
}

impl<T> From<Result<Vec<u8>, T>> for ByteArray {
    fn from(value: Result<Vec<u8>, T>) -> Self {
        value.map_or(ByteArray::default(), Vec::into)
    }
}

impl From<Option<Vec<u8>>> for ByteArray {
    fn from(value: Option<Vec<u8>>) -> Self {
        value.map_or(ByteArray::default(), Vec::into)
    }
}

impl<T> From<Result<SecVec, T>> for ByteArray {
    fn from(value: Result<SecVec, T>) -> Self {
        value.map_or(ByteArray::default(), |vec| {
            let ptr = vec.as_ptr();
            let len = vec.len();
            mem::forget(vec);
            ByteArray { ptr, len }
        })
    }
}

impl From<Option<SecVec>> for ByteArray {
    fn from(value: Option<SecVec>) -> Self {
        match value {
            Some(vec) => {
                let ptr = vec.as_ptr();
                let len = vec.len();
                mem::forget(vec);
                ByteArray { ptr, len }
            }
            None => ByteArray::default(),
        }
    }
}

