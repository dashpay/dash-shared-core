use ::dashcore::hashes::Hash;

pub mod anyhow;
pub mod byte;
pub mod dashcore;
pub mod dpp;
pub mod grovedb_version;
pub mod jsonschema;
pub mod regex;
pub mod serde_json;
pub mod std;
pub mod sdk;
pub mod versioned_feature_core;

#[macro_export]
macro_rules! mangle_path {
    // Base case: handle a single segment
    ($segment:ident, $suffix:literal) => {
        concat!(stringify!($segment), $suffix)
    };
    // Recursive case: replace `::` with `_`
    ($first:ident :: $($rest:tt)*, $suffix:literal) => {
        concat!(stringify!($first), "_", mangle_path!($($rest)*, $suffix))
    };
}

#[macro_export]
macro_rules! impl_cloneable_ferment {
    ($ty:path, $ffitype:ident) => {
        impl ferment::FFIConversionFrom<$ty> for $ffitype {
            unsafe fn ffi_from_const(ffi: *const Self) -> $ty {
                let ffi = &*ffi;
                let raw = &*ffi.0;
                raw.clone()
            }
        }
        impl ferment::FFIConversionTo<$ty> for $ffitype {
            unsafe fn ffi_to_const(obj: $ty) -> *const Self {
                ferment::boxed(Self(ferment::boxed(obj)))
            }
        }
        impl Drop for $ffitype {
            fn drop(&mut self) {
                unsafe {
                    ferment::unbox_any(self.0);
                }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_hash_ferment {
    ($hashtype:path, $ffitype:ident) => {
        impl ferment::FFIConversionFrom<$hashtype> for $ffitype {
            unsafe fn ffi_from_const(ffi: *const Self) -> $hashtype {
                <$hashtype>::from_byte_array(ferment::FFIConversionFrom::ffi_from((&*ffi).0))
            }
        }
        impl ferment::FFIConversionTo<$hashtype> for $ffitype {
            unsafe fn ffi_to_const(obj: $hashtype) -> *const Self {
                ferment::boxed(Self(ferment::FFIConversionTo::ffi_to(obj.to_byte_array())))
            }
        }
        impl Drop for $ffitype {
            fn drop(&mut self) {
                unsafe { ferment::unbox_any(self.0); }
            }
        }
    };
}

pub unsafe fn to_ffi_bytes<T, F, B>(ptr: *mut F) -> *mut B
where T: Hash,
      F: ferment::FFIConversionFrom<T>,
      B: ferment::FFIConversionTo<T::Bytes> {
    let hash = ferment::FFIConversionFrom::<T>::ffi_from(ptr);
    let byte_arr = T::to_byte_array(hash);
    let ptr = ferment::FFIConversionTo::ffi_to(byte_arr);
    ptr
}

pub unsafe fn to_ffi_hash<T, F, B>(ffi_bytes: *mut B) -> *mut F
where T: Hash,
      F: ferment::FFIConversionTo<T>,
      B: ferment::FFIConversionFrom<T::Bytes> {
    let byte_arr = ferment::FFIConversionFrom::ffi_from(ffi_bytes);
    let hash = T::from_byte_array(byte_arr);
    let ptr = ferment::FFIConversionTo::ffi_to(hash);
    ptr
}
