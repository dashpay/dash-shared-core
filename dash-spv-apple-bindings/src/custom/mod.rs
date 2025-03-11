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
macro_rules! impl_hash_ferment {
    ($hashtype:path, $ffitype:ident) => {
        impl ferment::FFIConversionFrom<$hashtype> for $ffitype {
            unsafe fn ffi_from_const(ffi: *const Self) -> $hashtype {
                <$hashtype>::from_slice(&*(&*ffi).0).expect("Invalid hash type")
            }
        }
        impl ferment::FFIConversionTo<$hashtype> for $ffitype {
            unsafe fn ffi_to_const(obj: $hashtype) -> *const Self {
                ferment::boxed(Self(ferment::boxed(obj.into())))
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
