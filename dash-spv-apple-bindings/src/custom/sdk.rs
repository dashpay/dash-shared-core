use ferment_interfaces::{boxed, FFIConversionFrom, FFIConversionTo, unbox_any};

#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(dash_sdk::error::Error)]
pub struct dash_sdk_error_ErrorFFI {
    raw: *mut dash_sdk::error::Error,
}
impl FFIConversionFrom<dash_sdk::error::Error> for dash_sdk_error_ErrorFFI {
    unsafe fn ffi_from_const(ffi: *const Self) -> dash_sdk::error::Error {
        FFIConversionFrom::ffi_from(ffi.cast_mut())
    }

    unsafe fn ffi_from(ffi: *mut Self) -> dash_sdk::error::Error {
        *unbox_any((&*ffi).raw)
    }
}
impl FFIConversionTo<dash_sdk::error::Error> for dash_sdk_error_ErrorFFI {
    unsafe fn ffi_to_const(obj: dash_sdk::error::Error) -> *const Self {
        boxed(dash_sdk_error_ErrorFFI { raw: boxed(obj) })
    }
}

impl Drop for dash_sdk_error_ErrorFFI {
    fn drop(&mut self) {
        unsafe {
            unbox_any(self.raw);
        }
    }
}
