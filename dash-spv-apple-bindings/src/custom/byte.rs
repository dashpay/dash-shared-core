#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(byte::Error)]
pub enum byte_Error_FFI {
    Incomplete,
    BadOffset(usize),
    BadInput { err: *mut std::os::raw::c_char },
}

impl ferment::FFIConversionFrom<byte::Error> for byte_Error_FFI {
    unsafe fn ffi_from_const(ffi: *const byte_Error_FFI) -> byte::Error {
        let ffi_ref = &*ffi;
        match ffi_ref {
            byte_Error_FFI::Incomplete =>
                byte::Error::Incomplete,
            byte_Error_FFI::BadOffset(o_0) => byte::Error::BadOffset(*o_0),
            byte_Error_FFI::BadInput { err} =>
                byte::Error::BadInput { err: ferment::FFIConversionFrom::ffi_from_const(*err) },
        }
    }
}
impl ferment::FFIConversionTo<byte::Error> for byte_Error_FFI {
    unsafe fn ffi_to_const(obj: byte::Error) -> *const byte_Error_FFI {
        ferment::boxed(match obj {
            byte::Error::Incomplete => byte_Error_FFI::Incomplete,
            byte::Error::BadOffset(o_0) => byte_Error_FFI::BadOffset(o_0),
            byte::Error::BadInput { err } => byte_Error_FFI::BadInput { err: ferment::FFIConversionTo::ffi_to(err) },
        })
    }
}
impl ferment::FFIConversionDestroy<byte::Error> for byte_Error_FFI {
    unsafe fn destroy(ffi: *mut byte_Error_FFI) {
        ferment::unbox_any(ffi);
    }
}
impl Drop for byte_Error_FFI {
    fn drop(&mut self) {
        unsafe {
            match self {
                byte_Error_FFI::BadInput { err } =>
                    <std::os::raw::c_char as ferment::FFIConversionDestroy<&str>>::destroy(*err),
                _ => {},
            }
        }
    }
}