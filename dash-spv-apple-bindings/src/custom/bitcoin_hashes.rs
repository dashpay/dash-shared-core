#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(hashes::hex::Error)]
pub enum hashes_hex_Error_FFI {
    InvalidChar(u8),
    OddLengthString(usize),
    InvalidLength(usize, usize),
}
// use

impl ferment::FFIConversionFrom<hashes::hex::Error> for hashes_hex_Error_FFI {
    unsafe fn ffi_from_const(ffi: *const hashes_hex_Error_FFI) -> hashes::hex::Error {
        let ffi_ref = &*ffi;
        match ffi_ref {
            hashes_hex_Error_FFI::InvalidChar(o_0) => hashes::hex::Error::InvalidChar(*o_0),
            hashes_hex_Error_FFI::OddLengthString(o_0) => hashes::hex::Error::OddLengthString(*o_0),
            hashes_hex_Error_FFI::InvalidLength(o_0, o_1) => hashes::hex::Error::InvalidLength(*o_0, *o_1),
        }
    }
}
impl ferment::FFIConversionTo<hashes::hex::Error> for hashes_hex_Error_FFI {
    unsafe fn ffi_to_const(obj: hashes::hex::Error) -> *const hashes_hex_Error_FFI {
        ferment::boxed(match obj {
            hashes::hex::Error::InvalidChar(o_0) => hashes_hex_Error_FFI::InvalidChar(o_0),
            hashes::hex::Error::OddLengthString(o_0) => hashes_hex_Error_FFI::OddLengthString(o_0),
            hashes::hex::Error::InvalidLength(o_0, o_1) => hashes_hex_Error_FFI::InvalidLength(o_0, o_1),
        })
    }
}
impl ferment::FFIConversionDestroy<hashes::hex::Error> for hashes_hex_Error_FFI {
    unsafe fn destroy(ffi: *mut hashes_hex_Error_FFI) {
        ferment::unbox_any(ffi);
    }
}