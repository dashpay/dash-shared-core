#[allow(non_camel_case_types)]
#[ferment_macro::register(grovedb_version::version::GroveVersion)]
pub struct grovedb_version_GroveVersion {
    raw: *mut grovedb_version::version::GroveVersion,
}

impl ferment_interfaces::FFIConversionFrom<grovedb_version::version::GroveVersion> for grovedb_version_GroveVersion {
    unsafe fn ffi_from_const(ffi: *const Self) -> grovedb_version::version::GroveVersion {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment_interfaces::FFIConversionTo<grovedb_version::version::GroveVersion> for grovedb_version_GroveVersion {
    unsafe fn ffi_to_const(obj: grovedb_version::version::GroveVersion) -> *const Self {
        ferment_interfaces::boxed(Self { raw: ferment_interfaces::boxed(obj) })
    }
}

impl Drop for grovedb_version_GroveVersion {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any(self.raw);
        }
    }
}
