#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(anyhow::Error)]
pub struct anyhow_Error(*mut std::os::raw::c_void);
impl ferment::FFIConversionFrom<anyhow::Error> for anyhow_Error {
    unsafe fn ffi_from_const(ffi: *const Self) -> anyhow::Error {
        *ferment::unbox_any((&*ffi).0 as *mut anyhow::Error)
    }
}
impl ferment::FFIConversionTo<anyhow::Error> for anyhow_Error {
    unsafe fn ffi_to_const(obj: anyhow::Error) -> *const Self {
        ferment::boxed(anyhow_Error(ferment::boxed(obj) as *mut std::os::raw::c_void))
    }
}

impl Drop for anyhow_Error {
    fn drop(&mut self) {
        unsafe { ferment::unbox_any(self.0); }
    }
}
