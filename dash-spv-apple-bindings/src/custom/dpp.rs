#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(dpp::identity::core_script::CoreScript)]
pub struct CoreScriptFFI {
    pub raw: *mut dpp::identity::core_script::CoreScript,
}
impl ferment::FFIConversionFrom<dpp::identity::core_script::CoreScript> for CoreScriptFFI {
    unsafe fn ffi_from_const(ffi: *const Self) -> dpp::identity::core_script::CoreScript {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment::FFIConversionTo<dpp::identity::core_script::CoreScript> for CoreScriptFFI {
    unsafe fn ffi_to_const(obj: dpp::identity::core_script::CoreScript) -> *const Self {
        ferment::boxed(Self { raw: ferment::boxed(obj) })
    }
}

impl Drop for CoreScriptFFI {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.raw);
        }
    }
}
