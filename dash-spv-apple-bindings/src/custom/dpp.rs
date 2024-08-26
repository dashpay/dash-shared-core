#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(dpp::identity::core_script::CoreScript)]
pub struct CoreScriptFFI {
    pub raw: *mut dpp::identity::core_script::CoreScript,
}
impl ferment_interfaces::FFIConversionFrom<dpp::identity::core_script::CoreScript> for CoreScriptFFI {
    unsafe fn ffi_from_const(ffi: *const Self) -> dpp::identity::core_script::CoreScript {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment_interfaces::FFIConversionTo<dpp::identity::core_script::CoreScript> for CoreScriptFFI {
    unsafe fn ffi_to_const(obj: dpp::identity::core_script::CoreScript) -> *const Self {
        ferment_interfaces::boxed(Self { raw: ferment_interfaces::boxed(obj) })
    }
}

impl Drop for CoreScriptFFI {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any(self.raw);
        }
    }
}
