#[allow(non_camel_case_types)]
#[ferment_macro::register(regex::Regex)]
pub struct regex_Regex {
    raw: *mut regex::Regex,
}

impl ferment_interfaces::FFIConversionFrom<regex::Regex> for regex_Regex {
    unsafe fn ffi_from_const(ffi: *const Self) -> regex::Regex {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment_interfaces::FFIConversionTo<regex::Regex> for regex_Regex {
    unsafe fn ffi_to_const(obj: regex::Regex) -> *const Self {
        ferment_interfaces::boxed(Self { raw: ferment_interfaces::boxed(obj) })
    }
}

impl Drop for regex_Regex {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any(self.raw);
        }
    }
}
