#[allow(non_camel_case_types)]
#[ferment_macro::register(regex::Regex)]
pub struct regex_Regex {
    raw: *mut regex::Regex,
}

impl ferment::FFIConversionFrom<regex::Regex> for regex_Regex {
    unsafe fn ffi_from_const(ffi: *const Self) -> regex::Regex {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment::FFIConversionTo<regex::Regex> for regex_Regex {
    unsafe fn ffi_to_const(obj: regex::Regex) -> *const Self {
        ferment::boxed(Self { raw: ferment::boxed(obj) })
    }
}

impl Drop for regex_Regex {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.raw);
        }
    }
}
