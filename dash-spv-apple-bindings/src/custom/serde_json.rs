#[allow(non_camel_case_types)]
#[ferment_macro::register(serde_json::Value)]
#[derive(Clone)]
pub struct serde_json_JsonValue {
    raw_err: *mut serde_json::Value,
}
impl ferment_interfaces::FFIConversionFrom<serde_json::Value> for serde_json_JsonValue {
    unsafe fn ffi_from_const(ffi: *const Self) -> serde_json::Value {
        let ffi = &*ffi;
        match &*ffi.raw_err {
            serde_json::Value::Null => serde_json::Value::Null,
            serde_json::Value::Bool(o_0) => serde_json::Value::Bool(*o_0),
            serde_json::Value::Number(o_0) => serde_json::Value::Number(o_0.clone()),
            serde_json::Value::String(o_0) => serde_json::Value::String(o_0.clone()),
            serde_json::Value::Array(o_0) => serde_json::Value::Array(o_0.clone()),
            serde_json::Value::Object(o_0) => serde_json::Value::Object(o_0.clone())
        }
    }
}
impl ferment_interfaces::FFIConversionTo<serde_json::Value> for serde_json_JsonValue {
    unsafe fn ffi_to_const(obj: serde_json::Value) -> *const Self {
        ferment_interfaces::boxed(serde_json_JsonValue { raw_err: ferment_interfaces::boxed(obj) })
    }
}

impl Drop for serde_json_JsonValue {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any(self.raw_err);
        }
    }
}

#[allow(non_camel_case_types)]
#[ferment_macro::register(serde_json::Error)]
// #[derive(Clone)]
pub struct serde_json_Error {
    raw: *mut serde_json::Error,
}
impl ferment_interfaces::FFIConversionFrom<serde_json::Error> for serde_json_Error {
    unsafe fn ffi_from_const(ffi: *const Self) -> serde_json::Error {
        ferment_interfaces::FFIConversionFrom::ffi_from(ffi.cast_mut())
    }
    unsafe fn ffi_from(ffi: *mut Self) -> serde_json::Error {
        *ferment_interfaces::unbox_any((&*ffi).raw)
    }
}
impl ferment_interfaces::FFIConversionTo<serde_json::Error> for serde_json_Error {
    unsafe fn ffi_to_const(obj: serde_json::Error) -> *const Self {
        ferment_interfaces::boxed(serde_json_Error { raw: ferment_interfaces::boxed(obj) })
    }
}

impl Drop for serde_json_Error {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any(self.raw);
        }
    }
}

#[allow(non_camel_case_types)]
// #[ferment_macro::register(serde_json::Map)]
// #[derive(Clone)]
pub struct serde_json_Map_keys_String_values_platform_value_Value {
    raw: *mut serde_json::Map<String, platform_value::Value>,
}

impl ferment_interfaces::FFIConversionFrom<serde_json::Map<String, platform_value::Value>> for serde_json_Map_keys_String_values_platform_value_Value {
    unsafe fn ffi_from_const(ffi: *const Self) -> serde_json::Map<String, platform_value::Value> {
        Self::ffi_from(ffi.cast_mut())
    }
    unsafe fn ffi_from(ffi: *mut Self) -> serde_json::Map<String, platform_value::Value> {
        *ferment_interfaces::unbox_any((&*ffi).raw)
    }
}
impl ferment_interfaces::FFIConversionTo<serde_json::Map<String, platform_value::Value>> for serde_json_Map_keys_String_values_platform_value_Value {
    unsafe fn ffi_to_const(obj: serde_json::Map<String, platform_value::Value>) -> *const Self {
        ferment_interfaces::boxed(serde_json_Map_keys_String_values_platform_value_Value { raw: ferment_interfaces::boxed(obj) })
    }
}

impl Drop for serde_json_Map_keys_String_values_platform_value_Value {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any(self.raw);
        }
    }
}