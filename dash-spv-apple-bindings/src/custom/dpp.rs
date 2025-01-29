// #[allow(non_camel_case_types)]
// #[derive(Clone)]
// #[ferment_macro::register(dpp::identity::core_script::CoreScript)]
// pub struct CoreScriptFFI {
//     pub raw: *mut dpp::identity::core_script::CoreScript,
// }
// impl ferment::FFIConversionFrom<dpp::identity::core_script::CoreScript> for CoreScriptFFI {
//     unsafe fn ffi_from_const(ffi: *const Self) -> dpp::identity::core_script::CoreScript {
//         let ffi = &*ffi;
//         let raw = &*ffi.raw;
//         raw.clone()
//     }
// }
// impl ferment::FFIConversionTo<dpp::identity::core_script::CoreScript> for CoreScriptFFI {
//     unsafe fn ffi_to_const(obj: dpp::identity::core_script::CoreScript) -> *const Self {
//         ferment::boxed(Self { raw: ferment::boxed(obj) })
//     }
// }
//
// impl Drop for CoreScriptFFI {
//     fn drop(&mut self) {
//         unsafe {
//             ferment::unbox_any(self.raw);
//         }
//     }
// }

#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(dpp::identity::errors::asset_lock_transaction_is_not_found_error::AssetLockTransactionIsNotFoundError)]
pub struct AssetLockTransactionIsNotFoundErrorFFI {
    pub raw: *mut dpp::identity::errors::asset_lock_transaction_is_not_found_error::AssetLockTransactionIsNotFoundError,
}
impl ferment::FFIConversionFrom<dpp::identity::errors::asset_lock_transaction_is_not_found_error::AssetLockTransactionIsNotFoundError> for AssetLockTransactionIsNotFoundErrorFFI {
    unsafe fn ffi_from_const(ffi: *const Self) -> dpp::identity::errors::asset_lock_transaction_is_not_found_error::AssetLockTransactionIsNotFoundError {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment::FFIConversionTo<dpp::identity::errors::asset_lock_transaction_is_not_found_error::AssetLockTransactionIsNotFoundError> for AssetLockTransactionIsNotFoundErrorFFI {
    unsafe fn ffi_to_const(obj: dpp::identity::errors::asset_lock_transaction_is_not_found_error::AssetLockTransactionIsNotFoundError) -> *const Self {
        ferment::boxed(Self { raw: ferment::boxed(obj) })
    }
}

impl Drop for AssetLockTransactionIsNotFoundErrorFFI {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.raw);
        }
    }
}
