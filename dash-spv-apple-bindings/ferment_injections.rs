// This file sometimes needed to bootstrap fermented types in case when you have custom conversions or extensions that are using some of the fermented types
#[allow(
    clippy::let_and_return,
    clippy::suspicious_else_formatting,
    clippy::redundant_field_names,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    redundant_semicolons,
    unreachable_patterns,
    unused_braces,
    unused_imports,
    unused_parens,
    unused_qualifications,
    unused_unsafe,
    unused_variables
)]
pub mod types {
    pub mod dash_spv_platform {
        pub mod error {
            pub struct dash_spv_platform_error_Error {

            }
            impl ferment::FFIConversionFrom<dash_spv_platform::error::Error> for dash_spv_platform_error_Error {
                unsafe fn ffi_from_const(ffi: *const dash_spv_platform_error_Error) -> dash_spv_platform::error::Error {
                    panic!("ffff")
                }
            }
            impl ferment::FFIConversionTo<dash_spv_platform::error::Error> for dash_spv_platform_error_Error {
                unsafe fn ffi_to_const(obj: dash_spv_platform::error::Error) -> *const dash_spv_platform_error_Error {
                    panic!("ffff")
                }
            }

        }
    }
}
#[allow(
    clippy::let_and_return,
    clippy::suspicious_else_formatting,
    clippy::redundant_field_names,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    redundant_semicolons,
    unreachable_patterns,
    unused_braces,
    unused_imports,
    unused_parens,
    unused_qualifications,
    unused_unsafe,
    unused_variables
)]
pub mod generics {
    use crate as dash_spv_apple_bindings;

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_20 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 20]> for Arr_u8_20 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_20) -> [u8; 20] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 20]> for Arr_u8_20 {
        unsafe fn ffi_to_const(obj: [u8; 20]) -> *const Arr_u8_20 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_20 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_20_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_20 {
        ferment::boxed(Arr_u8_20 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_20_destroy(ffi: *mut Arr_u8_20) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_32 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 32]> for Arr_u8_32 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_32) -> [u8; 32] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 32]> for Arr_u8_32 {
        unsafe fn ffi_to_const(obj: [u8; 32]) -> *const Arr_u8_32 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_32 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_32_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_32 {
        ferment::boxed(Arr_u8_32 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_32_destroy(ffi: *mut Arr_u8_32) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_36 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 36]> for Arr_u8_36 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_36) -> [u8; 36] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 36]> for Arr_u8_36 {
        unsafe fn ffi_to_const(obj: [u8; 36]) -> *const Arr_u8_36 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_36 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_36_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_36 {
        ferment::boxed(Arr_u8_36 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_36_destroy(ffi: *mut Arr_u8_36) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Slice_u8 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<Vec<u8>> for Slice_u8 {
        unsafe fn ffi_from_const(ffi: *const Slice_u8) -> Vec<u8> {
            let ffi_ref = &*ffi;
            ferment::from_primitive_group(ffi_ref.values, ffi_ref.count)
        }
    }
    impl ferment::FFIConversionTo<Vec<u8>> for Slice_u8 {
        unsafe fn ffi_to_const(obj: Vec<u8>) -> *const Slice_u8 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Slice_u8 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Slice_u8_ctor(count: usize, values: *mut u8) -> *mut Slice_u8 {
        ferment::boxed(Slice_u8 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Slice_u8_destroy(ffi: *mut Slice_u8) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_16 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 16]> for Arr_u8_16 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_16) -> [u8; 16] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 16]> for Arr_u8_16 {
        unsafe fn ffi_to_const(obj: [u8; 16]) -> *const Arr_u8_16 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_16 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_16_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_16 {
        ferment::boxed(Arr_u8_16 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_16_destroy(ffi: *mut Arr_u8_16) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_48 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 48]> for Arr_u8_48 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_48) -> [u8; 48] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 48]> for Arr_u8_48 {
        unsafe fn ffi_to_const(obj: [u8; 48]) -> *const Arr_u8_48 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_48 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_48_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_48 {
        ferment::boxed(Arr_u8_48 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_48_destroy(ffi: *mut Arr_u8_48) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_96 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 96]> for Arr_u8_96 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_96) -> [u8; 96] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 96]> for Arr_u8_96 {
        unsafe fn ffi_to_const(obj: [u8; 96]) -> *const Arr_u8_96 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_96 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_96_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_96 {
        ferment::boxed(Arr_u8_96 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_96_destroy(ffi: *mut Arr_u8_96) {
        ferment::unbox_any(ffi);
    }


    #[repr(C)]
    #[derive(Clone)]
    pub struct Vec_u8 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<Vec<u8>> for Vec_u8 {
        unsafe fn ffi_from_const(ffi: *const Vec_u8) -> Vec<u8> {
            let ffi_ref = &*ffi;
            ferment::from_primitive_group(ffi_ref.values, ffi_ref.count)
        }
    }
    impl ferment::FFIConversionTo<Vec<u8>> for Vec_u8 {
        unsafe fn ffi_to_const(obj: Vec<u8>) -> *const Vec_u8 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Vec_u8 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Vec_u8_ctor(count: usize, values: *mut u8) -> *mut Vec_u8 {
        ferment::boxed(Vec_u8 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Vec_u8_destroy(ffi: *mut Vec_u8) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_2 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 2]> for Arr_u8_2 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_2) -> [u8; 2] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 2]> for Arr_u8_2 {
        unsafe fn ffi_to_const(obj: [u8; 2]) -> *const Arr_u8_2 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_2 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_2_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_2 {
        ferment::boxed(Arr_u8_2 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_2_destroy(ffi: *mut Arr_u8_2) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Vec_u8_32 {
        pub count: usize,
        pub values: *mut *mut crate::fermented::generics::Arr_u8_32,
    }
    impl ferment::FFIConversionFrom<Vec<[u8; 32]>> for Vec_u8_32 {
        unsafe fn ffi_from_const(ffi: *const Vec_u8_32) -> Vec<[u8; 32]> {
            let ffi_ref = &*ffi;
            ferment::from_complex_group(ffi_ref.values, ffi_ref.count)
        }
    }
    impl ferment::FFIConversionTo<Vec<[u8; 32]>> for Vec_u8_32 {
        unsafe fn ffi_to_const(obj: Vec<[u8; 32]>) -> *const Vec_u8_32 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_complex_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Vec_u8_32 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_any_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Vec_u8_32_ctor(
        count: usize,
        values: *mut *mut crate::fermented::generics::Arr_u8_32,
    ) -> *mut Vec_u8_32 {
        ferment::boxed(Vec_u8_32 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Vec_u8_32_destroy(ffi: *mut Vec_u8_32) {
        ferment::unbox_any(ffi);
    }

    #[repr(C)]
    #[derive(Clone)]
    pub struct Arr_u8_4 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment::FFIConversionFrom<[u8; 4]> for Arr_u8_4 {
        unsafe fn ffi_from_const(ffi: *const Arr_u8_4) -> [u8; 4] {
            let ffi_ref = &*ffi;
            let vec: Vec<u8> = ferment::from_primitive_group(ffi_ref.values, ffi_ref.count);
            vec.try_into().unwrap()
        }
    }
    impl ferment::FFIConversionTo<[u8; 4]> for Arr_u8_4 {
        unsafe fn ffi_to_const(obj: [u8; 4]) -> *const Arr_u8_4 {
            ferment::boxed(Self {
                count: obj.len(),
                values: ferment::to_primitive_group(obj.into_iter()),
            })
        }
    }
    impl Drop for Arr_u8_4 {
        fn drop(&mut self) {
            unsafe {
                ferment::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_4_ctor(count: usize, values: *mut u8) -> *mut Arr_u8_4 {
        ferment::boxed(Arr_u8_4 { count, values })
    }
    #[no_mangle]
    pub unsafe extern "C" fn Arr_u8_4_destroy(ffi: *mut Arr_u8_4) {
        ferment::unbox_any(ffi);
    }


    # [repr (C)] # [derive (Clone)]
    pub struct Result_ok_u32_err_dash_spv_platform_error_Error {
        pub ok : * mut u32 ,
        pub error : * mut crate :: fermented :: types :: dash_spv_platform :: error :: dash_spv_platform_error_Error
    }
    impl ferment :: FFIConversionFrom < Result < u32 , dash_spv_platform :: error :: Error > > for Result_ok_u32_err_dash_spv_platform_error_Error {
        unsafe fn ffi_from_const (ffi : * const Result_ok_u32_err_dash_spv_platform_error_Error) -> Result < u32 , dash_spv_platform :: error :: Error > {
            let ffi_ref = & * ffi ;
            ferment :: fold_to_result (ffi_ref . ok , | o | * o , ffi_ref . error , | o | < crate :: fermented :: types :: dash_spv_platform :: error :: dash_spv_platform_error_Error as ferment :: FFIConversionFrom < dash_spv_platform :: error :: Error >> :: ffi_from (o)) }
    }
    impl ferment :: FFIConversionTo < Result < u32 , dash_spv_platform :: error :: Error > > for Result_ok_u32_err_dash_spv_platform_error_Error {
        unsafe fn ffi_to_const (obj : Result < u32 , dash_spv_platform :: error :: Error >) -> * const Result_ok_u32_err_dash_spv_platform_error_Error {
            ferment :: boxed ({ let (ok , error) = ferment :: to_result (obj , | o | ferment :: boxed (o) , | o | ferment :: FFIConversionTo :: ffi_to (o)) ;
                Self { ok , error } })
        }
    }
    impl Drop for Result_ok_u32_err_dash_spv_platform_error_Error {
        fn drop (& mut self) { unsafe { ferment :: destroy_opt_primitive (self . ok) ; ferment :: unbox_any_opt (self . error) ; } }
    }
    # [repr (C)]
    # [derive (Clone)]
    pub struct Fn_ARGS_std_os_raw_c_void_u32_std_os_raw_c_void_RTRN_ {
        caller: unsafe extern "C" fn(*const std::os::raw::c_void, u32, *const std::os::raw::c_void)
    }
    impl Fn_ARGS_std_os_raw_c_void_u32_std_os_raw_c_void_RTRN_ {
        pub unsafe fn call(&self, o_0: *const std::os::raw::c_void, o_1: u32, o_2: *const std::os::raw::c_void) {
            let ffi_result = (self.caller)(o_0, o_1, o_2);
            ffi_result
        }
    }
    unsafe impl Send for Fn_ARGS_std_os_raw_c_void_u32_std_os_raw_c_void_RTRN_ { }
    unsafe impl Sync for Fn_ARGS_std_os_raw_c_void_u32_std_os_raw_c_void_RTRN_ { }
}
