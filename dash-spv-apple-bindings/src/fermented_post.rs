#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn PlatformSDK_register_on_network(
    runtime: *const std::os::raw::c_void,
    platform: *const dash_spv_platform::PlatformSDK,
    controller: *mut dash_spv_platform::identity::callback::IdentityController,
    steps: u32,
    topup_duff_amount: u64,
    funding_account_context: *const std::os::raw::c_void,
    prompt: *mut std::os::raw::c_char,
    progress_handler: crate::fermented::generics::Fn_ARGS_std_os_raw_c_void_u32_std_os_raw_c_void_RTRN_,
    progress_context: *const std::os::raw::c_void,
) -> *mut crate::fermented::generics::Result_ok_u32_err_dash_spv_platform_error_Error {
    let runtime_arc = std::sync::Arc::from_raw(runtime as *const tokio::runtime::Runtime);
    let rt = runtime_arc.clone();
    std::mem::forget(runtime_arc);
    let platform_arc = std::sync::Arc::from_raw(platform);
    let sdk = platform_arc.clone();
    std::mem::forget(platform_arc);
    let controller = &mut *controller;
    let prompt_str = <std::os::raw::c_char as ferment::FFIConversionFrom<String>>::ffi_from(prompt);
    let result = rt.block_on(async move {
        dash_spv_platform::PlatformSDK::register_on_network(
            &sdk,
            controller,
            steps,
            topup_duff_amount,
            funding_account_context,
            prompt_str,
            move |ctx, step, prog_ctx| unsafe { progress_handler.call(ctx, step, prog_ctx) },
            progress_context,
        )
            .await
    });
    <crate::fermented::generics::Result_ok_u32_err_dash_spv_platform_error_Error as ferment::FFIConversionTo<_>>::ffi_to(result)
}