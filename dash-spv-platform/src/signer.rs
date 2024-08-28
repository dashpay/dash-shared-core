use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use dash_sdk::dpp::ProtocolError;
use drive::dpp::identity::IdentityPublicKey;
use drive::dpp::identity::signer::Signer;
use platform_value::BinaryData;
use crate::FFIContext;


#[derive(Clone)]
pub struct CallbackSigner {
    pub signer: Arc<dyn Fn(*const FFIContext, IdentityPublicKey, &[u8]) -> Result<BinaryData, ProtocolError> + Send + Sync>,
    pub context: Arc<FFIContext>
}

// # [repr (C)] # [derive (Clone)]
// pub struct FFI_CallbackSigner {
//     pub context: *const std::os::raw::c_void ,
//     caller : fn (*const FFIContext, *mut u8, *mut u8) -> *mut u8,
//     destructor : fn (result : u32) ,
// }
//
// unsafe impl Send for FFI_CallbackSigner {}
//
// impl FFI_CallbackSigner {
//     pub unsafe fn call (& self , o_0 : *const FFIContext, o_1: IdentityPublicKey, o_2: &[u8]) -> Result<BinaryData, ProtocolError> {
//         let ffi_result = (self.caller)(o_0, ferment_interfaces::boxed_vec(o_1.data().0.clone()), ferment_interfaces::boxed_vec(o_2.to_vec()));
//         ffi_result
//     }
// }
impl Debug for CallbackSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("{:?}", self.context).as_str())
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, identity_public_key: &IdentityPublicKey, data: &[u8]) -> Result<BinaryData, ProtocolError> {
        (self.signer)(Arc::as_ptr(&self.context), identity_public_key.clone(), data)
    }
}
