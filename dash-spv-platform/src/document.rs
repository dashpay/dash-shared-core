use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use dash_sdk::dpp::document::DocumentV0Getters;
use dash_sdk::dpp::util::entropy_generator::DefaultEntropyGenerator;
use dash_sdk::platform::transition::put_document::PutDocument;
use dash_sdk::Error;
use dash_sdk::dpp::ProtocolError;
use drive::dpp::data_contract::accessors::v0::DataContractV0Getters;
use drive::dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use drive::dpp::document::Document;
use drive::dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use drive::dpp::identity::IdentityPublicKey;
use drive::dpp::identity::signer::Signer;
use drive::dpp::prelude::{BlockHeight, CoreBlockHeight};
use drive::dpp::util::entropy_generator::EntropyGenerator;
use platform_value::{BinaryData, Identifier, Value};
use platform_version::version::PlatformVersion;
use crate::{FFIContext, PlatformSDK};


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

impl PlatformSDK {

    pub async fn put_document(
        &self,
        document: Document,
        contract_id: Identifier,
        document_type: &str,
        identity_public_key: IdentityPublicKey,
        block_height: BlockHeight,
        core_block_height: CoreBlockHeight
    ) -> Result<Document, Error> {
        let sdk = self.sdk_ref();
        match self.fetch_contract_by_id(contract_id).await? {
            None => Err(Error::Config("no contract".to_string())),
            Some(contract) => {
                let document_type = contract.document_type_for_name(document_type)
                    .map_err(ProtocolError::from)?;
                let entropy = DefaultEntropyGenerator.generate().unwrap();
                document_type
                    .create_document_from_data(
                        Value::from(document.properties()),
                        document.owner_id(),
                        block_height,
                        core_block_height,
                        entropy,
                        PlatformVersion::latest())
                    .map_err(Error::from)?
                    .put_to_platform_and_wait_for_response(
                        sdk,
                        document_type.to_owned_document_type(),
                        entropy,
                        identity_public_key,
                        Arc::new(contract),
                        &self.callback_signer)
                    .await
            },
        }
    }
}