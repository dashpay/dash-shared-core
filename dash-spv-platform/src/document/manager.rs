use std::collections::BTreeMap;
use std::sync::Arc;
use dash_sdk::{platform::{DocumentQuery, FetchMany}, Sdk};
use dpp::data_contract::DataContract;
use dpp::data_contract::accessors::v0::DataContractV0Getters;
use dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dash_sdk::platform::transition::put_document::PutDocument;
use dpp::document::{Document, DocumentV0Getters};
use dpp::errors::ProtocolError;
use dpp::identity::identity_public_key::IdentityPublicKey;
use dpp::prelude::{BlockHeight, CoreBlockHeight};
use dpp::util::entropy_generator::{DefaultEntropyGenerator, EntropyGenerator};
use platform_value::Identifier;
use platform_version::version::PlatformVersion;
use crate::error::Error;
use crate::signer::CallbackSigner;

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct DocumentsManager {
    pub sdk: Arc<Sdk>,
}
impl DocumentsManager {
    pub fn new(sdk: &Arc<Sdk>) -> Self {
        Self { sdk: Arc::clone(sdk) }
    }
}

// #[ferment_macro::export]
impl DocumentsManager {
    pub async fn documents_with_query(&self, query: DocumentQuery) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        Document::fetch_many(&self.sdk, query).await.map_err(Error::from)
    }


    pub async fn put_document(
        &self,
        document: Document,
        document_type: &str,
        block_height: BlockHeight,
        core_block_height: CoreBlockHeight,
        contract: DataContract,
        identity_public_key: IdentityPublicKey,
        signer: &CallbackSigner,
    ) -> Result<Document, Error> {
        let document_type = contract.document_type_for_name(document_type)
            .map_err(ProtocolError::from)?;
        let entropy = DefaultEntropyGenerator.generate().unwrap();

        document_type
            .create_document_from_data(document.properties().into(), document.owner_id(), block_height, core_block_height, entropy, PlatformVersion::latest())
            .map_err(Error::from)?
            .put_to_platform_and_wait_for_response(&self.sdk, document_type.to_owned_document_type(), entropy, identity_public_key, Arc::new(contract), signer)
            .await
            .map_err(Error::from)

    }

    // pub async fn profiles(&self, document: Document) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
    //     self.documents_with_query()
    // }
}