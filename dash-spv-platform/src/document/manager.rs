use std::os::raw::c_void;
use std::sync::Arc;
use dash_sdk::{platform::{DocumentQuery, FetchMany}, RequestSettings, Sdk};
use dash_sdk::platform::Fetch;
use dpp::data_contract::DataContract;
use dpp::data_contract::accessors::v0::DataContractV0Getters;
use dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dash_sdk::platform::transition::put_document::PutDocument;
use dashcore::prelude::DisplayHex;
use dpp::data_contracts::SystemDataContract;
use dpp::document::{Document, DocumentV0Getters};
use dpp::errors::ProtocolError;
use dpp::identity::identity_public_key::IdentityPublicKey;
use dpp::prelude::{BlockHeight, CoreBlockHeight};
use drive_proof_verifier::types::RetrievedObjects;
use indexmap::IndexMap;
use platform_value::Identifier;
use platform_value::string_encoding::Encoding;
use platform_version::version::PlatformVersion;
use dash_spv_crypto::crypto::byte_util::Random;
use dash_spv_crypto::network::ChainType;
use dash_spv_macro::StreamManager;
use crate::error::Error;
use crate::identity::manager::DEFAULT_FETCH_USERNAMES_RETRY_COUNT;
use crate::identity::model::IdentityModel;
use crate::models::transient_dashpay_user::TransientDashPayUser;
use crate::query::{order_by_asc_normalized_label, order_by_asc_owner_id, where_domain_is_dash, where_normalized_label_equal_to, where_normalized_label_starts_with, where_owner_in, where_owner_is, where_records_identity_is};
use crate::signer::CallbackSigner;
use crate::util::{RetryStrategy, StreamManager, StreamSettings, StreamSpec, Validator};

pub const PROFILE_SETTINGS: RequestSettings = RequestSettings {
    connect_timeout: None,
    timeout: None,
    retries: Some(5),
    ban_failed_address: None,
};
pub const USERNAME_SETTINGS: RequestSettings = RequestSettings {
    connect_timeout: None,
    timeout: None,
    retries: Some(DEFAULT_FETCH_USERNAMES_RETRY_COUNT),
    ban_failed_address: None,
};


#[derive(Clone, Debug, StreamManager)]
#[ferment_macro::opaque]
pub struct DocumentsManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
}

#[ferment_macro::export]
pub enum DocumentValidator {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}
impl DocumentValidator {
    pub fn accept_not_found(&self) -> bool {
        match self {
            DocumentValidator::None => false,
            DocumentValidator::AcceptNotFoundAsNotAnError => true
        }
    }
}
impl Validator<Option<Document>> for DocumentValidator {
    fn validate(&self, value: &Option<Document>) -> bool {
        value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl Validator<RetrievedObjects<Identifier, Document>> for DocumentValidator {
    fn validate(&self, _value: &RetrievedObjects<Identifier, Document>) -> bool {
        true
    }
}

impl StreamSpec for DocumentValidator {
    type Validator = DocumentValidator;
    type Error = dash_sdk::Error;
    type Result = Option<Document>;
    type ResultMany = IndexMap<Identifier, Self::Result>;
}


impl DocumentsManager {
    pub fn new(sdk: &Arc<Sdk>, chain_type: ChainType) -> Self {
        Self { sdk: Arc::clone(sdk), chain_type }
    }

    pub async fn documents_with_query(&self, query: DocumentQuery) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
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
        // let entropy = DefaultEntropyGenerator.generate()?;
        let entropy = <[u8; 32]>::random();
        document_type
            .create_document_from_data(document.properties().into(), document.owner_id(), block_height, core_block_height, entropy, PlatformVersion::latest())
            .map_err(Error::from)?
            .put_to_platform_and_wait_for_response(&self.sdk, document_type.to_owned_document_type(), entropy, identity_public_key, signer, None)
            // .put_to_platform_and_wait_for_response(&self.sdk, document_type.to_owned_document_type(), entropy, identity_public_key, Arc::new(contract), signer)
            .await
            .map_err(Error::from)

    }

    pub fn query_dpns_documents_for_identity_with_user_id(&self, contract: DataContract, user_id: [u8; 32]) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "domain").map_err(Error::from)?;
        query.limit = 100;
        query.where_clauses = vec![where_records_identity_is(user_id)];
        Ok(query)
    }
    pub fn query_dashpay_profile_for_user_id(&self, contract: DataContract, user_id: [u8; 32]) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "profile").map_err(Error::from)?;
        query.limit = 1;
        query.where_clauses = vec![where_owner_is(user_id)];
        Ok(query)
    }
    pub fn query_dashpay_profiles_for_user_ids(&self, contract: DataContract, user_ids: Vec<[u8; 32]>) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "profile").map_err(Error::from)?;
        query.limit = user_ids.len() as u32;
        query.where_clauses = vec![where_owner_in(user_ids)];
        query.order_by_clauses = vec![order_by_asc_owner_id()];
        Ok(query)
    }

    pub fn query_dpns_documents_for_username(&self, contract: DataContract, username: String) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "domain").map_err(Error::from)?;
        query.limit = 100;
        query.where_clauses = vec![
            where_domain_is_dash(),
            where_normalized_label_equal_to(username),
        ];
        query.order_by_clauses = vec![order_by_asc_normalized_label()];
        Ok(query)
    }

    pub fn query_dpns_documents_for_username_prefix(&self, contract: DataContract, username_prefix: String) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "domain").map_err(Error::from)?;
        query.limit = 100;
        query.where_clauses = vec![
            where_domain_is_dash(),
            where_normalized_label_starts_with(username_prefix),
        ];
        query.order_by_clauses = vec![order_by_asc_normalized_label()];
        Ok(query)
    }

}

#[ferment_macro::export]
impl DocumentsManager {

    pub async fn dpns_documents_for_identity_with_user_id(&self, user_id: [u8; 32]) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            user_id,
            |contract, user_id|
                self.dpns_documents_for_identity_with_user_id_using_contract(user_id, contract)).await
    }
    pub async fn stream_dpns_documents_for_identity_with_user_id(&self, user_id: [u8; 32], retry: RetryStrategy, options: DocumentValidator, delay: u64) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            user_id,
            |contract, user_id|
                self.stream_dpns_documents_for_identity_with_user_id_using_contract(user_id, contract, retry, options, delay)).await
    }
    pub async fn stream_dpns_documents_for_identity_with_user_id_using_contract(&self, user_id: [u8; 32], contract: DataContract, retry: RetryStrategy, options: DocumentValidator, delay: u64) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_dpns_documents_for_identity_with_user_id(contract, user_id)?;
        self.stream_many_with_settings::<DocumentValidator, Document, DocumentQuery>(query, retry, StreamSettings::default_with_delay(delay), options).await
    }

    pub async fn dpns_documents_for_username(&self, username: String) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            username,
            |contract, username|
                self.dpns_documents_for_username_using_contract(username, contract)).await
    }
    pub async fn dpns_documents_for_username_prefix(&self, username_prefix: String) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            username_prefix,
            |contract, username|
                self.dpns_documents_for_username_prefix_using_contract(username, contract)).await
    }
    pub async fn dashpay_profile_for_user_id(&self, user_id: [u8; 32]) -> Result<Option<Document>, Error> {
        self.with_contract(
            SystemDataContract::Dashpay,
            user_id,
            |contract, user_id|
                self.dashpay_profile_for_user_id_using_contract(user_id, contract)).await
    }
    pub async fn dashpay_profiles_for_user_ids(&self, user_ids: Vec<[u8; 32]>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::Dashpay,
            user_ids,
            |contract, user_ids|
                self.dashpay_profiles_for_user_ids_using_contract(user_ids, contract)).await
    }




    pub async fn dpns_documents_for_identity_with_user_id_using_contract(&self, user_id: [u8; 32], contract: DataContract) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_dpns_documents_for_identity_with_user_id(contract, user_id)?;
        self.many_documents_with_query(query).await
    }

    pub async fn dashpay_profile_for_user_id_using_contract(&self, user_id: [u8; 32], contract: DataContract) -> Result<Option<Document>, Error> {
        let query = self.query_dashpay_profile_for_user_id(contract, user_id)?;
        self.document_with_query(query).await
    }
    pub async fn stream_dashpay_profile_for_user_id_using_contract(&self, user_id: [u8; 32], contract: DataContract, retry: RetryStrategy, options: DocumentValidator, delay: u64) -> Result<Option<Document>, Error> {
        let query = self.query_dashpay_profile_for_user_id(contract, user_id)?;
        self.stream_with_settings::<DocumentValidator, Document, DocumentQuery>(query, retry, StreamSettings::default_with_delay(delay), options).await
    }

    pub async fn dashpay_profiles_for_user_ids_using_contract(&self, user_ids: Vec<[u8; 32]>, contract: DataContract) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_dashpay_profiles_for_user_ids(contract, user_ids)?;
        self.many_documents_with_query(query).await
    }
    pub async fn stream_dashpay_profiles_for_user_ids_using_contract(&self,  user_ids: Vec<[u8; 32]>, contract: DataContract, retry: RetryStrategy, options: DocumentValidator, delay: u64) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_dashpay_profiles_for_user_ids(contract, user_ids)?;
        self.stream_many_with_settings::<DocumentValidator, Document, DocumentQuery>(query, retry, StreamSettings::default_with_delay(delay), options).await
    }

    pub async fn dpns_documents_for_username_using_contract(&self, username: String, contract: DataContract) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_dpns_documents_for_username(contract, username)?;
        self.many_documents_with_query(query).await
    }
    pub async fn dpns_documents_for_username_prefix_using_contract(&self, username_prefix: String, contract: DataContract) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_dpns_documents_for_username_prefix(contract, username_prefix)?;
        self.many_documents_with_query(query).await
    }


    pub async fn fetch_usernames(&self, model: &mut IdentityModel, contract: DataContract, context: *const c_void) -> Result<bool, Error> {
        let user_id = model.unique_id;
        let query = self.query_dpns_documents_for_identity_with_user_id(contract, user_id)?;

        let (documents, _metadata) = Document::fetch_many_with_metadata(self.sdk_ref(), query, Some(USERNAME_SETTINGS)).await?;

        //
        // let documents = self.stream_dpns_documents_for_identity_with_user_id_using_contract(
        //     model.unique_id,
        //     contract, RetryStrategy::Linear(DEFAULT_FETCH_USERNAMES_RETRY_COUNT),
        //     DocumentValidator::None,
        //     1000
        // ).await?;
        for (identifier, maybe_document) in documents {
            if let Some(document) = maybe_document {
                model.update_with_username_document(document, context);
            } else {
                println!("[WARN] Document {} is nil", identifier.to_string(Encoding::Hex));
            }
        }
        Ok(true)
    }

    pub async fn fetch_profile(&self, model: &mut IdentityModel, contract: DataContract) -> Result<TransientDashPayUser, Error> {
        let user_id = model.unique_id;
        let query = self.query_dashpay_profile_for_user_id(contract, user_id)?;
        let (document, _metadata) = Document::fetch_with_metadata(self.sdk_ref(), query, Some(PROFILE_SETTINGS)).await?;
        match document {
            Some(doc) =>
                Ok(TransientDashPayUser::with_profile_document(doc)),
            None =>
                Err(Error::Any(0, format!("Profile for {} not found", user_id.to_lower_hex_string())))
        }

    }
}

