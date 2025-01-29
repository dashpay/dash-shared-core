use std::sync::Arc;
use dash_sdk::platform::DocumentQuery;
use dash_sdk::Sdk;
use dpp::data_contract::DataContract;
use dpp::data_contracts::SystemDataContract;
use dpp::document::Document;
use drive_proof_verifier::types::RetrievedObjects;
use indexmap::IndexMap;
use platform_value::Identifier;
use dash_spv_crypto::network::ChainType;
use dash_spv_macro::StreamManager;
use crate::error::Error;
use crate::query::{order_by_asc_normalized_label, where_domain_is, where_normalized_label_equal_to, where_normalized_label_in};
use crate::util::{RetryStrategy, StreamManager, StreamSettings, StreamSpec, Validator};

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum UsernameStatus {
    NotPresent = 0,
    Initial = 1,
    PreorderRegistrationPending = 2,
    Preordered = 3,
    RegistrationPending = 4, //sent to DAPI, not yet confirmed
    Confirmed = 5,
    TakenOnNetwork = 6,
}


#[derive(Clone, Debug, StreamManager)]
#[ferment_macro::opaque]
pub struct UsernamesManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
}
impl UsernamesManager {
    pub fn new(sdk: &Arc<Sdk>, chain_type: ChainType) -> Self {
        Self { sdk: Arc::clone(sdk), chain_type }
    }
    pub fn query_username(&self, contract: DataContract, domain: String, username: String) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "domain").map_err(Error::from)?;
        query.limit = 1;
        query.where_clauses = vec![where_domain_is(domain), where_normalized_label_equal_to(username)];
        Ok(query)
    }
    pub fn query_usernames(&self, contract: DataContract, domain: String, usernames: Vec<String>) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "domain").map_err(Error::from)?;
        query.limit = usernames.len() as u32;
        query.where_clauses = vec![where_domain_is(domain), where_normalized_label_in(usernames)];
        query.order_by_clauses = vec![order_by_asc_normalized_label()];
        Ok(query)

    }

}

#[ferment_macro::export]
impl UsernamesManager {
    pub async fn username(&self, domain: String, username: String) -> Result<Option<Document>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            (domain, username),
            |contract, (domain, username)|
                self.username_with_contract(domain, username, contract)).await
    }

    pub async fn usernames(&self, domain: String, usernames: Vec<String>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            (domain, usernames),
            |contract, (domain, usernames)|
                self.usernames_with_contract(domain, usernames, contract)).await
    }
    pub async fn username_stream(&self, domain: String, username: String, retry: RetryStrategy, options: UsernameValidator, delay: u64) -> Result<Option<Document>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            (domain, username, retry, options, delay),
            |contract, (domain, username, retry, options, delay)|
                self.stream_username_with_contract(domain, username, contract, retry, options, delay)).await
    }

    pub async fn usernames_stream(&self, domain: String, usernames: Vec<String>, retry: RetryStrategy, options: UsernameValidator, delay: u64) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            (domain, usernames, retry, options, delay),
            |contract, (domain, usernames, retry, options, delay)|
                self.stream_usernames_with_contract(domain, usernames, contract, retry, options, delay)).await
    }


    /// Using pre-fetched contract
    pub async fn username_with_contract(&self, domain: String, username: String, contract: DataContract) -> Result<Option<Document>, Error> {
        let query = self.query_username(contract, domain, username)?;
        self.document_with_query(query).await
    }

    pub async fn usernames_with_contract(&self, domain: String, usernames: Vec<String>, contract: DataContract) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_usernames(contract, domain, usernames)?;
        self.many_documents_with_query(query).await
    }

    pub async fn stream_username_with_contract(&self, domain: String, username: String, contract: DataContract, retry: RetryStrategy, options: UsernameValidator, delay: u64) -> Result<Option<Document>, Error> {
        let query = self.query_username(contract, domain, username)?;
        self.stream_with_settings::<UsernameValidator, Document, DocumentQuery>(query, retry, StreamSettings::default().with_delay(delay), options).await
    }
    pub async fn stream_usernames_with_contract(&self, domain: String, usernames: Vec<String>, contract: DataContract, retry: RetryStrategy, options: UsernameValidator, delay: u64) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_usernames(contract, domain, usernames)?;
        self.stream_many_with_settings::<UsernameValidator, Document, DocumentQuery>(query, retry, StreamSettings::default().with_delay(delay), options).await
    }

}


#[ferment_macro::export]
pub enum UsernameValidator {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}

impl UsernameValidator {
    pub fn accept_not_found(&self) -> bool {
        match self {
            UsernameValidator::None => false,
            UsernameValidator::AcceptNotFoundAsNotAnError => true
        }
    }
}
impl Validator<Option<Document>> for UsernameValidator {
    fn validate(&self, value: &Option<Document>) -> bool {
        value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl Validator<RetrievedObjects<Identifier, Document>> for UsernameValidator {
    fn validate(&self, _value: &RetrievedObjects<Identifier, Document>) -> bool {
        true
    }
}

impl StreamSpec for UsernameValidator {
    type Validator = UsernameValidator;
    type Error = dash_sdk::Error;
    type Result = Option<Document>;
    type ResultMany = IndexMap<Identifier, Self::Result>;
}

