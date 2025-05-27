use std::sync::Arc;
use dash_sdk::platform::DocumentQuery;
use dash_sdk::Sdk;
use dash_spv_macro::StreamManager;
use dpp::data_contract::DataContract;
use dpp::document::Document;
use dpp::system_data_contracts::SystemDataContract;
use drive_proof_verifier::types::RetrievedObjects;
use indexmap::IndexMap;
use platform_value::Identifier;
use dash_spv_crypto::network::ChainType;
use crate::error::Error;
use crate::query::{order_by_asc_salted_domain_hash, where_salted_domain_hash_in, where_salted_domain_hash_is};
use crate::util::{RetryStrategy, StreamManager, StreamSettings, StreamSpec, Validator};

#[derive(Clone, Debug, StreamManager)]
#[ferment_macro::opaque]
pub struct SaltedDomainHashesManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
}

impl SaltedDomainHashesManager {
    pub fn new(sdk: &Arc<Sdk>, chain_type: ChainType) -> Self {
        Self { sdk: Arc::clone(sdk), chain_type }
    }
    pub fn query_preorder_salted_domain_hash(&self, contract: DataContract, hash: [u8; 32]) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "preorder").map_err(Error::from)?;
        query.limit = 1;
        query.where_clauses = vec![where_salted_domain_hash_is(hash)];
        Ok(query)
    }
    pub fn query_preorder_salted_domain_hashes(&self, contract: DataContract, hashes: Vec<[u8; 32]>) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "preorder").map_err(Error::from)?;
        query.limit = hashes.len() as u32;
        query.where_clauses = vec![where_salted_domain_hash_in(hashes)];
        query.order_by_clauses = vec![order_by_asc_salted_domain_hash()];
        Ok(query)
    }

}

#[ferment_macro::export]
impl SaltedDomainHashesManager {
    pub async fn preorder_salted_domain_hash(&self, hash: [u8; 32]) -> Result<Option<Document>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            hash,
            |contract, hash|
                self.preorder_salted_domain_hash_with_contract(hash, contract)).await
    }
    pub async fn preorder_salted_domain_hashes(&self, hashes: Vec<[u8; 32]>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            hashes,
            |contract, hashes|
                self.preorder_salted_domain_hashes_with_contract(hashes, contract)).await
    }

    pub async fn preorder_salted_domain_hash_stream(&self, hash: [u8; 32], retry: RetryStrategy, options: SaltedDomainHashValidator, delay: u64) -> Result<Option<Document>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            (hash, retry, options, delay),
            |contract, (hash, retry, options, delay)|
                self.stream_preorder_salted_domain_hash_with_contract(hash, contract, retry, options, delay)).await
    }

    pub async fn preorder_salted_domain_hashes_stream(&self, hashes: Vec<[u8; 32]>, retry: RetryStrategy, options: SaltedDomainHashValidator, delay: u64) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            (hashes, retry, options, delay),
            |contract, (hashes, retry, options, delay)|
                self.stream_preorder_salted_domain_hashes_with_contract(hashes, contract, retry, options, delay)).await
    }


    pub async fn preorder_salted_domain_hash_with_contract(&self, hash: [u8; 32], contract: DataContract) -> Result<Option<Document>, Error> {
        let query = self.query_preorder_salted_domain_hash(contract, hash)?;
        self.document_with_query(query).await
    }

    pub async fn preorder_salted_domain_hashes_with_contract(&self, hashes: Vec<[u8; 32]>, contract: DataContract) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_preorder_salted_domain_hashes(contract, hashes)?;
        self.many_documents_with_query(query).await
    }

    pub async fn stream_preorder_salted_domain_hash_with_contract(&self, hash: [u8; 32], contract: DataContract, retry: RetryStrategy, options: SaltedDomainHashValidator, delay: u64) -> Result<Option<Document>, Error> {
        let query = self.query_preorder_salted_domain_hash(contract, hash)?;
        self.stream_with_settings::<SaltedDomainHashValidator, Document, DocumentQuery>(query, retry, StreamSettings::default_with_delay(delay), options).await
    }
    pub async fn stream_preorder_salted_domain_hashes_with_contract(&self, hashes: Vec<[u8; 32]>, contract: DataContract, retry: RetryStrategy, options: SaltedDomainHashValidator, delay: u64) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_preorder_salted_domain_hashes(contract, hashes)?;
        self.stream_many_with_settings::<SaltedDomainHashValidator, Document, DocumentQuery>(query, retry, StreamSettings::default_with_delay(delay), options).await
    }

}


#[ferment_macro::export]
pub enum SaltedDomainHashValidator {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}

impl SaltedDomainHashValidator {
    pub fn accept_not_found(&self) -> bool {
        match self {
            SaltedDomainHashValidator::None => false,
            SaltedDomainHashValidator::AcceptNotFoundAsNotAnError => true
        }
    }
}
impl Validator<Option<Document>> for SaltedDomainHashValidator {
    fn validate(&self, value: &Option<Document>) -> bool {
        value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl Validator<RetrievedObjects<Identifier, Document>> for SaltedDomainHashValidator {
    fn validate(&self, _value: &RetrievedObjects<Identifier, Document>) -> bool {
        true
    }
}

impl StreamSpec for SaltedDomainHashValidator {
    type Validator = SaltedDomainHashValidator;
    type Error = dash_sdk::Error;
    type Result = Option<Document>;
    type ResultMany = IndexMap<Identifier, Self::Result>;
}

