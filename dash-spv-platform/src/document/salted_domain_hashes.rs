use std::sync::Arc;
use dash_sdk::platform::{DocumentQuery, Fetch, FetchMany};
use dash_sdk::Sdk;
use dash_spv_macro::StreamManager;
use dpp::data_contract::DataContract;
use dpp::document::Document;
use dpp::system_data_contracts::SystemDataContract;
use indexmap::IndexMap;
use platform_value::Identifier;
use dash_spv_crypto::network::ChainType;
use crate::error::Error;
use crate::query::{order_by_asc_salted_domain_hash, where_salted_domain_hash_in, where_salted_domain_hash_is};
use crate::util::StreamManager;

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
    pub fn query_preorder_salted_domain_hash(&self, contract: DataContract, hash: Vec<u8>) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "preorder").map_err(Error::from)?;
        query.limit = 1;
        query.where_clauses = vec![where_salted_domain_hash_is(hash)];
        Ok(query)
    }
    pub fn query_preorder_salted_domain_hashes(&self, contract: DataContract, hashes: Vec<Vec<u8>>) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "preorder").map_err(Error::from)?;
        query.limit = hashes.len() as u32;
        query.where_clauses = vec![where_salted_domain_hash_in(hashes)];
        query.order_by_clauses = vec![order_by_asc_salted_domain_hash()];
        Ok(query)
    }

}

#[ferment_macro::export]
impl SaltedDomainHashesManager {
    pub async fn dpns_documents_for_preorder_salted_domain_hashes(&self, hashes: Vec<Vec<u8>>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            hashes,
            |contract, hashes|
                self.dpns_documents_for_preorder_salted_domain_hashes_using_contract(hashes, contract)).await
    }
    pub async fn dpns_documents_for_preorder_salted_domain_hash(&self, hash: Vec<u8>) -> Result<Option<Document>, Error> {
        self.with_contract(
            SystemDataContract::DPNS,
            hash,
            |contract, hash|
                self.dpns_documents_for_preorder_salted_domain_hash_using_contract(hash, contract)).await
    }
    pub async fn dpns_documents_for_preorder_salted_domain_hashes_using_contract(&self, hashes: Vec<Vec<u8>>, contract: DataContract) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let query = self.query_preorder_salted_domain_hashes(contract, hashes)?;
        Document::fetch_many(self.sdk_ref(), query).await
            .map_err(Error::from)
    }
    pub async fn dpns_documents_for_preorder_salted_domain_hash_using_contract(&self, hash: Vec<u8>, contract: DataContract) -> Result<Option<Document>, Error> {
        let query = self.query_preorder_salted_domain_hash(contract, hash)?;
        Document::fetch(self.sdk_ref(), query).await
            .map_err(Error::from)
    }

}

