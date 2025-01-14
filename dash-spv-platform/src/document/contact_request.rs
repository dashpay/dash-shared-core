use std::sync::Arc;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::platform::{DocumentQuery, FetchMany};
use dash_sdk::Sdk;
use dash_spv_macro::StreamManager;
use dpp::data_contract::DataContract;
use dpp::data_contracts::SystemDataContract;
use dpp::document::Document;
use drive_proof_verifier::types::Documents;
use dash_spv_crypto::network::ChainType;
use crate::error::Error;
use crate::models::contact_request::{ContactRequest, ContactRequestKind};
use crate::query::{order_by_asc_created_at, where_created_since, where_owner_is, where_recipient_is};
use crate::util::StreamManager;

#[derive(Clone, Debug, StreamManager)]
#[ferment_macro::opaque]
pub struct ContactRequestManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
}

impl ContactRequestManager {
    pub fn new(sdk: &Arc<Sdk>, chain_type: ChainType) -> Self {
        Self { sdk: Arc::clone(sdk), chain_type }
    }
    pub fn query_incoming_contact_requests(&self, contract: DataContract, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "contactRequest").map_err(Error::from)?;
        query.limit = 100;
        query.start = start_after.map(Start::StartAfter);
        query.where_clauses = vec![
            where_recipient_is(user_id),
            where_created_since(since)
        ];
        query.order_by_clauses = vec![order_by_asc_created_at()];
        Ok(query)
    }
    pub fn query_outgoing_contact_requests(&self, contract: DataContract, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<DocumentQuery, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "contactRequest").map_err(Error::from)?;
        query.limit = 100;
        query.start = start_after.map(Start::StartAfter);
        query.where_clauses = vec![
            where_owner_is(user_id),
            where_created_since(since)
        ];
        query.order_by_clauses = vec![order_by_asc_created_at()];
        Ok(query)
    }
}

#[ferment_macro::export]
impl ContactRequestManager {
    pub async fn incoming_contact_requests_using_contract(&self, contract: DataContract, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<Vec<ContactRequestKind>, Error> {
        let query = self.query_incoming_contact_requests(contract, user_id, since, start_after)?;
        Document::fetch_many(self.sdk_ref(), query).await
            .map_err(Error::from)
            .map(|docs| process_contact_requests(&user_id, docs))
    }
    pub async fn outgoing_contact_requests_using_contract(&self, contract: DataContract, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<Vec<ContactRequestKind>, Error> {
        let query = self.query_outgoing_contact_requests(contract, user_id, since, start_after)?;
        Document::fetch_many(self.sdk_ref(), query).await
            .map_err(Error::from)
            .map(|docs| process_contact_requests(&user_id, docs))
    }
    pub async fn incoming_contact_requests(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<Vec<ContactRequestKind>, Error> {
        self.with_contract(
            SystemDataContract::Dashpay,
            (user_id, since, start_after),
            |contract, (user_id, since, start_after)|
                self.incoming_contact_requests_using_contract(contract, user_id, since, start_after)).await
    }
    pub async fn outgoing_contact_requests(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<Vec<ContactRequestKind>, Error> {
        self.with_contract(
            SystemDataContract::Dashpay,
            (user_id, since, start_after),
            |contract, (user_id, since, start_after)|
                self.outgoing_contact_requests_using_contract(contract, user_id, since, start_after)).await
    }
}

fn process_contact_requests(user_id: &[u8; 32], documents: Documents) -> Vec<ContactRequestKind> {
    Vec::from_iter(documents.into_iter().filter_map(|(_, doc)| {
        if let Some(doc) = doc {
            if let Ok(contact_request) = ContactRequest::try_from(doc) {
                return Some(if contact_request.recipient.eq(user_id) {
                    ContactRequestKind::Incoming(contact_request)
                } else {
                    ContactRequestKind::Outgoing(contact_request)
                })
            }
        }
        None
    }))
}

