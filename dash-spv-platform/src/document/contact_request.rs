use std::os::raw::c_void;
use std::sync::Arc;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::platform::DocumentQuery;
use dash_sdk::Sdk;
use dash_spv_macro::StreamManager;
use dpp::data_contract::DataContract;
use dpp::data_contracts::SystemDataContract;
use dpp::document::Document;
use drive_proof_verifier::types::Documents;
use dash_spv_crypto::network::ChainType;
use drive_proof_verifier::types::RetrievedObjects;
use indexmap::IndexMap;
use platform_value::Identifier;
use crate::error::Error;
use crate::identity::model::IdentityModel;
use crate::models::contact_request::{ContactRequest, ContactRequestKind};
use crate::query::{order_by_asc_created_at, where_created_since, where_owner_is, where_recipient_is};
use crate::util::{RetryStrategy, StreamManager, StreamSettings, StreamSpec, Validator};

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum ContactRequestValidator {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}
impl ContactRequestValidator {
    pub fn accept_not_found(&self) -> bool {
        match self {
            ContactRequestValidator::None => false,
            ContactRequestValidator::AcceptNotFoundAsNotAnError => true
        }
    }
}
impl Validator<Option<Document>> for ContactRequestValidator {
    fn validate(&self, value: &Option<Document>) -> bool {
        value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl Validator<RetrievedObjects<Identifier, Document>> for ContactRequestValidator {
    fn validate(&self, _value: &RetrievedObjects<Identifier, Document>) -> bool {
        true
        // value.is_some() || value.is_none() && self.accept_not_found()
    }
}
impl StreamSpec for ContactRequestValidator {
    type Validator = ContactRequestValidator;
    type Error = dash_sdk::Error;
    type Result = Option<Document>;
    type ResultMany = IndexMap<Identifier, Option<Document>>;
}

#[derive(Clone, StreamManager)]
#[ferment_macro::opaque]
pub struct ContactRequestManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
    // pub has_contact_request_with_id: Arc<dyn Fn(/*context*/*const c_void, /*direction*/ bool, /*identifier*/[u8; 32], /*storage_context*/*const c_void) -> bool>,
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
        self.many_documents_with_query(query).await
            .map(|docs| process_contact_requests(&user_id, docs))
    }
    pub async fn outgoing_contact_requests_using_contract(&self, contract: DataContract, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<Vec<ContactRequestKind>, Error> {
        let query = self.query_outgoing_contact_requests(contract, user_id, since, start_after)?;
        self.many_documents_with_query(query).await
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



    pub async fn stream_incoming_contact_requests(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>, retry: RetryStrategy, options: ContactRequestValidator, delay: u64) -> Result<Vec<ContactRequestKind>, Error> {
        self.with_contract(
            SystemDataContract::Dashpay,
            (user_id, since, start_after, retry, options, delay),
            |contract, (user_id, since, start_after, retry, options, delay)|
                self.stream_incoming_contact_requests_with_contract(user_id, since, start_after, contract, retry, options, delay)).await
    }
    pub async fn stream_incoming_contact_requests_with_contract(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>, contract: DataContract, retry: RetryStrategy, options: ContactRequestValidator, delay: u64) -> Result<Vec<ContactRequestKind>, Error> {
        let query = self.query_incoming_contact_requests(contract, user_id, since, start_after)?;
        self.stream_many_with_settings::<ContactRequestValidator, Document, DocumentQuery>(query, retry, StreamSettings::default_with_delay(delay), options).await
            .map(|docs| process_contact_requests(&user_id, docs))
    }

    pub async fn stream_outgoing_contact_requests(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>, retry: RetryStrategy, options: ContactRequestValidator, delay: u64) -> Result<Vec<ContactRequestKind>, Error> {
        self.with_contract(
            SystemDataContract::Dashpay,
            (user_id, since, start_after, retry, options, delay),
            |contract, (user_id, since, start_after, retry, options, delay)|
                self.stream_outgoing_contact_requests_with_contract(user_id, since, start_after, contract, retry, options, delay)).await
    }
    pub async fn stream_outgoing_contact_requests_with_contract(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>, contract: DataContract, retry: RetryStrategy, options: ContactRequestValidator, delay: u64) -> Result<Vec<ContactRequestKind>, Error> {
        let query = self.query_outgoing_contact_requests(contract, user_id, since, start_after)?;
        self.stream_many_with_settings::<ContactRequestValidator, Document, DocumentQuery>(query, retry, StreamSettings::default_with_delay(delay), options).await
            .map(|docs| process_contact_requests(&user_id, docs))
    }

    pub async fn fetch_incoming_contact_requests_in_context<
        HasContactRequestWithId: Fn(/*context*/*const c_void, /*direction*/ bool, /*identifier*/[u8; 32], /*storage_context*/*const c_void) -> bool + Send + Sync + 'static
    >(
        &self,
        model: &mut IdentityModel,
        contract: DataContract,
        since: u64,
        start_after: Option<Vec<u8>>,
        storage_context: *const c_void,
        context: *const c_void,
        has_contact_request_with_id: HasContactRequestWithId,
    ) ->Result<Vec<ContactRequest>, Error> {
        let result = self.stream_incoming_contact_requests_with_contract(model.unique_id, since, start_after, contract, RetryStrategy::Linear(5), ContactRequestValidator::None, 1000).await?;
        let mut contact_requests = Vec::new();
        for contact_request in result {
            match contact_request {
                ContactRequestKind::Incoming(request) => {
                    if !has_contact_request_with_id(context, true, request.owner_id, storage_context) {
                        contact_requests.push(request);
                    }
                },
                ContactRequestKind::Outgoing(_) => {},
            }
        }
        Ok(contact_requests)
    }
    pub async fn fetch_outgoing_contact_requests_in_context<
        HasContactRequestWithId: Fn(/*context*/*const c_void, /*direction*/ bool, /*identifier*/[u8; 32], /*storage_context*/*const c_void) -> bool + Send + Sync + 'static
    >(
        &self,
        model: &mut IdentityModel,
        data_contract: DataContract,
        since: u64,
        start_after: Option<Vec<u8>>,
        storage_context: *const c_void,
        context: *const c_void,
        has_contact_request_with_id: HasContactRequestWithId,
    ) -> Result<Vec<ContactRequest>, Error> {
        let result = self.stream_outgoing_contact_requests_with_contract(model.unique_id, since, start_after, data_contract, RetryStrategy::Linear(5), ContactRequestValidator::None, 1000).await?;
        let mut contact_requests = Vec::new();
        for contact_request in result {
            match contact_request {
                ContactRequestKind::Outgoing(request) => {
                    if !has_contact_request_with_id(context, false, request.recipient, storage_context) {
                        contact_requests.push(request);
                    }
                },
                ContactRequestKind::Incoming(_) => {},
            }
        }
        Ok(contact_requests)
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

#[ferment_macro::export]
pub fn as_incoming_request(kind: ContactRequestKind) -> Option<ContactRequest> {
    match kind {
        ContactRequestKind::Incoming(request) => Some(request),
        _ => None
    }
}
#[ferment_macro::export]
pub fn as_outgoing_request(kind: ContactRequestKind) -> Option<ContactRequest> {
    match kind {
        ContactRequestKind::Outgoing(request) => Some(request),
        _ => None
    }
}
