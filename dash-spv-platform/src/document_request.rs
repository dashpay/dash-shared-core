use std::collections::BTreeMap;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::Error;
use dash_sdk::platform::{Document, DocumentQuery, FetchMany};
use drive::query::{OrderClause, conditions::WhereClause, WhereOperator};
use platform_value::{Identifier, Value};
use crate::PlatformSDK;


// pub type DocumentQueryBuilder<T> = dyn Fn(T) -> DocumentQuery;

// fn document_query(
//     document_type: &str,
//     data_contract: DataContract,
//     where_clauses: Vec<WhereClause>,
//     order_clauses: Vec<OrderClause>,
//     limit: u32,
//     start: Option<Start>
// ) -> Result<DocumentQuery, Error> {
//     Ok(query)
// }

impl PlatformSDK {
    pub async fn documents_with_query(&self, query: DocumentQuery) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        Document::fetch_many(self.sdk_ref(), query).await
    }

    // pub async fn documents_with_contract_and_query_builder<T>(&self, params: T, query_builder: Box<DocumentQueryBuilder<T>>) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
    //     self.documents_with_query(query_builder(params)).await
    // }

    pub async fn fetch_documents(
        &self,
        contract_id: Identifier,
        document_type: &str,
        where_clauses: Vec<WhereClause>,
        order_clauses: Vec<OrderClause>,
        limit: u32,
        start: Option<Start>
    ) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        match self.fetch_contract_by_id(contract_id).await? {
            Some(contract) => {
                let mut query = DocumentQuery::new(contract, document_type)?;
                query.where_clauses.extend(where_clauses);
                query.order_by_clauses.extend(order_clauses);
                query.limit = limit;
                query.start = start;
                self.documents_with_query(query).await
            },
            None =>
                Err(Error::Config("Contract not exist".to_string())),
        }
    }

    pub async fn dpns_domain_starts_with(&self, starts_with: &str, document_type: &str, contract_id: Identifier) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        match self.fetch_contract_by_id(contract_id).await? {
            None => Err(Error::Config("Contract not exist".to_string())),
            Some(contract) => {
                let mut query = DocumentQuery::new(contract, document_type)?;
                query.where_clauses.push(WhereClause {
                    field: "normalizedLabel".to_string(),
                    operator: WhereOperator::StartsWith,
                    value: Value::Text(starts_with.to_string())
                });
                query.where_clauses.push(WhereClause {
                    field: "normalizedParentDomainName".to_string(),
                    operator: WhereOperator::Equal,
                    value: Value::Text("dash".to_string())
                });
                query.order_by_clauses.push(OrderClause { field: "normalizedLabel".to_string(), ascending: true });
                self.documents_with_query(query).await
            }
        }
    }
    pub async fn dpns_domain_by_id(&self, unique_id: Identifier, document_type: &str, contract_id: Identifier) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
        match self.fetch_contract_by_id(contract_id).await? {
            None => Err(Error::Config("Contract not exist".to_string())),
            Some(contract) => {
                let mut query = DocumentQuery::new(contract, document_type)?;
                query.where_clauses.push(WhereClause {
                    field: "records.identity".to_string(),
                    operator: WhereOperator::Equal,
                    value: Value::from(unique_id),
                });
                self.documents_with_query(query).await
            }
        }

    }
 }