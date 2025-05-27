use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::Error;
use dash_sdk::platform::DocumentQuery;
use dpp::data_contract::DataContract;
use drive::query::{OrderClause, WhereClause, WhereOperator};
use platform_value::{Identifier, Value};

pub enum WhereKind<'a> {
    RecordIdentityIsEqualTo(Identifier),
    LabelStartsWith(&'a str),
    DomainIsDash,
    Usernames(&'a [&'a str])
}
pub enum OrderKind {
    LabelAsc
}
pub enum QueryKind<'a> {
    Generic {
        contract: DataContract,
        document_type: &'a str,
        where_clauses: Vec<WhereClause>,
        order_clauses: Vec<OrderClause>,
        limit: u32,
        start: Option<Start>,
    },
    RecordsIdentity {
        contract: DataContract,
        document_type: &'a str,
        unique_id: Identifier,
    },
    DPNSDomain {
        contract: DataContract,
        document_type: &'a str,
        starts_with: &'a str,
    },
    Usernames {
        contract: DataContract,
        document_type: &'a str,
        usernames: &'a [&'a str],
    },
    IncomingContactRequests {
        contract: DataContract,
        document_type: &'a str,
    },
    OutgoingContactRequests {
        contract: DataContract,
        document_type: &'a str,
    }
}

impl<'a> Into<WhereClause> for WhereKind<'a> {
    fn into(self) -> WhereClause {
        match self {
            WhereKind::RecordIdentityIsEqualTo(unique_id) => WhereClause {
                field: "records.identity".to_string(),
                operator: WhereOperator::Equal,
                value: Value::from(unique_id),
            },
            WhereKind::LabelStartsWith(text) => WhereClause {
                field: "normalizedLabel".to_string(),
                operator: WhereOperator::StartsWith,
                value: Value::Text(text.to_string())
            },
            WhereKind::DomainIsDash => WhereClause {
                field: "normalizedParentDomainName".to_string(),
                operator: WhereOperator::Equal,
                value: Value::Text("dash".to_string())
            },
            WhereKind::Usernames(usernames) => WhereClause {
                field: "normalizedLabel".to_string(),
                operator: WhereOperator::Between,
                value: Value::Array(Vec::from_iter(usernames.iter().map(|username| Value::Text(username.to_string())))),
            }
        }
    }
}

impl Into<OrderClause> for OrderKind {
    fn into(self) -> OrderClause {
        match self {
            OrderKind::LabelAsc => OrderClause {
                field: "normalizedLabel".to_string(),
                ascending: true
            }
        }
    }
}

impl<'a> Into<Result<DocumentQuery, Error>> for QueryKind<'a> {
    fn into(self) -> Result<DocumentQuery, Error> {
        match self {
            QueryKind::Generic { contract, document_type, where_clauses, order_clauses, limit, start } =>
                DocumentQuery::new(contract, document_type)
                    .map(|mut query| {
                        query.where_clauses.extend(where_clauses);
                        query.order_by_clauses.extend(order_clauses);
                        query.limit = limit;
                        query.start = start;
                        query
                    }),
            QueryKind::RecordsIdentity { contract, document_type, unique_id } =>
                DocumentQuery::new(contract, document_type)
                    .map(|query| query.with_where(WhereKind::RecordIdentityIsEqualTo(unique_id).into())),
            QueryKind::DPNSDomain { contract, document_type, starts_with } =>
                DocumentQuery::new(contract, document_type)
                    .map(|query|
                        query.with_where(WhereKind::LabelStartsWith(starts_with).into())
                            .with_where(WhereKind::DomainIsDash.into())
                            .with_order_by(OrderKind::LabelAsc.into())),
            QueryKind::Usernames { contract, document_type, usernames } =>
                DocumentQuery::new(contract, document_type)
                    .map(|mut query| {
                        query.limit = usernames.len() as u32;
                        query.with_where(WhereKind::Usernames(usernames).into())
                            .with_order_by(OrderKind::LabelAsc.into())
                    }),
            QueryKind::IncomingContactRequests { contract, document_type } =>
                DocumentQuery::new(contract, document_type)
                    .map(|query| query.into()),
            QueryKind::OutgoingContactRequests { contract, document_type } =>
                DocumentQuery::new(contract, document_type)
                    .map(|query| query.into())
        }
    }
}

impl<'a> QueryKind<'a> {
    pub fn dpns_domain(contract: DataContract, document_type: &'a str, starts_with: &'a str) -> Result<DocumentQuery, Error> {
        QueryKind::DPNSDomain { contract, document_type, starts_with }.into()
    }
    pub fn records_identity(contract: DataContract, document_type: &'a str, unique_id: Identifier) -> Result<DocumentQuery, Error> {
        QueryKind::RecordsIdentity { contract, document_type, unique_id }.into()
    }
    pub fn usernames(contract: DataContract, document_type: &'a str, usernames: &[&'a str]) -> Result<DocumentQuery, Error> {
        QueryKind::Usernames {
            contract,
            document_type,
            usernames
        }.into()
    }
    pub fn generic(contract: DataContract, document_type: &'a str, where_clauses: Vec<WhereClause>, order_clauses: Vec<OrderClause>, limit: u32, start: Option<Start>) -> Result<DocumentQuery, Error> {
        QueryKind::Generic { contract, document_type, where_clauses, order_clauses, limit, start }.into()
    }
    pub fn outgoing_contact_requests(contract: DataContract, document_type: &'a str) -> Result<DocumentQuery, Error> {
        QueryKind::OutgoingContactRequests { contract, document_type }.into()
    }
}


pub fn order_by_asc_normalized_label() -> OrderClause {
    OrderClause { field: "normalizedLabel".to_string(), ascending: true }
}
pub fn order_by_asc_created_at() -> OrderClause {
    OrderClause { field: "$createdAt".to_string(), ascending: true }
}
pub fn order_by_asc_owner_id() -> OrderClause {
    OrderClause { field: "$ownerId".to_string(), ascending: true }
}
pub fn order_by_asc_salted_domain_hash() -> OrderClause {
    OrderClause { field: "saltedDomainHash".to_string(), ascending: true }
}


pub fn where_owner_is(user_id: [u8; 32]) -> WhereClause {
    WhereClause { field: "$ownerId".to_string(), operator: WhereOperator::Equal, value: Value::Identifier(user_id) }
}
pub fn where_owner_in(user_ids: Vec<[u8; 32]>) -> WhereClause {
    WhereClause { field: "$ownerId".to_string(), operator: WhereOperator::In, value: Value::Array(Vec::from_iter(user_ids.into_iter().map(|user_id| Value::Identifier(user_id)))) }
}
pub fn where_created_since(time: u64) -> WhereClause {
    WhereClause { field: "$createdAt".to_string(), operator: WhereOperator::GreaterThanOrEquals, value: Value::U64(time) }
}
pub fn where_normalized_label_equal_to(username: String) -> WhereClause {
    WhereClause { field: "normalizedLabel".to_string(), operator: WhereOperator::Equal, value: Value::Text(username) }
}
pub fn where_normalized_label_in(usernames: Vec<String>) -> WhereClause {
    WhereClause { field: "normalizedLabel".to_string(), operator: WhereOperator::In, value: Value::Array(usernames.into_iter().map(|u| Value::Text(u.to_lowercase())).collect()) }
}
pub fn where_normalized_label_starts_with(prefix: String) -> WhereClause {
    WhereClause { field: "normalizedLabel".to_string(), operator: WhereOperator::StartsWith, value: Value::Text(prefix) }
}
pub fn where_domain_is_dash() -> WhereClause {
    WhereClause { field: "normalizedParentDomainName".to_string(), operator: WhereOperator::Equal, value: Value::Text("dash".to_string()) }
}
pub fn where_domain_is(domain: String) -> WhereClause {
    WhereClause { field: "normalizedParentDomainName".to_string(), operator: WhereOperator::Equal, value: Value::Text(domain) }
}
pub fn where_recipient_is(user_id: [u8; 32]) -> WhereClause {
    WhereClause { field: "toUserId".to_string(), operator: WhereOperator::Equal, value: Value::Identifier(user_id) }
}
pub fn where_records_identity_is(user_id: [u8; 32]) -> WhereClause {
    WhereClause { field: "records.identity".to_string(), operator: WhereOperator::Equal, value: Value::Identifier(user_id) }
}
pub fn where_salted_domain_hash_is(hash: [u8; 32]) -> WhereClause {
    WhereClause { field: "saltedDomainHash".to_string(), operator: WhereOperator::Equal, value: Value::Bytes32(hash) }
}
pub fn where_salted_domain_hash_in(hashes: Vec<[u8; 32]>) -> WhereClause {
    WhereClause { field: "saltedDomainHash".to_string(), operator: WhereOperator::In, value: Value::Array(hashes.into_iter().map(|hash| Value::Bytes32(hash)).collect()) }
}
