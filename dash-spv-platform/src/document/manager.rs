use std::sync::Arc;
use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dash_sdk::{platform::{DocumentQuery, FetchMany}, Sdk};
use dash_sdk::platform::Fetch;
use dpp::data_contract::DataContract;
use dpp::data_contract::accessors::v0::DataContractV0Getters;
use dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dash_sdk::platform::transition::put_document::PutDocument;
use dpp::data_contracts::SystemDataContract;
use dpp::document::{Document, DocumentV0Getters};
use dpp::errors::ProtocolError;
use dpp::identity::identity_public_key::IdentityPublicKey;
use dpp::prelude::{BlockHeight, CoreBlockHeight};
use dpp::util::entropy_generator::{DefaultEntropyGenerator, EntropyGenerator};
use drive::query::{OrderClause, WhereClause, WhereOperator};
use indexmap::IndexMap;
use platform_value::{Identifier, Value};
use platform_version::version::PlatformVersion;
use dash_spv_crypto::network::ChainType;
#[cfg(test)]
use crate::create_test_sdk;
use crate::error::Error;
use crate::signer::CallbackSigner;

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct DocumentsManager {
    pub sdk: Arc<Sdk>,
    pub chain_type: ChainType,
}
// #[ferment_macro::export]
// impl DocumentsManager {
//     pub async fn get_dpns_documents_for_usernames(&self, domain: String) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
//
//     }
//
// }

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
        let entropy = DefaultEntropyGenerator.generate()?;

        document_type
            .create_document_from_data(document.properties().into(), document.owner_id(), block_height, core_block_height, entropy, PlatformVersion::latest())
            .map_err(Error::from)?
            .put_to_platform_and_wait_for_response(&self.sdk, document_type.to_owned_document_type(), entropy, identity_public_key, signer, None)
            // .put_to_platform_and_wait_for_response(&self.sdk, document_type.to_owned_document_type(), entropy, identity_public_key, Arc::new(contract), signer)
            .await
            .map_err(Error::from)

    }

    // pub async fn profiles(&self, document: Document) -> Result<BTreeMap<Identifier, Option<Document>>, Error> {
    //     self.documents_with_query()
    // }
}

#[ferment_macro::export]
impl DocumentsManager {
    pub async fn search_identity_by_name(&self, _name: String) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        // let chain = ChainType::TestNet;
        // let sdk = create_test_sdk(&chain);
        let contract_id = SystemDataContract::DPNS.id();
        // let sdk_arc = Arc::new(sdk);
        let query = DocumentQuery::new_with_data_contract_id(&self.sdk, contract_id, "domain").await?;

        // let domain = "dash";
        // let name = "asdtwotwooct";

        // let doc_manager = DocumentsManager::new(&sdk_arc, chain);

        Document::fetch_many(&self.sdk, query).await.map_err(Error::from)

        // match self.documents_with_query(query.await.unwrap()).await {
        //     Ok(result) => {
        //         println!("Ok: {:?}", result);
        //     }
        //     Err(err) => {
        //         println!("Error: {:?}", err);
        //     }
        // }

    }


    pub async fn incoming_contact_requests(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        match DataContract::fetch(&self.sdk, SystemDataContract::Dashpay.id()).await {
            Ok(Some(contract)) => self.incoming_contact_requests_using_contract(contract, user_id, since, start_after).await,
            Ok(None) => Err(Error::DashSDKError("Contract not found".to_string())),
            Err(e) => Err(Error::from(e))
        }
    }
    pub async fn outgoing_contact_requests(&self, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        match DataContract::fetch(&self.sdk, SystemDataContract::Dashpay.id()).await {
            Ok(Some(contract)) => self.outgoing_contact_requests_using_contract(contract, user_id, since, start_after).await,
            Ok(None) => Err(Error::DashSDKError("Contract not found".to_string())),
            Err(e) => Err(Error::from(e))
        }
    }
    pub async fn incoming_contact_requests_using_contract(&self, contract: DataContract, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "contactRequest").map_err(Error::from)?;
        query.limit = 100;
        query.start = start_after.map(Start::StartAfter);
        query.where_clauses = vec![
            WhereClause { field: "toUserId".to_string(), operator: WhereOperator::Equal, value: Value::Identifier(user_id) },
            WhereClause { field: "$createdAt".to_string(), operator: WhereOperator::GreaterThanOrEquals, value: Value::U64(since) }
        ];
        query.order_by_clauses = vec![OrderClause {
            field: "$createdAt".to_string(),
            ascending: true,
        }];
        Document::fetch_many(&self.sdk, query).await.map_err(Error::from)
    }
    pub async fn outgoing_contact_requests_using_contract(&self, contract: DataContract, user_id: [u8; 32], since: u64, start_after: Option<Vec<u8>>) -> Result<IndexMap<Identifier, Option<Document>>, Error> {
        let mut query = DocumentQuery::new(Arc::new(contract), "contactRequest").map_err(Error::from)?;
        query.limit = 100;
        query.start = start_after.map(Start::StartAfter);
        query.where_clauses = vec![
            WhereClause { field: "$ownerId".to_string(), operator: WhereOperator::Equal, value: Value::Identifier(user_id) },
            WhereClause { field: "$createdAt".to_string(), operator: WhereOperator::GreaterThanOrEquals, value: Value::U64(since) }
        ];
        query.order_by_clauses = vec![OrderClause {
            field: "$createdAt".to_string(),
            ascending: true,
        }];
        Document::fetch_many(&self.sdk, query).await.map_err(Error::from)
    }
}
