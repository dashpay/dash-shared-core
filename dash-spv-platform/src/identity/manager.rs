use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use dpp::identity::Identity;
use dash_sdk::platform::Fetch;
use dash_sdk::platform::types::identity::PublicKeyHash;
use dash_sdk::Sdk;
use platform_value::Identifier;
use dash_spv_crypto::derivation::{IIndexPath, IndexPath, BIP32_HARD};
use dash_spv_crypto::hashes::{hash160, Hash};
use dash_spv_crypto::keys::{ECDSAKey, IKey};
use crate::error::Error;
use crate::util::{RetryStrategy, StreamSpec, StreamStrategy, Validator};

#[ferment_macro::export]
pub enum IdentityMonitorValidator {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}
impl IdentityMonitorValidator {
    pub fn accept_not_found(&self) -> bool {
        match self {
            IdentityMonitorValidator::None => false,
            IdentityMonitorValidator::AcceptNotFoundAsNotAnError => true
        }
    }
}
impl Validator<Option<Identity>> for IdentityMonitorValidator {
    fn validate(&self, value: &Option<Identity>) -> bool {
        value.is_some() || value.is_none() && self.accept_not_found()
    }
}

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct IdentitiesManager {
    pub sdk: Arc<Sdk>,
    pub foreign_identities: HashMap<Identifier, Identity>,
}

impl StreamSpec for IdentityMonitorValidator {
    type Validator = IdentityMonitorValidator;
    type Result = Option<Identity>;
    type Error = dash_sdk::Error;
}

const KEYS_TO_CHECK: u32 = 5;

#[ferment_macro::export]
impl IdentitiesManager {

    // pub async fn fetch_by_name(&self, username: String, domain: String, contract_id: Identifier) -> Result<Option<Identity>, Error> {
    //     // platformDocumentsRequest.pathPredicate = [NSPredicate predicateWithFormat:@"normalizedParentDomainName == %@", [domain lowercaseString]];
    //     // platformDocumentsRequest.predicate = [NSPredicate predicateWithFormat:@"normalizedLabel == %@", [username lowercaseString]];
    //     match DataContract::fetch_by_identifier(&self.sdk, contract_id).await? {
    //         Some(contract) => {},
    //         None => Ok(None)
    //     }
    // }
    pub async fn fetch_by_id(&self, id: Identifier) -> Result<Option<Identity>, Error> {
        Identity::fetch_by_identifier(&self.sdk, id).await.map_err(Error::from)
    }
    pub async fn fetch_by_key_hash(&self, key_hash: PublicKeyHash) -> Result<Option<Identity>, Error> {
        Identity::fetch(&self.sdk, key_hash).await.map_err(Error::from)
    }
    pub async fn fetch_balance(&self, id: Identifier) -> Result<Option<u64>, Error> {
        u64::fetch_by_identifier(&self.sdk, id).await.map_err(Error::from)
    }
    pub async fn get_identities_by_pub_key_hashes_at_index_range(&self, extended_public_key: &ECDSAKey, unused_index: u32) -> Result<BTreeMap<u32, Identity>, Error> {
        let mut identities = BTreeMap::new();
        for i in unused_index..KEYS_TO_CHECK {
            let index_path = IndexPath::<u32>::new([i | BIP32_HARD, 0 | BIP32_HARD].to_vec());
            let index_key = ECDSAKey::public_key_from_extended_public_key_data_at_index_path(extended_public_key, &index_path)
                .map_err(Error::KeyError)?;
            let pub_key_data = index_key.public_key_data();
            if let Some(identity) = Identity::fetch(&self.sdk, PublicKeyHash(hash160::Hash::hash(&pub_key_data).into_inner()))
                .await? {
                identities.insert(i, identity);
            }
        }
        Ok(identities)
    }

    pub async fn identity_monitor(&self, unique_id: Identifier, retry: RetryStrategy, options: IdentityMonitorValidator) -> Result<Option<Identity>, Error> {
        self.identity_stream::<IdentityMonitorValidator>(unique_id, retry, options).await
    }
}
impl IdentitiesManager {
    pub fn new(sdk: &Arc<Sdk>) -> Self {
        Self { foreign_identities: HashMap::new(), sdk: Arc::clone(sdk) }
    }
    pub async fn identity_stream<SPEC>(
        &self,
        unique_id: Identifier,
        retry: RetryStrategy,
        validator: SPEC::Validator,
    ) -> Result<SPEC::Result, Error>
    where SPEC: StreamSpec<Result=Option<Identity>, Error=dash_sdk::Error> {
        StreamStrategy::<SPEC>::with_retry(retry)
            .with_validator(validator)
            .on_max_retries_reached(dash_sdk::Error::Generic("Max retry reached".to_string()))
            .stream(|| async { Identity::fetch_by_identifier(&self.sdk, unique_id).await })
            .await
            .map_err(Error::from)
    }

}
