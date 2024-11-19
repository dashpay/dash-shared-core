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
use crate::util::Retry;

#[ferment_macro::export]
pub enum IdentityMonitorOptions {
    None = 0,
    AcceptNotFoundAsNotAnError = 1,
}
impl IdentityMonitorOptions {
    pub fn accept_not_found(&self) -> bool {
        match self {
            IdentityMonitorOptions::None => false,
            IdentityMonitorOptions::AcceptNotFoundAsNotAnError => true
        }
    }
}

// type ResultCallback = Box<dyn Fn(Result<Identity, Error>) + Send + Sync>;


#[derive(Clone)]
#[ferment_macro::opaque]
pub struct IdentitiesManager {
    pub sdk: Arc<Sdk>,
    // pub queue: dispatch_queue_attr_t,
    pub foreign_identities: HashMap<Identifier, Identity>,
}
const KEYS_TO_CHECK: u32 = 5;

#[ferment_macro::export]
impl IdentitiesManager {
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
    pub async fn identity_monitor(
        &self,
        unique_id: Identifier,
        retry: Retry,
        options: IdentityMonitorOptions,
    ) -> Result<Option<Identity>, Error> {
        match retry.perform(|| async { Identity::fetch_by_identifier(&self.sdk, unique_id).await }).await {
            Ok(Some(identity)) => Ok(Some(identity)),
            Ok(None) if matches!(options, IdentityMonitorOptions::AcceptNotFoundAsNotAnError) => Ok(None),
            Ok(None) => Err(Error::Any(500, "Platform returned no identity when one was expected".to_string())),
            Err(err) => Err(Error::MaxRetryExceeded(err.to_string())),
        }
    }

}
impl IdentitiesManager {
    pub fn new(sdk: &Arc<Sdk>) -> Self {
        Self { foreign_identities: HashMap::new(), sdk: Arc::clone(sdk) }
    }

    // pub async fn identity_monitor<T>(
    //     &self,
    //     unique_id: Identifier,
    //     retry: Retry,
    //     options: IdentityMonitorOptions,
    //     completion: Box<T>,
    // ) where T: Fn(Result<Option<Identity>, Error>) + Send + Sync {
    //     let result = match retry.perform(|| async { Identity::fetch_by_identifier(&self.sdk, unique_id).await }).await {
    //         Ok(Some(identity)) => Ok(Some(identity)),
    //         Ok(None) if matches!(options, IdentityMonitorOptions::AcceptNotFoundAsNotAnError) => Ok(None),
    //         Ok(None) => Err(Error::Any(500, "Platform returned no identity when one was expected".to_string())),
    //         Err(err) => Err(Error::MaxRetryExceeded(err.to_string())),
    //     };
    //     completion(result)
    // }
}
