use dash_sdk::Error;
use dash_sdk::platform::{Identity, Fetch};
use dash_sdk::platform::types::identity::PublicKeyHash;
use platform_value::Identifier;
use crate::PlatformSDK;

// pub struct IdentitiesManager {
//     pub foreign_identities: HashMap<Identifier, Identity>
// }

impl PlatformSDK  {

    pub async fn fetch_identity_by_id(&self, id: Identifier) -> Result<Option<Identity>, Error> {
        Identity::fetch_by_identifier(self.sdk_ref(), id).await
    }
    pub async fn fetch_identity_by_key_hash(&self, key_hash: PublicKeyHash) -> Result<Option<Identity>, Error> {
        Identity::fetch(self.sdk_ref(), key_hash).await
    }

    pub async fn fetch_identity_balance(&self, id: Identifier) -> Result<Option<u64>, Error> {
        u64::fetch_by_identifier(self.sdk_ref(), id).await
    }
}