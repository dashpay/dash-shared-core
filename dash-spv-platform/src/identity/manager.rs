use std::collections::HashMap;
use dash_sdk::platform::Identity;
use platform_value::Identifier;

#[derive(Clone)]
pub struct IdentityManager {
    // pub queue: dispatch_queue_attr_t,
    pub foreign_identities: HashMap<Identifier, Identity>,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self { foreign_identities: HashMap::new() }
    }

    // pub async fn get_identity_by_id(user_id: Identifier) -> Result<Identity>
    // - (id<DSDAPINetworkServiceRequest>)getIdentityById:(NSData *)userId
    // completionQueue:(dispatch_queue_t)completionQueue
    // success:(void (^)(NSDictionary *blockchainIdentity))success
    // failure:(void (^)(NSError *error))failure {
}