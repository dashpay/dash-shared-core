use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use platform_value::Identifier;
use crate::models::transient_dashpay_user::TransientDashPayUser;

#[derive(Default)]
#[ferment_macro::opaque]
pub struct PlatformCache {
    pub user_profiles: Arc<RwLock<BTreeMap<Identifier, TransientDashPayUser>>>,
    // pub identities: Arc<RwLock<BTreeMap<>>>
}