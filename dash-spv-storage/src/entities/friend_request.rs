use crate::entities::account::AccountEntity;
use crate::entities::dashpay_user::DashpayUserEntity;
use crate::entities::derivation_path::DerivationPathEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct FriendRequestEntity {
    pub destination_key_index: i32,
    pub friendship_identifier: Vec<u8>,
    pub source_key_index: i32,
    pub timestamp: i64,
    // Relationships
    pub account: Option<AccountEntity>,
    pub derivation_path: Option<DerivationPathEntity>,
    pub destination_contact: Option<DashpayUserEntity>,
    pub source_contact: Option<DashpayUserEntity>,
}
