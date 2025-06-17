use crate::entities::account::AccountEntity;
use crate::entities::address::AddressEntity;
use crate::entities::chain::ChainEntity;
use crate::entities::friend_request::FriendRequestEntity;
use crate::entities::identity_key_path::IdentityKeyPathEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct DerivationPathEntity {
    pub derivation_path: Vec<u8>,
    pub public_key_identifier: String,
    pub sync_block_height: i32,
    // Relationships
    pub account: Option<AccountEntity>,
    pub addresses: Vec<AddressEntity>,
    pub chain: Option<ChainEntity>,
    pub friend_request: Option<Box<FriendRequestEntity>>,
    pub identity_key_paths: Vec<IdentityKeyPathEntity>,
}
