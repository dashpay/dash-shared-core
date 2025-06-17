use crate::entities::chain::ChainEntity;
use crate::entities::friend_request::FriendRequestEntity;
use crate::entities::identity::IdentityEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct DashpayUserEntity {
    pub avatar_fingerprint: Vec<u8>,
    pub avatar_hash: Vec<u8>,
    pub avatar_path: String,
    pub created_at: i64,
    pub display_name: String,
    pub document_identifier: Vec<u8>,
    pub local_profile_document_index: i32,
    pub original_entropy_data: Vec<u8>,
    pub public_message: String,
    pub remote_profile_document_index: i32,
    pub updated_at: i64,
    // Relationships
    pub associated_blockchain_identity: Option<IdentityEntity>,
    pub chain: Option<ChainEntity>,
    pub friends: Vec<DashpayUserEntity>,
    pub incoming_requests: Vec<FriendRequestEntity>,
    pub outgoing_requests: Vec<FriendRequestEntity>,
}
