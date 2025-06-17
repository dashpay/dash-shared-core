use crate::entities::asset_lock_transaction::AssetLockTransactionEntity;
use crate::entities::chain::ChainEntity;
use crate::entities::dashpay_user::DashpayUserEntity;
use crate::entities::identity_username::IdentityUsernameEntity;
use crate::entities::invitation::InvitationEntity;
use crate::entities::key_info::KeyInfoEntity;

// #[derive(Clone, Debug)]
// #[ferment_macro::export]
// pub struct IdentityEntity {
//     pub unique_id: [u8; 32],
//     pub is_local: bool,
//     pub registration_status: u8,
//     pub credit_balance: u64,
//     pub sync_block_hash: [u8; 32],
//     pub key_infos: BTreeMap<u32, KeyInfoEntity>,
//     pub username_infos: Vec<UsernameStatusInfo>,
//
//     pub last_checked_usernames_timestamp: u64,
//     pub last_checked_profile_timestamp: u64,
//     pub last_checked_incoming_contacts_timestamp: u64,
//     pub last_checked_outgoing_contacts_timestamp: u64,
//
//     pub registration_funding_transaction: Option<AssetLockTransactionEntity>,
// }
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct IdentityEntity {
    pub credit_balance: u64,
    pub dashpay_synchronization_block_hash: [u8; 32],
    pub is_local: bool,
    pub last_checked_incoming_friends: u64,
    pub last_checked_outgoing_friends: u64,
    pub last_checked_profiles: u64,
    pub last_checked_usernames: u64,
    pub registration_status: u8,
    pub unique_id: [u8; 32],

    pub key_paths: Vec<KeyInfoEntity>,
    pub top_up_funding_transactions: Vec<AssetLockTransactionEntity>,
    pub registration_funding_transaction: Option<AssetLockTransactionEntity>,
    pub matching_dashpay_user: Option<Box<DashpayUserEntity>>,
    pub associated_invitation: Option<Box<InvitationEntity>>,
    pub usernames: Vec<IdentityUsernameEntity>,
    pub chain: Option<ChainEntity>,
    pub dashpay_username: Option<Box<IdentityUsernameEntity>>,
}
