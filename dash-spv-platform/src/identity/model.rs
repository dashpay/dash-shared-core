use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use dashcore::hashes::{sha256d, Hash};
use dashcore::prelude::DisplayHex;
use dpp::document::{Document, DocumentV0Getters};
use dpp::identity::{Identity, IdentityPublicKey, KeyType};
use dpp::identity::accessors::IdentityGettersV0;
use dpp::identity::identity_public_key::purpose::Purpose;
use dpp::identity::identity_public_key::security_level::SecurityLevel;
use dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use platform_value::{Hash256, Identifier, Value, ValueMap};
use dash_spv_chain::TransactionModel;
use dash_spv_crypto::crypto::byte_util::Random;
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::keys::{BLSKey, ECDSAKey, IKey, KeyError, OpaqueKey};
use dash_spv_crypto::network::ChainType;
use dash_spv_crypto::util::base58;
use dash_spv_keychain::IdentityDictionaryItemValue;
use dash_spv_storage::entities::identity::IdentityEntity;
use dash_spv_storage::entities::identity_username::IdentityUsernameEntity;
use dash_spv_storage::entities::key_info::KeyInfoEntity;
use crate::document::usernames::UsernameStatus;
use crate::identity::key_info::KeyInfo;
use crate::identity::key_status::IdentityKeyStatus;
use crate::identity::manager::{identity_public_key, purpose_from_index, purpose_to_index, security_level_from_index, security_level_to_index};
use crate::identity::registration_status::IdentityRegistrationStatus;
use crate::identity::storage::username::SaveUsernameContext;
use crate::identity::username_status_info::UsernameStatusInfo;
use crate::models::transient_dashpay_user::TransientDashPayUser;

pub const DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL: SecurityLevel = SecurityLevel::HIGH;
pub const DEFAULT_PROFILE_REGISTRATION_SECURITY_LEVEL: SecurityLevel = SecurityLevel::HIGH;
pub const DEFAULT_USERNAME_REGISTRATION_PURPOSE: Purpose = Purpose::AUTHENTICATION;
pub const DEFAULT_PROFILE_REGISTRATION_PURPOSE: Purpose = Purpose::AUTHENTICATION;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct AssetLockSubmissionError {
    pub steps_completed: u32,
}

#[derive(Clone, Debug, PartialEq)]
#[ferment_macro::export]
pub enum ContextType {
    Chain(ChainType),
    Wallet(String)
}

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct IdentityModel {
    // pub context: *const c_void,
    pub context_type: ContextType,
    pub identity: Option<Identity>,

    // pub wallet_id: Option<String>,
    // pub invitation_locked_outpoint: Option<[u8; 36]>,

    pub registration_funding_private_key: Option<OpaqueKey>,
    pub topup_funding_private_key: Option<OpaqueKey>,

    pub identity_registration_status: IdentityRegistrationStatus,
    pub key_info_dictionaries: BTreeMap<u32, KeyInfo>,
    pub username_domains: HashMap<String, Vec<u8>>,
    pub username_salts: HashMap<String, [u8; 32]>,
    pub username_statuses: HashMap<String, UsernameStatusInfo>,

    // pub keys_created: u32,
    // pub keys_created: u32,
    pub current_main_index: u32,
    pub current_main_key_type: KeyKind,

    /// This is if the blockchain identity is present in wallets or not.
    /// If false -> blockchain identity is known for example from being a DashPay friend.
    pub is_local: bool,
    // TRUE if the identity is an effemeral identity returned when searching.
    pub is_transient: bool,
    /// Represents the last L1 block hash for which DashPay would be synchronized
    pub sync_block_hash: [u8; 32],
    pub sync_block_height: u32,

    pub last_checked_usernames_timestamp: u64,
    pub last_checked_profile_timestamp: u64,
    pub last_checked_incoming_contacts_timestamp: u64,
    pub last_checked_outgoing_contacts_timestamp: u64,

    pub index: u32,
    pub unique_id: [u8; 32],
    pub credit_balance: u64,

    pub is_outgoing_invitation: bool,
    pub is_from_incoming_invitation: bool,

    pub transient_dashpay_user: Option<TransientDashPayUser>,

    pub locked_outpount: Option<[u8; 36]>,
    pub asset_lock_registration_model: Option<TransactionModel>,
    pub asset_lock_registration_hash: Option<[u8; 32]>,

    pub asset_lock_topup_models: Vec<TransactionModel>,
}

#[ferment_macro::export]
impl IdentityModel {
    pub fn with_asset_lock_transaction(index: u32, transaction: TransactionModel, wallet_id: String) -> IdentityModel {
        Self {
            index,
            unique_id: transaction.credit_burn_identity_identifier(),
            context_type: ContextType::Wallet(wallet_id),
            // context: std::ptr::null(),
            identity_registration_status: IdentityRegistrationStatus::Registered,
            locked_outpount: Some(transaction.locked_outpoint()),
            is_local: false,
            is_transient: false,
            // wallet_id: Some(wallet_id),
            is_outgoing_invitation: true,
            is_from_incoming_invitation: false,


            identity: None,
            registration_funding_private_key: None,
            topup_funding_private_key: None,
            key_info_dictionaries: Default::default(),
            username_domains: Default::default(),
            username_salts: Default::default(),
            username_statuses: Default::default(),
            current_main_index: 0,
            current_main_key_type: KeyKind::ECDSA,
            // invitation_locked_outpoint: None,
            sync_block_hash: [0u8; 32],
            sync_block_height: 0,
            last_checked_usernames_timestamp: 0,
            last_checked_profile_timestamp: 0,
            last_checked_incoming_contacts_timestamp: 0,
            last_checked_outgoing_contacts_timestamp: 0,
            credit_balance: 0,
            transient_dashpay_user: None,
            asset_lock_registration_model: None,
            asset_lock_registration_hash: None,
            asset_lock_topup_models: vec![],
        }

    }
    pub fn with_locked_outpoint(
        index: u32,
        unique_id: [u8; 32],
        locked_outpoint: [u8; 36],
        wallet_id: String,
    ) -> IdentityModel {
        Self {
            index,
            unique_id,
            context_type: ContextType::Wallet(wallet_id),
            // context: std::ptr::null(),
            identity_registration_status: IdentityRegistrationStatus::Registered,
            locked_outpount: Some(locked_outpoint),
            is_local: false,
            is_transient: false,
            // wallet_id: Some(wallet_id),
            is_outgoing_invitation: true,
            is_from_incoming_invitation: false,


            identity: None,
            registration_funding_private_key: None,
            topup_funding_private_key: None,
            key_info_dictionaries: Default::default(),
            username_domains: Default::default(),
            username_salts: Default::default(),
            username_statuses: Default::default(),
            current_main_index: 0,
            current_main_key_type: KeyKind::ECDSA,
            // invitation_locked_outpoint: None,
            sync_block_hash: [0u8; 32],
            sync_block_height: 0,
            last_checked_usernames_timestamp: 0,
            last_checked_profile_timestamp: 0,
            last_checked_incoming_contacts_timestamp: 0,
            last_checked_outgoing_contacts_timestamp: 0,
            credit_balance: 0,
            transient_dashpay_user: None,
            asset_lock_registration_model: None,
            asset_lock_registration_hash: None,
            asset_lock_topup_models: vec![],
        }
    }

    pub fn new_with_index(
        index: u32,
        unique_id: [u8; 32],
        status: IdentityRegistrationStatus,
        is_local: bool,
        is_transient: bool,
        context_type: ContextType,
        // wallet_id: Option<String>,
        // context: *const c_void,
    ) -> IdentityModel {
        Self {
            context_type,
            // context,
            unique_id,
            identity_registration_status: status,
            identity: None,
            locked_outpount: None,
            registration_funding_private_key: None,
            topup_funding_private_key: None,
            key_info_dictionaries: Default::default(),
            username_domains: Default::default(),
            username_salts: Default::default(),
            username_statuses: Default::default(),
            is_local,
            is_transient,
            // wallet_id,
            current_main_index: 0,
            current_main_key_type: KeyKind::ECDSA,
            // invitation_locked_outpoint: None,
            sync_block_hash: [0u8; 32],
            sync_block_height: 0,
            last_checked_usernames_timestamp: 0,
            last_checked_profile_timestamp: 0,
            last_checked_incoming_contacts_timestamp: 0,
            last_checked_outgoing_contacts_timestamp: 0,
            credit_balance: 0,
            index,
            is_outgoing_invitation: false,
            is_from_incoming_invitation: false,
            transient_dashpay_user: None,
            asset_lock_registration_model: None,
            asset_lock_registration_hash: None,
            asset_lock_topup_models: vec![],
        }
    }

    // pub fn with_unique_id(
    //     unique_id: [u8; 32],
    //     is_transient: bool,
    //     chain_type: ChainType,
    // ) -> IdentityModel {
    //     Self::new_with_index(
    //         0,
    //         unique_id,
    //         IdentityRegistrationStatus::Registered,
    //         false,
    //         is_transient,
    //         ContextType::Chain(chain_type),
    //     )
    // }

    pub fn with_index_and_unique_id_and_wallet_id(
        index: u32,
        unique_id: [u8; 32],
        wallet_id: String
    ) -> IdentityModel {
        Self::new_with_index(
            index,
            unique_id,
            IdentityRegistrationStatus::Registered,
            true,
            false,
            ContextType::Wallet(wallet_id),
            // Some(wallet_id)
            // std::ptr::null()
        )
    }

        pub fn with_index(
        index: u32,
        wallet_id: String
        // wallet_context: *const c_void
    ) -> IdentityModel {
        Self::new_with_index(
            index,
            [0u8; 32],
            IdentityRegistrationStatus::Unknown,
            true,
            false,
            ContextType::Wallet(wallet_id),
            // Some(wallet_id)
        )
    }
    pub fn with_index_and_unique_id(
        index: u32,
        unique_id: [u8; 32],
        wallet_id: String,
        // wallet_context: *const c_void
    ) -> IdentityModel {
        Self::new_with_index(
            index,
            unique_id,
            IdentityRegistrationStatus::Registered,
            true,
            false,
            ContextType::Wallet(wallet_id),
            // Some(wallet_id)
            // wallet_context
        )
    }
    // pub fn with_index_and_unique_id_and_entity(
    //     index: u32,
    //     unique_id: [u8; 32],
    //     entity: IdentityEntity,
    //     wallet_id: String
    //     // wallet_context: *const c_void
    // ) -> IdentityModel {
    //     let mut model = Self::with_index_and_unique_id(index, unique_id, wallet_id);
    //     model.apply_identity_entity(entity);
    //     model
    // }

    //     pub fn with_entity(
    //         entity: IdentityEntity,
    //         // chain_context: *const c_void
    //     ) -> IdentityModel {
    //     let mut model = Self::with_unique_id(entity.unique_id, false);
    //     model.apply_identity_entity(entity);
    //     model
    // }

    pub fn with_index_and_locked_outpoint(
        index: u32,
        locked_outpoint: [u8; 36],
        wallet_id: String
        // wallet_context: *const c_void
    ) -> IdentityModel {
        // let outpoint = OutPoint::from(locked_outpoint);
        let unique_id = sha256d::Hash::hash(locked_outpoint.as_slice()).to_byte_array();
        let mut model = Self::with_index_and_unique_id(index, unique_id, wallet_id);
        model.locked_outpount = Some(locked_outpoint);
        model
    }
    // pub fn with_index_and_locked_outpoint_and_entity(
    //     index: u32,
    //     locked_outpoint: [u8; 36],
    //     entity: IdentityEntity,
    //     wallet_id: String
    //     // wallet_context: *const c_void
    // ) -> IdentityModel {
    //     let mut model = Self::with_index_and_locked_outpoint(index, locked_outpoint, wallet_id);
    //     model.apply_identity_entity(entity);
    //     model
    // }

    // pub fn with_index_and_locked_outpoint_and_entity_and_invitation(
    //     index: u32,
    //     locked_outpoint: [u8; 36],
    //     entity: IdentityEntity,
    //     invitation_locked_outpoint: [u8; 36],
    //     wallet_id: String,
    //     // wallet_context: *const c_void
    // ) -> IdentityModel {
    //     let mut model = Self::with_index_and_locked_outpoint(index, locked_outpoint, wallet_id);
    //     model.set_associated_invitation_locked_outpoint(invitation_locked_outpoint, true);
    //     model.apply_identity_entity(entity);
    //     model
    // }

    pub fn with_index_and_asset_lock_transaction_model(
        index: u32,
        transaction_model: TransactionModel,
        wallet_id: String
        // wallet_context: *const c_void
    ) -> IdentityModel {
        let mut locked_outpoint = [0u8; 36];
        locked_outpoint.copy_from_slice(transaction_model.transaction.txid().as_byte_array());
        let mut model = Self::with_index_and_locked_outpoint(index, locked_outpoint, wallet_id);
        model.asset_lock_registration_model = Some(transaction_model);
        model
    }


    pub fn new(
        unique_id: [u8; 32],
        status: IdentityRegistrationStatus,
        is_local: bool,
        is_transient: bool,
        context_type: ContextType,
        // wallet_id: Option<String>,
    ) -> IdentityModel {
        Self::new_with_index(
            0,
            unique_id,
            status,
            is_local,
            is_transient,
            context_type,
            // wallet_id
        )
    }

    // pub fn local_unknown(index: u32, context: *const c_void) -> Self {
    //     Self::new_with_index(
    //         index,
    //         [0u8; 32],
    //         IdentityRegistrationStatus::Unknown,
    //         true,
    //         false,
    //         context,
    //     )
    // }
    // pub fn local_known(index: u32, unique_id: [u8; 32], context: *const c_void) -> Self {
    //     Self::new_with_index(
    //         index,
    //         unique_id,
    //         IdentityRegistrationStatus::Registered,
    //         true,
    //         false,
    //         context,
    //     )
    // }
    //


    pub fn at_index_with_identity(
        index: u32,
        identity: Identity,
        // wallet_id: String,
        context_type: ContextType,
        // context: *const c_void,
    ) -> Self {
        let key_info_dictionaries = identity.public_keys().iter().map(|(key_id, public_key)| {
            let key = match public_key.key_type() {
                KeyType::ECDSA_SECP256K1 =>
                    ECDSAKey::key_with_public_key_data(&public_key.data().0)
                        .map(OpaqueKey::ECDSA),
                KeyType::BLS12_381 => {
                    <Vec<u8> as TryInto<[u8; 48]>>::try_into(public_key.data().to_vec())
                        .map_err(|_e| KeyError::WrongLength(public_key.data().len()))
                        .map(|pubkey| BLSKey::key_with_public_key(pubkey, false))
                        .map(OpaqueKey::BLS)
                }
                key_type => Err(KeyError::Any(format!("unsupported type of key: {}", key_type))),
            }.unwrap();
            (*key_id, KeyInfo::registered(key, public_key.security_level(), public_key.purpose()))
        }).collect();

        IdentityModel {
            context_type,
            // context,
            index,
            unique_id: identity.id().to_buffer(),
            identity_registration_status: IdentityRegistrationStatus::Registered,
            credit_balance: identity.balance(),
            identity: Some(identity),
            locked_outpount: None,
            registration_funding_private_key: None,
            topup_funding_private_key: None,
            key_info_dictionaries,
            username_domains: Default::default(),
            username_salts: Default::default(),
            username_statuses: Default::default(),
            is_local: true,
            is_transient: false,
            // wallet_id: Some(wallet_id),
            current_main_index: 0,
            current_main_key_type: KeyKind::ECDSA,

            sync_block_hash: [0u8; 32],
            sync_block_height: 0,
            last_checked_usernames_timestamp: 0,
            last_checked_profile_timestamp: 0,
            last_checked_incoming_contacts_timestamp: 0,
            last_checked_outgoing_contacts_timestamp: 0,
            is_outgoing_invitation: false,
            is_from_incoming_invitation: false,
            transient_dashpay_user: None,
            asset_lock_registration_model: None,
            asset_lock_registration_hash: None,
            asset_lock_topup_models: vec![],
            // invitation_locked_outpoint: None,
        }
    }

    // pub fn from_identity_entity(entity: IdentityEntity, context_type: ContextType, context: *const c_void) -> Option<IdentityModel> {
    //     let IdentityEntity {
    //         unique_id,
    //         is_local,
    //         registration_status,
    //         credit_balance,
    //         sync_block_hash,
    //         key_infos,
    //         username_infos,
    //         last_checked_usernames_timestamp,
    //         last_checked_profile_timestamp,
    //         last_checked_incoming_contacts_timestamp,
    //         last_checked_outgoing_contacts_timestamp,
    //         registration_funding_transaction
    //     } = entity;
    //     if unique_id.is_zero() {
    //         return None;
    //     }
    //     let mut model = Self::new(unique_id, IdentityRegistrationStatus::from(registration_status), is_local, false, context_type, context);
    //
    //     for UsernameStatusInfo { proper, domain, status, salt } in username_infos {
    //         let username = proper.unwrap_or_default();
    //         let domain = domain.unwrap_or_default();
    //         if salt.is_zero() {
    //             model.add_username(username, domain, status);
    //         } else {
    //             model.add_username_with_salt(username, domain, status, salt);
    //         }
    //     }
    //     // model.credit_balance
    //
    //     model.credit_balance = credit_balance;
    //     model.sync_block_hash = sync_block_hash;
    //     model.last_checked_usernames_timestamp = last_checked_usernames_timestamp;
    //     model.last_checked_profile_timestamp = last_checked_profile_timestamp;
    //     model.last_checked_incoming_contacts_timestamp = last_checked_incoming_contacts_timestamp;
    //     model.last_checked_outgoing_contacts_timestamp = last_checked_outgoing_contacts_timestamp;
    //     model.sync_block_hash = sync_block_hash;
    //
    //     model.key_info_dictionaries = key_infos;
    //
    //
    //     Some(model)
    // }
    pub fn to_entity(&self) -> IdentityEntity {

        let usernames = self.username_statuses.iter().map(|(username_full_path, UsernameStatusInfo { status, salt, .. })| {
            IdentityUsernameEntity {
                domain: self.domain_of_username_full_path(username_full_path).unwrap_or_default(),
                salt: *salt,
                status: u8::from(*status),
                string_value: self.username_of_username_full_path(username_full_path).unwrap_or_default(),
                identity: None,
                identity_for_dashpay: None,
            }
        }).collect();
        let key_paths = self.key_info_dictionaries.iter().map(|(key_id, KeyInfo { key, key_status, security_level, purpose })| {
            KeyInfoEntity {
                index_path: None,
                key_id: *key_id,
                key_kind: key.kind().index(),
                key_status: u8::from(key_status),
                public_key_data: key.public_key_data(),
                purpose: purpose_to_index(*purpose),
                security_level: security_level_to_index(*security_level),
            }
        }).collect();

        IdentityEntity {
            unique_id: self.unique_id,
            is_local: self.is_local,
            registration_status: u8::from(&self.identity_registration_status),
            credit_balance: self.credit_balance,
            dashpay_synchronization_block_hash: self.sync_block_hash,
            last_checked_usernames: self.last_checked_usernames_timestamp,
            last_checked_profiles: self.last_checked_profile_timestamp,
            last_checked_incoming_friends: self.last_checked_incoming_contacts_timestamp,
            last_checked_outgoing_friends: self.last_checked_outgoing_contacts_timestamp,
            registration_funding_transaction: None,
            matching_dashpay_user: None,
            associated_invitation: None,
            usernames,
            chain: None,
            top_up_funding_transactions: vec![],
            key_paths,
            dashpay_username: self.first_dashpay_username().map(|username| {
                IdentityUsernameEntity {
                    domain: self.domain_of_username_full_path(&username).unwrap_or_default(),
                    salt: self.username_salts.get(&username).cloned().unwrap_or_default(),
                    status: u8::from(self.status_of_username_full_path(&username).unwrap_or(UsernameStatus::NotPresent)),
                    string_value: username,
                    identity: None,
                    identity_for_dashpay: None,
                }
            }.into())
        }
    }

    pub fn log_prefix(&self) -> String {
        format!("[Identity: {}: {}]", self.unique_id.to_lower_hex_string(), self.index)
    }
    // pub fn set_associated_invitation_locked_outpoint(&mut self, locked_outpoint: [u8; 36], created_locally: bool) {
    //     // self.invitation_locked_outpoint = Some(locked_outpoint);
    //     if created_locally {
    //         self.set_is_outgoing_invitation(true);
    //         self.set_is_from_incoming_invitation(false);
    //         self.set_is_local(false);
    //     } else {
    //         // It was created on another device, we are receiving the invite
    //         self.set_is_outgoing_invitation(false);
    //         self.set_is_from_incoming_invitation(true);
    //         self.set_is_local(true);
    //     }
    // }

    pub fn set_invitation_asset_lock_transaction(&mut self, transaction: TransactionModel) {
        assert!(self.is_outgoing_invitation, "This can only be done on an invitation");
        if !self.is_outgoing_invitation {
            return;
        }
        let locked_outpoint = transaction.locked_outpoint();
        let unique_id = if locked_outpoint.eq(&[0u8; 36]) {
            [0u8; 32]
        } else {
            sha256d::Hash::hash(&locked_outpoint).into()
        };
        self.asset_lock_registration_model = Some(transaction);
        self.locked_outpount = Some(locked_outpoint);
        // let locked_outpoint = self.locked_outpoint();
        // let utxo: [u8; 36] = locked_outpoint.into();
        self.set_unique_id(unique_id);
    }


    pub fn registration_derivation_kind(&self) -> DerivationPathKind {
        if self.is_outgoing_invitation {
            DerivationPathKind::InvitationFunding
        } else {
            DerivationPathKind::IdentityRegistrationFunding
        }
    }

    pub fn set_registration_status(&mut self, status: IdentityRegistrationStatus) {
        self.identity_registration_status = status;
    }
    pub fn registration_status(&self) -> IdentityRegistrationStatus {
        self.identity_registration_status.clone()
    }
    pub fn registration_status_index(&self) -> u8 {
        u8::from(&self.identity_registration_status)
    }
    pub fn is_registered(&self) -> bool {
        self.identity_registration_status == IdentityRegistrationStatus::Registered
    }
    pub fn is_claimed(&self) -> bool {
        self.identity_registration_status == IdentityRegistrationStatus::Registered || self.identity_registration_status == IdentityRegistrationStatus::Registering
    }
    pub fn is_pending(&self) -> bool {
        self.identity_registration_status == IdentityRegistrationStatus::NotRegistered || self.identity_registration_status == IdentityRegistrationStatus::Unknown
    }
    pub fn set_identity(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }
    pub fn identity(&self) -> Option<Identity> {
        self.identity.clone()
    }

    pub fn set_sync_block_hash(&mut self, block_hash: [u8; 32]) {
        self.sync_block_hash = block_hash;
    }
    pub fn sync_block_hash(&self) -> [u8; 32] {
        self.sync_block_hash.clone()
    }
    pub fn set_sync_block_height(&mut self, block_height: u32) {
        self.sync_block_height = block_height;
    }
    pub fn sync_block_height(&self) -> u32 {
        self.sync_block_height
    }

    pub fn set_last_checked_profile_timestamp(&mut self, timestamp: u64) {
        self.last_checked_profile_timestamp = timestamp;
    }
    pub fn last_checked_profile_timestamp(&self) -> u64 {
        self.last_checked_profile_timestamp
    }

    pub fn set_last_checked_usernames_timestamp(&mut self, timestamp: u64) {
        self.last_checked_usernames_timestamp = timestamp;
    }
    pub fn last_checked_usernames_timestamp(&self) -> u64 {
        self.last_checked_usernames_timestamp
    }
    pub fn set_last_checked_incoming_contacts_timestamp(&mut self, timestamp: u64) {
        self.last_checked_incoming_contacts_timestamp = timestamp;
    }
    pub fn last_checked_incoming_contacts_timestamp(&self) -> u64 {
        self.last_checked_incoming_contacts_timestamp
    }
    pub fn set_last_checked_outgoing_contacts_timestamp(&mut self, timestamp: u64) {
        self.last_checked_outgoing_contacts_timestamp = timestamp;
    }
    pub fn last_checked_outgoing_contacts_timestamp(&self) -> u64 {
        self.last_checked_outgoing_contacts_timestamp
    }

    pub fn register_key_from_key_path_entity(&mut self, key_type: u16, public_key_data: &[u8], security_level: u16, purpose: u16, key_id: u32, key_status: u16) -> bool {
        let kind = KeyKind::from(key_type as i16);
        let key = kind.key_with_public_key_data(public_key_data);
        if key.is_err() {
            return false;
        }
        let security_level = security_level_from_index(security_level as u8);
        let purpose = purpose_from_index(purpose as u8);
        // self.set_keys_created(max(self.keys_created, key_id + 1));
        self.add_key_info(key_id, KeyInfo {
            key: key.unwrap(),
            key_status: IdentityKeyStatus::from(key_status as u8),
            security_level,
            purpose,
        });
        true
    }


    pub fn profile_is_outdated(&self) -> bool {
        self.last_checked_profile_timestamp() < SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() - 3600
    }
    pub fn incoming_contacts_is_outdated(&self) -> bool {
        self.last_checked_incoming_contacts_timestamp() < SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() - 3600
    }
    pub fn outgoing_contacts_is_outdated(&self) -> bool {
        self.last_checked_outgoing_contacts_timestamp() < SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() - 3600
    }
    pub fn usernames_are_outdated(&self) -> bool {
        self.dashpay_username_count() == 0 && self.last_checked_usernames_timestamp() == 0
    }

    // pub fn set_wallet_id(&mut self, wallet_id: Option<String>) {
    //     self.wallet_id = wallet_id;
    // }
    pub fn wallet_id(&self) -> Option<String> {
        match &self.context_type {
            ContextType::Chain(_) => None,
            ContextType::Wallet(wallet_id) => Some(wallet_id.clone())
        }
    }
    pub fn has_wallet_id(&self) -> bool {
        match &self.context_type {
            ContextType::Chain(..) => false,
            ContextType::Wallet(..) => true
        }
    }

    pub fn set_registration_funding_private_key(&mut self, private_key: Option<OpaqueKey>) {
        self.registration_funding_private_key = private_key;
    }
    pub fn registration_funding_private_key(&self) -> Option<OpaqueKey> {
        self.registration_funding_private_key.clone()
    }
    pub fn has_registration_funding_private_key(&self) -> bool {
        self.registration_funding_private_key.is_some()
    }

    pub fn set_topup_funding_private_key(&mut self, private_key: Option<OpaqueKey>) {
        self.topup_funding_private_key = private_key;
    }
    pub fn topup_funding_private_key(&self) -> Option<OpaqueKey> {
        self.topup_funding_private_key.clone()
    }
    pub fn has_topup_funding_private_key(&self) -> bool {
        self.topup_funding_private_key.is_some()
    }

    pub fn set_unique_id(&mut self, unique_id: [u8; 32]) {
        self.unique_id = unique_id;
    }
    pub fn unique_id(&self) -> [u8; 32] {
        self.unique_id
    }
    pub fn unique_id_string(&self) -> String {
        base58::encode_slice(&self.unique_id)

    }
    pub fn set_is_local(&mut self, is_local: bool) {
        self.is_local = is_local;
    }
    pub fn is_local(&self) -> bool {
        self.is_local
    }
    pub fn set_is_transient(&mut self, is_transient: bool) {
        self.is_transient = is_transient;
    }
    pub fn is_transient(&self) -> bool {
        self.is_transient
    }

    pub fn set_credit_balance(&mut self, credit_balance: u64) {
        self.credit_balance = credit_balance;
    }
    pub fn credit_balance(&self) -> u64 {
        self.credit_balance
    }

    pub fn set_index(&mut self, index: u32) {
        self.index = index;
    }
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn set_is_outgoing_invitation(&mut self, is_outgoing_invitation: bool) {
        self.is_outgoing_invitation = is_outgoing_invitation;
    }
    pub fn is_outgoing_invitation(&self) -> bool {
        self.is_outgoing_invitation
    }

    pub fn set_is_from_incoming_invitation(&mut self, is_from_incoming_invitation: bool) {
        self.is_from_incoming_invitation = is_from_incoming_invitation;
    }
    pub fn is_from_incoming_invitation(&self) -> bool {
        self.is_from_incoming_invitation
    }

    pub fn set_current_main_index(&mut self, current_main_index: u32) {
        self.current_main_index = current_main_index;
    }
    pub fn current_main_index(&self) -> u32 {
        self.current_main_index
    }

    pub fn set_current_main_key_type(&mut self, current_main_key_type: KeyKind) {
        self.current_main_key_type = current_main_key_type;
    }
    pub fn current_main_key_type(&self) -> KeyKind {
        self.current_main_key_type
    }

    pub fn asset_lock_registration_model(&self) -> Option<TransactionModel> {
        self.asset_lock_registration_model.clone()
    }
    pub fn set_asset_lock_registration_model(&mut self, model: TransactionModel) {
        self.asset_lock_registration_model = Some(model);
    }
    pub fn has_asset_lock_registration_model(&self) -> bool {
        self.asset_lock_registration_model.is_some()
    }

    pub fn asset_lock_registration_hash(&self) -> Option<[u8; 32]> {
        self.asset_lock_registration_hash.clone()
    }
    pub fn set_asset_lock_registration_hash(&mut self, hash: [u8; 32]) {
        self.asset_lock_registration_hash = Some(hash);
    }
    pub fn has_asset_lock_registration_hash(&self) -> bool {
        self.asset_lock_registration_hash.is_some()
    }

    pub fn asset_lock_topup_models(&self) -> Vec<TransactionModel> {
        self.asset_lock_topup_models.clone()
    }
    pub fn set_asset_lock_topup_models(&mut self, models: Vec<TransactionModel>) {
        self.asset_lock_topup_models = models;
    }
    pub fn has_asset_lock_topup_models(&self) -> bool {
        !self.asset_lock_topup_models.is_empty()
    }
    pub fn add_asset_lock_topup_model(&mut self, model: TransactionModel) {
        self.asset_lock_topup_models.push(model);
    }

    pub fn set_locked_outpoint(&mut self, outpoint: Option<[u8; 36]>) {
        self.locked_outpount = outpoint;
    }
    pub fn locked_outpoint(&self) -> Option<[u8; 36]> {
        self.locked_outpount
    }
    pub fn has_locked_outpoint(&self) -> bool {
        self.locked_outpount.is_some()
    }

    pub fn full_path_for_username(username: &str, domain: &str) -> String {
        username.to_lowercase() + "." + &domain.to_lowercase()
    }

    pub fn to_keychain_value(&self) -> IdentityDictionaryItemValue {
        if let Some(ref locked_outpoint) = self.locked_outpount {
            if locked_outpoint[..32] != [0u8; 32] {
                IdentityDictionaryItemValue::Outpoint { index: self.index(), locked_outpoint_data: locked_outpoint.clone() }
            } else {
                IdentityDictionaryItemValue::Index { index: self.index() }
            }
        } else {
            IdentityDictionaryItemValue::Index { index: self.index() }
        }
    }


    pub fn add_username(&mut self, username: String, domain: String, status: UsernameStatus) {
        let full_path = Self::full_path_for_username(&username, &domain);
        self.username_statuses.insert(full_path, UsernameStatusInfo {
            proper: Some(username),
            domain: Some(domain),
            status,
            salt: [0u8; 32],
        });
    }
    pub fn add_username_with_salt(&mut self, username: String, domain: String, status: UsernameStatus, salt: [u8; 32]) {
        let full_path = Self::full_path_for_username(&username, &domain);
        self.username_statuses.insert(full_path, UsernameStatusInfo {
            proper: Some(username),
            domain: Some(domain),
            status,
            salt,
        });
    }

    pub fn add_key_info(&mut self, index: u32, key_info: KeyInfo) {
        self.key_info_dictionaries.insert(index, key_info);
    }

    pub fn keys_created(&self) -> usize {
        self.key_info_dictionaries.len()
    }

    pub fn add_salt(&mut self, username: String, salt: [u8; 32]) {
        self.username_salts.insert(username, salt);
    }

    pub fn salt_for_username(&self, username: &str) -> Option<[u8; 32]> {
        self.username_salts.get(username).cloned()
    }

    pub fn username_full_paths_with_status(&self, status: UsernameStatus) -> Vec<String> {
        self.username_statuses.iter().filter_map(|(full_path, info)| {
            if status.eq(&info.status) {
                Some(full_path.clone())
            } else {
                None
            }
        }).collect()
    }

    pub fn unregistered_username_full_paths(&self) -> Vec<String> {
        self.username_full_paths_with_status(UsernameStatus::Initial)
    }
    pub fn confirmed_username_full_paths(&self) -> Vec<String> {
        self.username_full_paths_with_status(UsernameStatus::Confirmed)
    }

    pub fn unregistered_username_full_paths_count(&self) -> usize {
        self.unregistered_username_full_paths().len()
    }
    pub fn confirmed_username_full_paths_count(&self) -> usize {
        self.confirmed_username_full_paths().len()
    }

    pub fn status_of_username(&self, username: &str, domain: &str) -> Option<UsernameStatus> {
        let full_path = Self::full_path_for_username(username, domain);
        self.status_of_username_full_path(&full_path)
    }

    pub fn status_of_dashpay_username(&self, username: &str) -> Option<UsernameStatus> {
        let full_path = Self::full_path_for_username(username, "dash");
        self.status_of_username_full_path(&full_path)
    }

    pub fn is_dashpay_username_confirmed(&self, username: &str) -> bool {
        let full_path = Self::full_path_for_username(username, "dash");
        self.status_of_username_full_path(&full_path) == Some(UsernameStatus::Confirmed)
    }

    pub fn is_dashpay_ready(&self) -> bool {
        self.active_key_count() > 0 && self.is_registered()
    }

    pub fn status_of_username_full_path(&self, username_full_path: &str) -> Option<UsernameStatus> {
        self.username_statuses.get(username_full_path).map(|s| s.status.clone())
    }
    pub fn status_index_of_username_full_path(&self, username_full_path: &str) -> Option<u8> {
        self.username_statuses.get(username_full_path).map(|s| s.status.clone().into())
    }
    pub fn status_of_username_full_path_is_initial(&self, username_full_path: &str) -> bool {
        self.username_statuses.get(username_full_path).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default()
    }
    pub fn username_of_username_full_path(&self, username_full_path: &str) -> Option<String> {
        self.username_statuses.get(username_full_path).and_then(|s| s.proper.clone())
    }
    pub fn domain_of_username_full_path(&self, username_full_path: &str) -> Option<String> {
        self.username_statuses.get(username_full_path).and_then(|s| s.domain.clone())
    }

    pub fn dashpay_username_full_paths(&self) -> Vec<String> {
        self.username_statuses.keys().cloned().collect()
    }
    pub fn dashpay_username_count(&self) -> usize {
        self.username_statuses.len()
    }
    pub fn username_statuses(&self) -> HashMap<String, UsernameStatusInfo> {
        self.username_statuses.clone()
    }

    pub fn usernames_and_domains(&self, username_full_paths: Vec<String>) -> Vec<(String, String)> {
        username_full_paths.iter().filter_map(|username_full_path| {
            if let Some(UsernameStatusInfo { proper, domain, .. }) = self.username_statuses.get(username_full_path) {
                match (proper, domain) {
                    (Some(proper), Some(domain)) => Some((proper.clone(), domain.clone())),
                    _ => None
                }
            } else {
                None
            }
        }).collect()
    }
    pub fn identifier(&self) -> Identifier {
        Identifier::from(self.unique_id)
    }

    pub fn dashpay_usernames(&self) -> Vec<String> {
        self.username_statuses.iter().filter_map(|(full_path, _)| self.username_of_username_full_path(full_path)).collect()
    }
    pub fn first_dashpay_username(&self) -> Option<String> {
        self.dashpay_usernames().first().cloned()
    }
    pub fn has_dashpay_username(&self, username: &str) -> bool {
        self.username_statuses.iter().any(|(full_path, _)| {
            if let Some(u) = self.username_of_username_full_path(full_path) {
                u.eq(username)
            } else {
                false
            }
        })
    }

    /// Profile
    pub fn maybe_user(&self) -> Option<TransientDashPayUser> {
        self.transient_dashpay_user.clone()
    }
    pub fn set_user(&mut self, user: Option<TransientDashPayUser>) {
        self.transient_dashpay_user = user;
    }

    pub fn if_user_matches_revision(&self, remote_profile_revision: u64) -> bool {
        if let Some(user) = self.transient_dashpay_user.as_ref() {
            if let Some(revision) = user.revision {
                return revision == remote_profile_revision
            }
        }
        false
    }

    pub fn maybe_avatar_path(&self) -> Option<String> {
        self.transient_dashpay_user.as_ref().and_then(|user| user.avatar_url.clone())
    }
    pub fn maybe_avatar_fingerprint(&self) -> Option<Vec<u8>> {
        self.transient_dashpay_user.as_ref().and_then(|user| user.avatar_fingerprint.clone())
    }
    pub fn maybe_avatar_hash(&self) -> Option<[u8; 32]> {
        self.transient_dashpay_user.as_ref().and_then(|user| user.avatar_hash.clone())
    }
    pub fn maybe_display_name(&self) -> Option<String> {
        self.transient_dashpay_user.as_ref().and_then(|user| user.display_name.clone())
    }
    pub fn maybe_public_message(&self) -> Option<String> {
        self.transient_dashpay_user.as_ref().and_then(|user| user.public_message.clone())
    }
    pub fn maybe_profile_created_at(&self) -> Option<u64> {
        self.transient_dashpay_user.as_ref().and_then(|user| user.created_at.clone())
    }
    pub fn maybe_profile_updated_at(&self) -> Option<u64> {
        self.transient_dashpay_user.as_ref().and_then(|user| user.updated_at.clone())
    }

    pub fn set_username_full_paths(&mut self, username_full_paths: Vec<String>, status: UsernameStatus) {
        username_full_paths.into_iter().for_each(|full_path| self.set_username_status(full_path, status.clone()));
    }

    pub fn set_username_status(&mut self, username_full_path: String, status: UsernameStatus) {
        if let Some(status_info) = self.username_statuses.get_mut(&username_full_path) {
            status_info.status = status;
        } else {
            self.username_statuses.insert(username_full_path, UsernameStatusInfo::with_status(status));
        }
    }
    pub fn set_username_status_confirmed(&mut self, username: String, normalized_parent_domain_name: String, label: String) -> bool {
        // TODO: check it (migrated as is, but it maybe wrong)
        let full_path_username = Self::full_path_for_username(&username, "dash");
        let maybe_status = self.username_statuses.get(&username);
        let is_new = maybe_status.is_none();
        let status_info = if let Some(status_info) = maybe_status {
            status_info.confirmed()
        } else {
            UsernameStatusInfo {
                proper: Some(label),
                domain: Some(normalized_parent_domain_name),
                status: UsernameStatus::Confirmed,
                salt: [0u8; 32],
            }
        };
        self.username_statuses.insert(full_path_username, status_info);
        is_new
    }
    pub fn set_username_status_confirmed2(&mut self, username: String, domain: String, lowercase_username: String) -> bool {
        // TODO: check it (migrated as is, but it maybe wrong)
        let full_path_username = Self::full_path_for_username(&username, &domain);
        let maybe_status = self.username_statuses.get(&Self::full_path_for_username(&lowercase_username, &domain));
        let is_new = maybe_status.is_none();
        let status_info = if let Some(status_info) = maybe_status {
            status_info.confirmed()
        } else {
            UsernameStatusInfo {
                proper: Some(username),
                domain: Some(domain),
                status: UsernameStatus::Confirmed,
                salt: [0u8; 32],
            }
        };
        self.username_statuses.insert(full_path_username, status_info);
        is_new
    }


    pub fn active_key_count(&self) -> usize {
        self.key_info_dictionaries.values().filter(|KeyInfo { key_status, .. }| key_status.is_registered()).count()
    }
    pub fn total_key_count(&self) -> usize {
        self.key_info_dictionaries.len()
    }
    pub fn key_info_dictionaries(&self) -> BTreeMap<u32, KeyInfo> {
        self.key_info_dictionaries.clone()
    }

    pub fn registered_key_info_dictionaries(&self) -> BTreeMap<u32, KeyInfo> {
        self.key_info_dictionaries().into_iter().filter(|(_index, KeyInfo { key_status, .. })| key_status.is_registered()).collect()
    }

    pub fn active_keys_for_key_type(&self, kind: KeyKind) -> Vec<OpaqueKey> {
        self.key_info_dictionaries.values().filter_map(|info| info.kind().eq(&kind).then_some(&info.key)).cloned().collect()
    }

    pub fn verify_signature(&mut self, signature: Vec<u8>, kind: KeyKind, digest: [u8; 32]) -> bool {
        for info in self.key_info_dictionaries.values_mut() {
            if info.kind().eq(&kind) {
                if let Ok(true) = info.key.verify(&digest, &signature) {
                    return true;
                }
            }
        }
        false
    }

    pub fn key_info_at_index(&self, index: u32) -> Option<KeyInfo> {
        self.key_info_dictionaries.get(&index).map(|info| info.clone())
    }

    pub fn status_of_key_at_index(&self, index: u32) -> Option<IdentityKeyStatus> {
        self.key_info_dictionaries.get(&index).map(|info| info.key_status.clone())
    }

    pub fn key_at_index(&self, index: u32) -> Option<OpaqueKey> {
        self.key_info_dictionaries.get(&index).map(|info| info.key.clone())
    }
    pub fn has_key_at_index(&self, index: u32) -> bool {
        self.key_info_dictionaries.get(&index).is_some()
    }

    pub fn has_key_of_security_level(&self, security_level: SecurityLevel) -> bool {
        self.key_info_dictionaries.values()
            .any(|key_info| key_info.of_security_level(security_level))
    }
    pub fn has_key_of_purpose(&self, purpose: Purpose) -> bool {
        self.key_info_dictionaries.values()
            .any(|key_info| key_info.of_purpose(purpose))
    }

    pub fn first_identity_public_key(&self, security_level: SecurityLevel, purpose: Purpose) -> Option<IdentityPublicKey> {
        self.key_info_dictionaries.iter()
            .find_map(|(index, KeyInfo { key, security_level: level, purpose: p, .. })|
                (security_level.eq(level) && purpose.eq(p))
                    .then(|| identity_public_key(*index, key.clone(), security_level, purpose)))
    }
    pub fn first_index_of_key_kind(&self, kind: KeyKind) -> Option<u32> {
        self.key_info_dictionaries.iter()
            .find_map(|(index, key_info)| kind.eq(&key_info.kind())
                .then_some(*index))
    }

    pub fn first_index_of_key_kind_and_security_level(&self, kind: KeyKind, security_level: SecurityLevel) -> Option<u32> {
        self.key_info_dictionaries.iter()
            .find_map(|(index, key_info)| (kind.eq(&key_info.kind()) && security_level.eq(&key_info.security_level))
                .then_some(*index))
    }

    pub fn first_index_of_ecdsa_key_with_security_level(&self, security_level: SecurityLevel) -> Option<u32> {
        self.key_info_dictionaries.iter()
            .find_map(|(index, key_info)| (key_info.is_ecdsa() && security_level.eq(&key_info.security_level))
                .then_some(*index))
    }


    pub fn has_identity_public_key(&self, key: &IdentityPublicKey) -> bool {
        self.key_at_index(key.id())
            .map(|opaque_key| opaque_key.public_key_data().eq(key.data().as_slice()))
            .unwrap_or_default()
    }

    pub fn owner_id(&self) -> Identifier {
        self.identity().map(|ide| ide.id()).unwrap_or(self.identifier())
    }


    pub fn contains_topup_transaction_with_hash(&self, hash: &[u8; 32]) -> bool {
        self.asset_lock_topup_models.iter().any(|model| model.transaction.txid().as_byte_array().eq(hash))
    }

    // pub fn steps_completed(&self) -> u32 /*{
    //     let mut steps_completed = RegistrationStep::None;
    //
    //     if self.is_registered() {
    //         steps_completed = RegistrationStep::RegistrationSteps;
    //         if self.confirmed_username_full_paths_count() > 0 {
    //             steps_completed.insert(RegistrationStep::Username);
    //         }
    //     } else if let Some(tx_model) = &self.asset_lock_registration_model {
    //         steps_completed.insert(RegistrationStep::FundingTransactionCreation);
    //         if tx_model.core_chain_locked_height != i32::MAX && tx_model.is_verified {
    //             steps_completed.insert(RegistrationStep::FundingTransactionAccepted);
    //         }
    //
    //
    //         DSAccount *account = [self.chain firstAccountThatCanContainTransaction:self.registrationAssetLockTransaction];
    //         if (self.registrationAssetLockTransaction.blockHeight != TX_UNCONFIRMED || [account transactionIsVerified:self.registrationAssetLockTransaction])
    //         stepsCompleted |= DSIdentityRegistrationStep_FundingTransactionAccepted;
    //         if ([self isRegisteredInWallet])
    //         stepsCompleted |= DSIdentityRegistrationStep_LocalInWalletPersistence;
    //         if tx_model.
    //         stepsCompleted |= DSIdentityRegistrationStep_ProofAvailable;
    //     }
    //     return stepsCompleted;
    // }*/
    //
    // pub fn apply_identity_entity(&mut self, entity: IdentityEntity) {
    //     for usernameEntity in entity.usernames {
    //         let salt = usernameEntity.salt;
    //         let domain = usernameEntity.domain;
    //         let username = usernameEntity.string_value;
    //         let status = UsernameStatus::from(usernameEntity.status);
    //         if !salt.is_zero() {
    //             self.add_username_with_salt(username.clone(), domain, status, salt);
    //             self.add_salt(username, salt);
    //         } else {
    //             self.add_username(username, domain, status);
    //         }
    //     }
    //     self.set_credit_balance(entity.credit_balance);
    //     self.set_registration_status(IdentityRegistrationStatus::from(entity.registration_status));
    //     self.set_last_checked_profile_timestamp(entity.last_checked_profiles);
    //     self.set_last_checked_usernames_timestamp(entity.last_checked_usernames);
    //     self.set_last_checked_outgoing_contacts_timestamp(entity.last_checked_outgoing_friends);
    //     self.set_last_checked_incoming_contacts_timestamp(entity.last_checked_incoming_friends);
    //
    //     self.set_sync_block_hash(entity.dashpay_synchronization_block_hash);
    //     // self.set_sync_block_height();
    //
    //     for key_path_entity in entity.key_paths {
    //         let mut added = false;
    //         if let Some(index_path) = key_path_entity.index_path {
    //             // IndexHardSoft::
    //             // let non_hardened = index_path.sof
    //         }
    //         //     NSIndexPath *keyIndexPath = (NSIndexPath *)[keyPathEntity path];
    //         // BOOL added = NO;
    //         // if (keyIndexPath) {
    //         //     DSAuthenticationKeysDerivationPath *derivationPath = [self derivationPathForType:keyPathEntity.keyType];
    //         //     NSIndexPath *nonhardenedPath = [keyIndexPath softenAllItems];
    //         //     NSIndexPath *hardenedPath = [nonhardenedPath hardenAllItems];
    //         //     DOpaqueKey *key = [derivationPath publicKeyAtIndexPathAsOpt:hardenedPath];
    //         //     if (key) {
    //         //         DSecurityLevel *level = DSecurityLevelFromIndex(keyPathEntity.securityLevel);
    //         //         DPurpose *purpose = DPurposeFromIndex(keyPathEntity.purpose);
    //         //         uint32_t index = (uint32_t)[nonhardenedPath indexAtPosition:[nonhardenedPath length] - 1];
    //         //         DKeyInfo *key_info = DKeyInfoCtor(key, DIdentityKeyStatusFromIndex(keyPathEntity.keyStatus), level, purpose);
    //         //         DIdentityModelAddKeyInfo(model, index, key_info);
    //         //         DKeyInfoDtor(key_info);
    //         //         added = YES;
    //         //     }
    //         // }
    //         // if (!added) {
    //         //     key_path_entity.
    //         //     Slice_u8 *slice = slice_ctor(keyPathEntity.publicKeyData);
    //         //     self.register_key_from_key_path_entity(key_path_entity.key_info.key.kind())
    //         //     dash_spv_platform_identity_model_IdentityModel_register_key_from_key_path_entity(DIdentityModelMut(self.controller), keyPathEntity.keyType, slice, keyPathEntity.securityLevel, keyPathEntity.purpose, keyPathEntity.keyID, keyPathEntity.keyStatus);
    //         //     slice_dtor(slice);
    //         // }
    //     }
    //     if self.is_local || self.is_outgoing_invitation {
    //         if let Some(tx) = entity.registration_funding_transaction {
    //             self.asset_lock_registration_hash = tx.base.base.transaction_hash.map(|hash| hash.tx_hash);
    //             println!("{} AssetLockTX: Entity Attached: txHash: {}", self.log_prefix(), self.asset_lock_registration_hash.unwrap_or_default().to_lower_hex_string());
    //         } else if let Some(locked_outpoint) = self.locked_outpount {
    //             let transaction_hash_data = self.locked_outpount
    //             // NSData *transactionHashData = uint256_data(uint256_reverse(self.lockedOutpoint.hash));
    //             // // DSLog(@"%@ AssetLockTX: Load: lockedOutpoint: %@: %lu %@", self.logPrefix, uint256_hex(self.lockedOutpoint.hash), self.lockedOutpoint.n, transactionHashData.hexString);
    //             // DSAssetLockTransactionEntity *assetLockEntity = [DSAssetLockTransactionEntity anyObjectInContext:identityEntity.managedObjectContext matching:@"transactionHash.txHash == %@", transactionHashData];
    //             // if (assetLockEntity) {
    //             //     self.registrationAssetLockTransactionHash = assetLockEntity.transactionHash.txHash.UInt256;
    //             //     DSLog(@"%@ AssetLockTX: Entity Found for txHash: %@", self.logPrefix, uint256_hex(self.registrationAssetLockTransactionHash));
    //             //     DSAssetLockTransaction *registrationAssetLockTransaction = (DSAssetLockTransaction *)[assetLockEntity transactionForChain:self.chain];
    //             //     BOOL correctIndex = self.is_outgoing_invitation ?
    //             //     [registrationAssetLockTransaction checkInvitationDerivationPathIndexForWallet:self.wallet isIndex:self.index] :
    //             //     [registrationAssetLockTransaction checkDerivationPathIndexForWallet:self.wallet isIndex:self.index];
    //             //     if (!correctIndex) {
    //             //         DSLog(@"%@ AssetLockTX: IncorrectIndex %u (%@)", self.logPrefix, self.index, registrationAssetLockTransaction.toData.hexString);
    //             //         //NSAssert(FALSE, @"We should implement this");
    //             //     }
    //             // }
    //         }
    //     }
    // }
}

impl IdentityModel {

    // pub fn create_salted_domain_hashes_documents<'a>(&self, platform_version: &PlatformVersion, salted_domain_hashes: &HashMap<String, [u8; 32]>, document_type: DocumentTypeRef<'a>) -> Result<HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef<'a>, Bytes32, Option<TokenPaymentInfo>)>>, Error> {
    //     let owner_id = self.identifier();
    //     let entropy = <[u8; 32]>::random();
    //     let mut documents = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::new();
    //     for username_full_path in salted_domain_hashes.keys() {
    //         let value = self.to_salted_domain_hash_value(username_full_path);
    //         let document = document_type.create_document_from_data(value, owner_id, 1000, 1000, entropy, platform_version)
    //             .map_err(Error::from)?;
    //         documents.insert(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy), None)]);
    //     }
    //     Ok(documents)
    // }

    pub fn update_with_username_document(&mut self, document: Document) -> Option<SaveUsernameContext> {
        let properties = document.properties();
        let username = properties.get("label").and_then(|value| value.as_text());
        let lowercase_username = properties.get("normalizedLabel").and_then(|value| value.as_text());
        let domain = properties.get("normalizedParentDomainName").and_then(|value| value.as_text());
        if username.is_some() && lowercase_username.is_some() && domain.is_some() {
            let username = username.unwrap();
            let doesnt_contain_dot = !username.contains(".");
            assert!(doesnt_contain_dot, "This is most likely an error");
            assert!(domain.is_some(), "Domain must not be nil");
            let lowercase_username = lowercase_username.unwrap();
            let domain = domain.unwrap();
            let save_context = if self.set_username_status_confirmed2(username.to_string(), domain.to_string(), lowercase_username.to_string()) {
                let username_full_path = IdentityModel::full_path_for_username(&username, &domain);
                let is_initial = self.username_statuses.get(&username_full_path).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default();
                let maybe_salt = self.salt_for_username(&username_full_path);
                let salt = if is_initial || maybe_salt.is_none() {
                    let salt = <[u8; 32]>::random();
                    self.add_salt(username_full_path, salt);
                    Some(salt)
                } else {
                    maybe_salt
                };
                SaveUsernameContext::new_username(username, domain, UsernameStatus::Confirmed, salt, true)
            } else {
                SaveUsernameContext::username(username, domain, UsernameStatus::Confirmed, None, true)
            };
            Some(save_context)
        } else {
            println!("[WARN] Username, lowercase username or domain is nil {:?}", document);
            None
        }
    }

    pub fn to_salted_domain_hash_value(&self, username_full_path: &str) -> Value {
        let UsernameStatusInfo { proper, domain, .. } = self.username_statuses.get(username_full_path).unwrap();
        let salt = self.salt_for_username(username_full_path).unwrap();
        let mut map = ValueMap::new();
        map.push((Value::Text("label".to_string()), Value::Text(proper.clone().unwrap())));
        map.push((Value::Text("normalizedLabel".to_string()), Value::Text(proper.clone().unwrap().to_lowercase())));
        map.push((Value::Text("normalizedParentDomainName".to_string()), Value::Text(domain.clone().unwrap().clone())));
        map.push((Value::Text("preorderSalt".to_string()), Value::Bytes32(salt)));
        map.push((Value::Text("records".to_string()), Value::Map(ValueMap::from([(Value::Text("identity".to_string()), Value::Identifier(Hash256::from(self.owner_id())))]))));
        map.push((Value::Text("subdomainRules".to_string()), Value::Map(ValueMap::from([(Value::Text("allowSubdomains".to_string()), Value::Bool(false))]))));
        Value::Map(map)
    }



}
pub fn domains_for_username_full_paths(username_full_paths: &Vec<String>) -> HashMap<String, Vec<String>> {
    let mut domains = HashMap::new();
    for username_full_path in username_full_paths {
        let components = username_full_path.split('.').collect::<Vec<_>>();
        let name = components[0];
        let domain = if components.len() > 1 {
            components[1..].join(".")
        } else {
            String::new()
        };
        domains.entry(domain)
            .or_insert(Vec::new())
            .push(name.to_string());
    }
    domains
}
