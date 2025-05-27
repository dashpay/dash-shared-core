use std::cmp::max;
use std::collections::{BTreeMap, HashMap};
use std::os::raw::c_void;
use std::sync::Arc;
use dapi_grpc::Message;
use dashcore::blockdata::transaction::outpoint::OutPoint;
use dashcore::hashes::{sha256d, Hash};
use dpp::data_contract::document_type::DocumentTypeRef;
use dpp::data_contract::document_type::methods::DocumentTypeV0Methods;
use dpp::document::{Document, DocumentV0Getters};
use dpp::identity::{Identity, IdentityPublicKey, KeyID, KeyType};
use dpp::identity::accessors::IdentityGettersV0;
use dpp::identity::identity_public_key::purpose::Purpose;
use dpp::identity::identity_public_key::security_level::SecurityLevel;
use dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dpp::state_transition::state_transitions::document::batch_transition::batched_transition::document_transition_action_type::DocumentTransitionActionType;
use dpp::tokens::token_payment_info::TokenPaymentInfo;
use platform_value::{Bytes32, Hash256, Identifier, Value, ValueMap};
use platform_version::version::PlatformVersion;
use dash_spv_crypto::crypto::byte_util::Random;
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::keys::{BLSKey, ECDSAKey, IKey, KeyError, OpaqueKey};
use crate::document::usernames::UsernameStatus;
use crate::error::Error;
use crate::identity::key_info::KeyInfo;
use crate::identity::key_status::IdentityKeyStatus;
use crate::identity::manager::{identity_public_key, key_kind_from_key_type};
use crate::identity::registration_status::IdentityRegistrationStatus;
use crate::identity::storage::username::SaveUsernameContext;
use crate::identity::username_status_info::UsernameStatusInfo;
use crate::models::transient_dashpay_user::TransientDashPayUser;

pub const DEFAULT_USERNAME_REGISTRATION_SECURITY_LEVEL: SecurityLevel = SecurityLevel::HIGH;
pub const DEFAULT_USERNAME_REGISTRATION_PURPOSE: Purpose = Purpose::AUTHENTICATION;

pub enum DerivationContextType {

}

#[ferment_macro::opaque]
pub struct IdentityModel {
    pub identity: Option<Identity>,

    pub registration_funding_private_key: Option<OpaqueKey>,
    pub topup_funding_private_key: Option<OpaqueKey>,

    pub identity_registration_status: IdentityRegistrationStatus,
    pub key_info_dictionaries: BTreeMap<u32, KeyInfo>,
    pub username_domains: HashMap<String, Vec<u8>>,
    pub username_salts: HashMap<String, [u8; 32]>,
    pub username_statuses: HashMap<String, UsernameStatusInfo>,

    pub keys_created: u32,
    pub current_main_index: u32,
    pub current_main_key_type: KeyKind,

    /// This is if the blockchain identity is present in wallets or not.
    /// If false -> blockchain identity is known for example from being a DashPay friend.
    pub is_local: bool,
    // TRUE if the identity is an effemeral identity returned when searching.
    pub is_transient: bool,
    /// Represents the last L1 block hash for which DashPay would be synchronized
    pub sync_block_hash: [u8; 32],

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

    pub locked_outpount: Option<OutPoint>,

    pub get_derivation_context: Arc<dyn Fn(*const c_void, KeyKind, OpaqueKey, u32, u32) -> *const c_void>,

    pub save_key_status: Arc<dyn Fn(/*identity*/*const c_void, /*storage_context*/*const c_void, u32, u32, KeyInfo) -> bool>,
    pub save_remote_key_status: Arc<dyn Fn(/*identity*/*const c_void, /*storage_context*/*const c_void, u32, IdentityKeyStatus) -> bool>,

    pub save_key_info: Arc<dyn Fn(/*identity*/*const c_void, /*storage_context*/ *const c_void, u32, u32, KeyInfo) -> bool>,
    pub save_remote_key_info: Arc<dyn Fn(/*identity*/*const c_void, /*storage_context*/*const c_void, u32, KeyInfo) -> bool>,

    pub save_username: Arc<dyn Fn(/*context*/*const c_void, SaveUsernameContext)>,

    pub get_private_key: Arc<dyn Fn(/*context*/*const c_void, /*index*/u32, KeyKind) -> Option<Vec<u8>>>,

    pub create_new_key: Arc<dyn Fn(/*context*/*const c_void, KeyKind, SecurityLevel, Purpose, bool) -> Result<u32, Error>>,
    pub active_private_keys_are_loaded: Arc<dyn Fn(*const c_void, /*is_local*/bool, /*key_info_dictionaries*/ BTreeMap<u32, KeyInfo>) -> Result<bool, Error>>
}

impl IdentityModel {
    pub fn save_username_in_context(&self, context: *const c_void, username_context: SaveUsernameContext) {
        (self.save_username)(context, username_context);
    }
    pub fn save_usernames_and_domains_in_context(&self, context: *const c_void, username_full_paths: Vec<String> ) {
        (self.save_username)(context, SaveUsernameContext::confirmed_username_full_paths(self.usernames_and_domains(username_full_paths)));
    }

    pub fn get_main_private_key_in_context(&self, context: *const c_void) -> Option<Vec<u8>> {
        (self.get_private_key)(context, self.current_main_index, self.current_main_key_type)
    }

    pub fn active_private_keys_are_loaded(&self, context: *const c_void) -> Result<bool, Error> {
        (self.active_private_keys_are_loaded)(context, self.is_local, self.key_info_dictionaries.clone())
    }

    pub fn create_new_ecdsa_auth_key(&self, context: *const c_void, level: SecurityLevel, save_key: bool) -> Result<u32, Error> {
        (self.create_new_key)(context, KeyKind::ECDSA, level, Purpose::AUTHENTICATION, save_key)
    }

    pub fn create_new_ecdsa_auth_key_of_level_if_needed(&self, context: *const c_void, level: SecurityLevel) -> Result<u32, Error> {
        if self.keys_created == 0 {
            self.create_new_ecdsa_auth_key(context, level, true)
        } else {
            Ok(u32::MAX)
        }
    }


    pub fn get_derivation_context(&self, context: *const c_void, key_kind: KeyKind, key: OpaqueKey, index: u32) -> *const c_void {
        (self.get_derivation_context)(context, key_kind, key, self.index, index)
    }

}

#[ferment_macro::export]
impl IdentityModel {
    pub fn new<
        GetDerivationContext: Fn(*const c_void, KeyKind, OpaqueKey, u32, u32) -> *const c_void + Sync + Send + 'static,
        SaveKeyStatus: Fn(*const c_void, *const c_void, /*identity_index*/u32, /*key_index*/u32, KeyInfo) -> bool + Sync + Send + 'static,
        SaveRemoteKeyStatus: Fn(*const c_void, *const c_void, u32, IdentityKeyStatus) -> bool + Sync + Send + 'static,
        SaveKeyInfo: Fn(*const c_void, *const c_void, /*identity_index*/u32, /*key_index*/u32, KeyInfo) -> bool + Sync + Send + 'static,
        SaveRemoteKeyInfo: Fn(*const c_void, *const c_void, u32, KeyInfo) -> bool + Sync + Send + 'static,
        SaveNewUsername: Fn(*const c_void, SaveUsernameContext) + Sync + Send + 'static,
        GetPrivateKeyAtIndex: Fn(*const c_void, u32, KeyKind) -> Option<Vec<u8>> + Sync + Send + 'static,
        CreateNewKey: Fn(*const c_void, KeyKind, SecurityLevel, Purpose, bool) -> Result<u32, Error> + Sync + Send + 'static,
        ActivePrivateKeysAreLoaded: Fn(*const c_void, bool, BTreeMap<u32, KeyInfo>) -> Result<bool, Error> + Sync + Send + 'static,

    >(
        unique_id: [u8; 32],
        status: IdentityRegistrationStatus,
        is_local: bool,
        is_transient: bool,
        current_main_index: u32,
        current_main_key_type: KeyKind,
        get_derivation_context: GetDerivationContext,
        save_key_status: SaveKeyStatus,
        save_remote_key_status: SaveRemoteKeyStatus,
        save_key_info: SaveKeyInfo,
        save_remote_key_info: SaveRemoteKeyInfo,
        save_username: SaveNewUsername,
        get_private_key: GetPrivateKeyAtIndex,
        create_new_key: CreateNewKey,
        active_private_keys_are_loaded: ActivePrivateKeysAreLoaded,
    ) -> Self {
        Self {
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
            current_main_index,
            current_main_key_type,
            keys_created: 0,
            sync_block_hash: [0u8; 32],
            last_checked_usernames_timestamp: 0,
            last_checked_profile_timestamp: 0,
            last_checked_incoming_contacts_timestamp: 0,
            last_checked_outgoing_contacts_timestamp: 0,
            credit_balance: 0,
            index: 0,
            is_outgoing_invitation: false,
            is_from_incoming_invitation: false,
            transient_dashpay_user: None,
            get_derivation_context: Arc::new(get_derivation_context),
            save_key_info: Arc::new(save_key_info),
            save_remote_key_info: Arc::new(save_remote_key_info),
            save_key_status: Arc::new(save_key_status),
            save_remote_key_status: Arc::new(save_remote_key_status),
            save_username: Arc::new(save_username),
            get_private_key: Arc::new(get_private_key),
            create_new_key: Arc::new(create_new_key),
            active_private_keys_are_loaded: Arc::new(active_private_keys_are_loaded),
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

    pub fn set_keys_created(&mut self, keys_created: u32) {
        self.keys_created = keys_created;
    }
    pub fn keys_created(&self) -> u32 {
        self.keys_created
    }

    pub fn set_locked_outpoint(&mut self, outpoint: Option<OutPoint>) {
        self.locked_outpount = outpoint;
    }
    pub fn locked_outpoint(&self) -> Option<OutPoint> {
        self.locked_outpount
    }
    pub fn has_locked_outpoint(&self) -> bool {
        self.locked_outpount.is_some()
    }

    pub fn full_path_for_username(username: &str, domain: &str) -> String {
        username.to_lowercase() + "." + &domain.to_lowercase()
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
        self.status_of_username_full_path(Self::full_path_for_username(username, domain))
    }

    pub fn status_of_dashpay_username(&self, username: String) -> Option<UsernameStatus> {
        self.status_of_username_full_path(Self::full_path_for_username(&username, "dash"))
    }

    pub fn is_dashpay_username_confirmed(&self, username: String) -> bool {
        self.status_of_username_full_path(Self::full_path_for_username(&username, "dash")) == Some(UsernameStatus::Confirmed)
    }

    pub fn status_of_username_full_path(&self, username_full_path: String) -> Option<UsernameStatus> {
        self.username_statuses.get(&username_full_path).map(|s| s.status.clone())
    }
    pub fn status_index_of_username_full_path(&self, username_full_path: String) -> Option<u8> {
        self.username_statuses.get(&username_full_path).map(|s| s.status.clone().into())
    }
    pub fn status_of_username_full_path_is_initial(&self, username_full_path: String) -> bool {
        self.username_statuses.get(&username_full_path).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default()
    }
    pub fn username_of_username_full_path(&self, username_full_path: &str) -> Option<String> {
        self.username_statuses.get(username_full_path).and_then(|s| s.proper.clone())
    }
    pub fn domain_of_username_full_path(&self, username_full_path: String) -> Option<String> {
        self.username_statuses.get(&username_full_path).and_then(|s| s.domain.clone())
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

    pub fn first_identity_public_key(&self, security_level: SecurityLevel, purpose: Purpose) -> Option<IdentityPublicKey> {
        self.key_info_dictionaries.iter().find_map(|(index, KeyInfo { key, security_level: level, purpose: p, .. })| {
            if security_level.eq(level) && purpose.eq(p) {
                Some(identity_public_key(*index, key.clone(), security_level, purpose))
            } else {
                None
            }
        })
    }
    pub fn first_index_of_key_kind(&self, kind: KeyKind) -> Option<u32> {
        self.key_info_dictionaries.iter().find_map(|(index, key_info)| kind.eq(&key_info.kind()).then_some(*index))
    }

    pub fn first_index_of_ecdsa_auth_key_create_if_needed(&self, level: SecurityLevel, save_key_if_need: bool, context: *const c_void) -> Result<u32, Error> {
        if let Some(index) = self.first_index_of_key_kind(KeyKind::ECDSA) {
            Ok(index)
        } else if self.is_local {
            self.create_new_ecdsa_auth_key(context, level, save_key_if_need)
        } else {
            Ok(u32::MAX)
        }
    }

    pub fn has_identity_public_key(&self, key: IdentityPublicKey) -> bool {
        self.key_at_index(key.id())
            .map(|opaque_key| opaque_key.public_key_data().eq(key.data().as_slice()))
            .unwrap_or_default()
    }

    pub fn maybe_private_key_for_identity_public_key(&self, identity_public_key: IdentityPublicKey, identity_context: *const c_void) -> Option<OpaqueKey> {
        let key_id = identity_public_key.id();
        let key_type = identity_public_key.key_type();
        let key_kind = key_kind_from_key_type(key_type);
        self.key_at_index(key_id).and_then(|key| {
            if key.public_key_data().eq(identity_public_key.data().as_slice()) {
                if let Some(maybe_private_key_data) = (self.get_private_key)(identity_context, key_id, key_kind) {
                    key_kind.key_with_private_key_data_as_opt(&maybe_private_key_data)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    pub fn salted_domain_hashes_for_username_full_paths(&mut self, username_full_paths: &Vec<String>, context: *const c_void) -> HashMap<String, [u8; 32]> {
        let mut salted_domain_hashes = HashMap::new();
        for unregistered_username_full_path in username_full_paths {
            let mut salted_domain = Vec::new();
            let is_initial = self.username_statuses.get(unregistered_username_full_path.as_str()).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default();
            let maybe_salt = self.salt_for_username(&unregistered_username_full_path);
            let salt = if is_initial || maybe_salt.is_none() {
                let random_salt = <[u8; 32]>::random();
                self.add_salt(unregistered_username_full_path.clone(), random_salt);
                let UsernameStatusInfo { proper, domain, status, .. } = self.username_statuses.get(unregistered_username_full_path.as_str()).unwrap();
                let username = proper.clone().unwrap();
                let domain = domain.clone().unwrap();

                self.save_username_in_context(context, SaveUsernameContext::salted_username(username, domain, random_salt, *status));
                random_salt
            } else {
                maybe_salt.unwrap()
            };
            salted_domain.extend_from_slice(&salt);
            salted_domain.extend(unregistered_username_full_path.encode_to_vec());
            salted_domain_hashes.insert(unregistered_username_full_path.clone(), sha256d::Hash::hash(&salted_domain).to_byte_array());
            self.add_salt(unregistered_username_full_path.clone(), salt);
        }
        salted_domain_hashes
    }

    pub fn salted_domain_hashes_for_username_full_paths_values(&mut self, username_full_paths: &Vec<String>, context: *const c_void) -> Value {
        let mut map = ValueMap::new();
        for unregistered_username_full_path in username_full_paths {
            let mut salted_domain = Vec::new();
            let is_initial = self.username_statuses.get(unregistered_username_full_path.as_str()).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default();
            let maybe_salt = self.salt_for_username(&unregistered_username_full_path);
            let salt = if is_initial || maybe_salt.is_none() {
                let random_salt = <[u8; 32]>::random();
                self.add_salt(unregistered_username_full_path.clone(), random_salt);
                let UsernameStatusInfo { proper, domain, status, .. } = self.username_statuses.get(unregistered_username_full_path.as_str()).unwrap();
                let username = proper.clone().unwrap();
                let domain = domain.clone().unwrap();
                self.save_username_in_context(context, SaveUsernameContext::salted_username(username, domain, random_salt, *status));
                random_salt
            } else {
                maybe_salt.unwrap()
            };
            salted_domain.extend_from_slice(&salt);
            salted_domain.extend(unregistered_username_full_path.encode_to_vec());
            map.push((Value::Text(unregistered_username_full_path.clone()), Value::Bytes32(sha256d::Hash::hash(&salted_domain).to_byte_array())));
            self.add_salt(unregistered_username_full_path.clone(), salt);
        }
        Value::Map(map)
    }

    pub fn process_salted_domain_hash_document(&mut self, username_full_path: &str, hash: [u8; 32], document: &Document, context: *const c_void) -> bool {
        match document.get("saltedDomainHash") {
            Some(Value::Bytes32(salted_domain_hash)) if hash.eq(salted_domain_hash) => {
                self.set_username_status(username_full_path.to_string(), UsernameStatus::Preordered);
                self.save_username_in_context(context, SaveUsernameContext::preordered_username_full_path(username_full_path));
                true
            }
            _ => false
        }
    }

    pub fn update_with_key_id_and_public_key(&mut self, index: KeyID, public_key: IdentityPublicKey, storage_context: *const c_void, context: *const c_void) -> Result<bool, Error> {
        println!("update_with_key_id_and_public_key.1: {}: {:?}", index, public_key);
        let security_level = public_key.security_level();
        let purpose = public_key.purpose();
        let public_key_data = public_key.data();
        let key = match public_key.key_type() {
            KeyType::ECDSA_SECP256K1 =>
                ECDSAKey::key_with_public_key_data(public_key_data.as_slice())
                    .map(OpaqueKey::ECDSA),
            KeyType::BLS12_381 => {
                <Vec<u8> as TryInto<[u8; 48]>>::try_into(public_key_data.to_vec())
                    .map_err(|_e| KeyError::WrongLength(public_key_data.len()))
                    .map(|pubkey| BLSKey::key_with_public_key(pubkey, false))
                    .map(OpaqueKey::BLS)
            }
            key_type => Err(KeyError::Any(format!("unsupported type of key: {}", key_type))),
        }.map_err(Error::KeyError)?;
        // let key_type = key.kind();
        let maybe_key_info = self.key_info_at_index(index);
        let add_key_info = maybe_key_info.as_ref().map(|key_info| key_info.has_key_with_public_key_data(&public_key_data.0)).unwrap_or_default();
        println!("update_with_key_id_and_public_key.2: {}: {}", self.is_local, add_key_info);

        if self.is_local {
            if maybe_key_info.is_some() {
                if add_key_info {
                    let key_info = KeyInfo::registered(key.clone(), security_level, purpose);
                    self.add_key_info(index, key_info.clone());
                    if !self.is_transient {
                        (self.save_key_status)(context, storage_context, self.index, index, key_info);
                    }
                } else {
                    return Err(Error::Any(0, "these should really match up".to_string()));
                }
            } else {
                self.keys_created = max(self.keys_created, index + 1);
                let key_info = KeyInfo::registered(key.clone(), security_level, purpose);

                if add_key_info {
                    self.add_key_info(index, key_info.clone());
                }
                if !self.is_transient {
                    (self.save_key_info)(context, storage_context, self.index, index, key_info);
                }
            }
        } else {
            if let Some(KeyInfo { key_status, .. }) = maybe_key_info {
                if add_key_info {
                    self.add_key_info(index, KeyInfo::registered(key, security_level, purpose));
                    if !self.is_transient && !key_status.is_registered() {
                        (self.save_remote_key_status)(context, storage_context, index, IdentityKeyStatus::Registered);
                    }
                } else {
                    return Err(Error::Any(0, "these should really match up".to_string()));
                }
            } else {
                self.keys_created = max(self.keys_created, index + 1);
                if add_key_info {
                    self.add_key_info(index, KeyInfo::registered(key.clone(), security_level, purpose));
                }
                if !self.is_transient {
                    (self.save_remote_key_info)(context, storage_context, index, KeyInfo::registered(key.clone(), security_level, purpose));
                }
            }
        }
        println!("update_with_key_id_and_public_key.3: OK");
        Ok(true)
    }

    pub fn update_with_state_information(&mut self, identity: Identity, storage_context: *const c_void, context: *const c_void) -> Result<bool, Error> {
        println!("update_with_state_information: {:?}", identity);
        self.credit_balance = identity.balance();
        for (key_id, public_key) in identity.public_keys_owned() {
            self.update_with_key_id_and_public_key(key_id, public_key, storage_context, context)?;
        }
        self.set_registration_status(IdentityRegistrationStatus::Registered);
        Ok(true)
    }

    pub fn update_with_username_document(&mut self, document: Document, context: *const c_void) {
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
            self.save_username_in_context(context, save_context);
        } else {
            println!("[WARN] Username, lowercase username or domain is nil {:?}", document);
        }
    }

}

impl IdentityModel {

    pub fn create_salted_domain_hashes_documents<'a>(&self, platform_version: &PlatformVersion, salted_domain_hashes: &HashMap<String, [u8; 32]>, document_type: DocumentTypeRef<'a>) -> Result<HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef<'a>, Bytes32, Option<TokenPaymentInfo>)>>, Error> {
        let owner_id = self.identifier();
        let entropy = <[u8; 32]>::random();
        let mut documents = HashMap::<DocumentTransitionActionType, Vec<(Document, DocumentTypeRef, Bytes32, Option<TokenPaymentInfo>)>>::new();
        for username_full_path in salted_domain_hashes.keys() {
            let UsernameStatusInfo { proper, domain, .. } = self.username_statuses.get(username_full_path.as_str()).unwrap();
            let salt = self.salt_for_username(username_full_path).unwrap();
            let mut map = ValueMap::new();
            map.push((Value::Text("label".to_string()), Value::Text(proper.clone().unwrap())));
            map.push((Value::Text("normalizedLabel".to_string()), Value::Text(proper.clone().unwrap().to_lowercase())));
            map.push((Value::Text("normalizedParentDomainName".to_string()), Value::Text(domain.clone().unwrap().clone())));
            map.push((Value::Text("preorderSalt".to_string()), Value::Bytes32(salt)));
            map.push((Value::Text("records".to_string()), Value::Map(ValueMap::from([(Value::Text("identity".to_string()), Value::Identifier(Hash256::from(self.unique_id)))]))));
            map.push((Value::Text("subdomainRules".to_string()), Value::Map(ValueMap::from([(Value::Text("allowSubdomains".to_string()), Value::Bool(false))]))));
            let document = document_type.create_document_from_data(Value::Map(map), owner_id, 1000, 1000, entropy, platform_version)
                .map_err(Error::from)?;
            documents.insert(DocumentTransitionActionType::Create, vec![(document, document_type, Bytes32(entropy), None)]);
        }
        Ok(documents)
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
