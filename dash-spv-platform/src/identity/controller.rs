use std::collections::HashMap;
use std::sync::Arc;
use dapi_grpc::Message;
use dashcore::hashes::{sha256d, Hash};
use dashcore::prelude::DisplayHex;
use dpp::document::{Document, DocumentV0Getters};
use dpp::identity::{Identity, Purpose, SecurityLevel};
use dpp::identity::accessors::IdentityGettersV0;
use dpp::identity::identity_public_key::{IdentityPublicKey, KeyID, KeyType};
use dpp::identity::identity_public_key::accessors::v0::IdentityPublicKeyGettersV0;
use dpp::prelude::Revision;
use platform_value::{Value, ValueMap};
use dash_spv_crypto::crypto::byte_util::{Random, Zeroable};
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;
use dash_spv_crypto::derivation::index_path::{IIndexPath, IndexHardSoft};
use dash_spv_crypto::derivation::IndexPath;
use dash_spv_crypto::keys::{BLSKey, ECDSAKey, IKey, KeyError, OpaqueKey};
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::util::address::address::with_public_key_data_and_script_pub_key;
use dash_spv_crypto::util::from_hash160_for_script_map;
use dash_spv_storage::entities::identity::IdentityEntity;
use dash_spv_storage::{StorageContext, StorageRef};
use dash_spv_storage::entities::identity_username::IdentityUsernameEntity;
use dash_spv_storage::entities::key_info::KeyInfoEntity;
use dash_spv_storage::entity::Entity;
use dash_spv_storage::predicate::Predicate;
use crate::document::usernames::UsernameStatus;
use crate::error::Error;
use crate::identity::callback::IdentityCallbacks;
use crate::identity::key_info::KeyInfo;
use crate::identity::key_status::IdentityKeyStatus;
use crate::identity::manager::key_kind_from_key_type;
use crate::identity::model::{ContextType, IdentityModel};
use crate::identity::registration_status::IdentityRegistrationStatus;
use crate::identity::storage::username::SaveUsernameContext;
use crate::identity::username_status_info::UsernameStatusInfo;
use crate::models::contact_request::ContactRequest;
use crate::models::profile::ProfileModel;
use crate::models::transient_dashpay_user::TransientDashPayUser;
use crate::transition::registration_model::RegistrationTransitionModel;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum IdentityCtorType {
    Foreign {
        unique_id: [u8; 32],
        is_transient: bool,
    },
    ForeignWithEntity {
        unique_id: [u8; 32],
        is_transient: bool,
        entity: IdentityEntity,
    },
    Local {
        index: u32
    }
}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum SaveIdentity {
    KeyStatus {
        identity_index: u32,
        key_index: u32,
        key_info: KeyInfo,
    },
    RemoteKeyStatus {
        key_index: u32,
        key_status: IdentityKeyStatus,
    },
    KeyInfo {
        identity_index: u32,
        key_index: u32,
        key_info: KeyInfo,
    },
    RemoteKeyInfo {
        key_index: u32,
        key_info: KeyInfo,
    },
    Username(SaveUsernameContext),
    Profile(TransientDashPayUser),
    ProfileRevision(u64),
    ContactRequests(bool, Vec<ContactRequest>),
    Model(IdentityEntity),

    NewKey {
        identity_id: [u8; 32],
        derivation_path_kind: u32,
        index_path: Vec<u32>,
        key_type: u32,
        public_key_data: Vec<u8>,
        key_status: u8,
        key_id: u32,
        security_level: u8,
        purpose: u8,
    },
    NewTopUpTransaction {
        identity_id: [u8; 32],
        tx_hash: [u8; 32],
    }
}

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct IdentityController {
    pub callbacks: Arc<IdentityCallbacks>,
    pub model: IdentityModel,

    // pub acquire_callbacks: Arc<dyn Fn(*const c_void) -> IdentityCallbacks>,
}

impl Drop for IdentityController {
    fn drop(&mut self) {
        println!("IdentityController is being dropped: {}", self.model.log_prefix());
    }
}

impl IdentityController {

    pub fn save(&self, storage_context: StorageContext, data: SaveIdentity) -> bool {
        self.callbacks.save(self.model.context_type.clone(), storage_context, data)
    }
    pub fn save_model_in_context(&self, storage_context: StorageContext) -> bool {
        self.callbacks.save(self.model.context_type.clone(), storage_context, SaveIdentity::Model(self.to_model_entity()))
    }

    pub fn save_username_in_context_if_need(&self, username_context: SaveUsernameContext) -> bool {
        if !self.model.is_transient /*&& self.is_active()*/ {
            self.callbacks.save(self.model.context_type.clone(), StorageContext::Platform, SaveIdentity::Username(username_context))
        } else {
            false
        }
    }

    pub fn save_initial_username_full_paths_if_need(&self, username_full_paths: Vec<String>) -> bool {
        self.save_username_in_context_if_need(SaveUsernameContext::initial_username_full_paths(self.model.usernames_and_domains(username_full_paths)))
    }

    pub fn save_preordered_username_full_paths_if_need(&self, username_full_paths: Vec<String>) -> bool {
        self.save_username_in_context_if_need(SaveUsernameContext::preordered_username_full_paths(self.model.usernames_and_domains(username_full_paths)))
    }

    pub fn save_confirmed_username_full_paths_if_need(&self, username_full_paths: Vec<String>) -> bool {
        self.save_username_in_context_if_need(SaveUsernameContext::confirmed_username_full_paths(self.model.usernames_and_domains(username_full_paths)))
    }
    pub fn save_confirmed_username_and_domain_if_need(&self, username: &str, normalized_parent_domain_name: &str) -> bool {
        self.save_username_in_context_if_need(SaveUsernameContext::confirmed_username(username, normalized_parent_domain_name))
    }

    pub fn get_stored_remote_profile_revision(&self, storage_context: StorageContext) -> u64 {
        self.callbacks.get_stored_remote_profile_revision(self.model.context_type.clone(), self.model.unique_id, storage_context)
    }

    pub fn active_private_keys_are_loaded(&self) -> Result<bool, Error> {
        self.callbacks.active_private_keys_are_loaded(self.model.context_type.clone(), self.model.is_local, self.model.key_info_dictionaries.clone())
    }

    pub fn save_outgoing_contact_requests(&self, storage_context: StorageContext, requests: Vec<ContactRequest>) -> bool {
        self.callbacks.save_outgoing_contact_requests(self.model.context_type.clone(), storage_context, requests)
    }
    pub fn save_incoming_contact_requests(&self, storage_context: StorageContext, requests: Vec<ContactRequest>) -> bool {
        self.callbacks.save_incoming_contact_requests(self.model.context_type.clone(), storage_context, requests)
    }


    // pub fn create_new_ecdsa_auth_key_of_level_if_needed(&self, level: SecurityLevel, save: bool) -> Result<u32, Error> {
    //     if !self.model.has_key_of_security_level(level) {
    //         self.callbacks.create_new_ecdsa_auth_key(self.model.context, level, save)
    //     } else {
    //         Ok(u32::MAX)
    //     }
    // }

    // pub fn is_active(&self) -> bool {
    //     self.callbacks.is_active(&self.model)
    // }

    // pub fn is_wallet_transient(&self) -> bool {
        // self.callbacks.is_active(&self.model)
    // }

    pub fn matching_dashpay_user_entity_created_at(&self, storage_context: StorageContext) -> u64 {
        self.callbacks.matching_dashpay_user_entity_created_at(self.model.context_type.clone(), self.model.unique_id, storage_context)
    }

    // pub fn get_registration_funding_address(&self) -> String {
    //     self.callbacks.get_registration_funding_address(&self.model)
    // }

    pub fn load_profile(&self, storage_context: StorageContext) -> Result<ProfileModel, Error> {
        self.callbacks.load_profile(self.model.context_type.clone(), storage_context)
    }
    pub fn save_profile(&self, storage_context: StorageContext, user: TransientDashPayUser) -> bool {
        self.callbacks.save_profile(self.model.context_type.clone(), storage_context, user)
    }

    pub fn save_profile_revision(&self, storage_context: StorageContext, revision: Revision) -> bool {
        self.callbacks.save_profile_revision(self.model.context_type.clone(), storage_context, revision)
    }

    // pub fn has_registration_asset_lock_transaction(&self, context: *const c_void) -> bool {
    //     self.callbacks.has_registration_asset_lock_transaction(context)
    // }
    pub fn get_registration_transition_model(&self) -> Option<RegistrationTransitionModel> {
        self.callbacks.get_registration_transition_model(self.model.context_type.clone())
    }

    pub fn has_incoming_contact_request_with_id(&self, storage_context: StorageContext, id: [u8; 32]) -> bool {
        self.callbacks.has_incoming_contact_request_with_id(self.model.context_type.clone(), storage_context, id)
    }
    pub fn has_outgoing_contact_request_with_id(&self, storage_context: StorageContext, id: [u8; 32]) -> bool {
        self.callbacks.has_outgoing_contact_request_with_id(self.model.context_type.clone(), storage_context, id)
    }

    // pub fn create_and_publish_registration_transaction(
    //     &self,
    //     topup_duff_amount: u64,
    //     funding_account_context: *const c_void,
    //     prompt: String,
    //     steps: u32,
    // ) -> Result<u32, AssetLockSubmissionError> {
    //     (self.create_and_publish_registration_transaction)(self.model.context, topup_duff_amount, funding_account_context, prompt, steps)
    // }

}

#[ferment_macro::export]
impl IdentityController {
    pub fn new<
        // Save: Fn(*const c_void, StorageContext, SaveIdentity) -> bool + Sync + Send + 'static,
        // GetPrivateKeyAtIndex: Fn(*const c_void, u32, KeyKind) -> Option<Vec<u8>> + Sync + Send + 'static,
        // CreateNewKey: Fn(*const c_void, KeyKind, SecurityLevel, Purpose, bool) -> Result<u32, Error> + Sync + Send + 'static,
        // ActivePrivateKeysAreLoaded: Fn(*const c_void, bool, BTreeMap<u32, KeyInfo>) -> Result<bool, Error> + Sync + Send + 'static,
        // IsActive: Fn(*const c_void, /*is_local*/bool, /*unique_id*/[u8; 32]) -> bool + Sync + Send + 'static,
        // IsWalletTransient: Fn(*const c_void) -> bool + Sync + Send + 'static,
        // HasContactRequestWithId: Fn(*const c_void, StorageContext, /*incoming*/bool, /*request_id*/[u8; 32]) -> bool + Sync + Send + 'static,
        // MatchingIdentityEntity: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> *const c_void + Sync + Send + 'static,
        // MatchingDashPayUserEntity: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> *const c_void + Sync + Send + 'static,
        // MatchingDashPayUserEntityCreatedAt: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> u64 + Sync + Send + 'static,
        // MatchingDashPayUserEntityRemoteProfileRevision: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> u64 + Sync + Send + 'static,
        // GetRegistrationTransitionModel: Fn(*const c_void) -> Option<RegistrationTransitionModel> + Sync + Send + 'static,
        // LoadProfile: Fn(*const c_void, StorageContext) -> Result<ProfileModel, Error> + Sync + Send + 'static,
        // HasRegistrationAssetLockTransaction: Fn(*const c_void) -> bool + Sync + Send + 'static,
        // GetRegistrationFundingAddress: Fn(*const c_void, u32, bool) -> String + Sync + Send + 'static,
        // HasExtendedPublicKeys: Fn(*const c_void, bool) -> bool + Sync + Send + 'static,
        // AcquireCallbacks: Fn(*const c_void) -> IdentityCallbacks + Sync + Send + 'static,
    >(
        unique_id: [u8; 32],
        status: IdentityRegistrationStatus,
        is_local: bool,
        is_transient: bool,
        identity_callbacks: Arc<IdentityCallbacks>,
        context_type: ContextType,
        // maybe_wallet_id: Option<String>,
        // context: *const c_void,
        // save: Save,
        // get_private_key: GetPrivateKeyAtIndex,
        // create_new_key: CreateNewKey,
        // active_private_keys_are_loaded: ActivePrivateKeysAreLoaded,
        // is_active: IsActive,
        // is_wallet_transient: IsWalletTransient,
        // has_contact_request_with_id: HasContactRequestWithId,
        // matching_identity_entity: MatchingIdentityEntity,
        // matching_dashpay_user_entity: MatchingDashPayUserEntity,
        // matching_dashpay_user_entity_created_at: MatchingDashPayUserEntityCreatedAt,
        // matching_dashpay_user_entity_remote_profile_revision: MatchingDashPayUserEntityRemoteProfileRevision,
        // load_profile: LoadProfile,
        // get_registration_transition_model: GetRegistrationTransitionModel,
        // get_registration_funding_address: GetRegistrationFundingAddress,
        // has_registration_asset_lock_transaction: HasRegistrationAssetLockTransaction,
        // has_extended_public_keys: HasExtendedPublicKeys,
        // acquire_callbacks: AcquireCallbacks,
    ) -> Self {
        Self::with_model(
            IdentityModel::new(
                unique_id,
                status,
                is_local,
                is_transient,
                context_type,
                // maybe_wallet_id
            ),
            identity_callbacks,
        )
    }

    pub fn with_model(
        model: IdentityModel,
        callbacks: Arc<IdentityCallbacks>,
    ) -> IdentityController {
        Self {
            model,
            callbacks,
        }

    }

    pub fn at_index_with_identity(
        index: u32,
        identity: Identity,
        wallet_id: String,
        // context_type: ContextType,
        // identity_context: *const c_void,
        callbacks: Arc<IdentityCallbacks>,
    ) -> IdentityController {
        Self::with_model(
            IdentityModel::at_index_with_identity(index, identity, ContextType::Wallet(wallet_id)),
            callbacks,
        )
    }

    pub fn asset_lock_registration_address(&self) -> String {
        let script_map_ref = self.callbacks.chain.chain_type_ref().script_map_ref();
        if let Some(ref model) = self.model.asset_lock_registration_model {
            if let Some(script_hash) = model.maybe_credit_burn_public_key_hash() {
                return from_hash160_for_script_map(script_hash.as_byte_array(), script_map_ref)
            }
        }
        let public_key = self.callbacks.chain.public_key_data_at_index_path_for_derivation_kind(
            self.model.wallet_id().as_ref().unwrap(),
            vec![self.model.index],
            self.model.registration_derivation_kind()
        );
        with_public_key_data_and_script_pub_key(&public_key, script_map_ref.pubkey)
    }

    // NSString *assetLockRegistrationAddress = identity.registrationAssetLockTransaction
    //     ? [DSKeyManager addressFromHash160:identity.registrationAssetLockTransaction.creditBurnPublicKeyHash forChainType:identity.chain.chainType]
    // : [[[DSDerivationPathFactory sharedInstance] derivationPathOfKind:identity.isOutgoingInvitation
    //     ? DSDerivationPathKind_InvitationFunding
    //     : DSDerivationPathKind_IdentityRegistrationFunding forWallet:identity.wallet] addressAtIndexPath:[NSIndexPath indexPathWithIndex:identity.index]];
    //


    pub fn is_unsynced_at_block_height(&self, block_height: u32) -> bool {
        match &self.model.asset_lock_registration_model {
            None => {
                println!("{} Unsynced identity {} (asset lock tx unknown) {}", self.log_prefix(), self.unique_id().to_lower_hex_string(), self.model.asset_lock_registration_hash.map(|hash| hash.to_lower_hex_string()).unwrap_or_default());
                true
            },
            Some(model) if model.core_chain_locked_height == i32::MAX as u32 => {
                println!("{} Unsynced identity {} (asset lock tx unknown or has unknown height) {} {:?}", self.log_prefix(), self.unique_id().to_lower_hex_string(), self.model.asset_lock_registration_hash.map(|hash| hash.to_lower_hex_string()).unwrap_or_default(), self.model.asset_lock_registration_model);
                true
            }
            Some(..) if block_height > self.model.sync_block_height => {
                println!("{} Unsynced identity {} (lastSyncBlockHeight ({}) > dashpaySyncronizationBlockHeight {})", self.log_prefix(), self.unique_id().to_lower_hex_string(), block_height, self.model.sync_block_height);
                //If they are equal then the blockchain identity is synced
                //This is because the dashpaySyncronizationBlock represents the last block for the bloom filter used in L1 should be considered valid
                //That's because it is set at the time with the hash of the last
                true
            },
            _ => false
        }
    }

    pub fn apply_identity_entity(&mut self, entity: IdentityEntity, context: StorageContext) {
        for IdentityUsernameEntity {
            domain,
            salt,
            status,
            string_value: username,
            ..
        } in entity.usernames {
            let username_status = UsernameStatus::from(status);
            if !salt.is_zero() {
                self.model.add_username_with_salt(username.clone(), domain, username_status, salt);
                self.model.add_salt(username, salt);
            } else {
                self.model.add_username(username, domain, username_status);
            }
        }
        self.model.set_credit_balance(entity.credit_balance);
        self.model.set_registration_status(IdentityRegistrationStatus::from(entity.registration_status));
        self.model.set_last_checked_profile_timestamp(entity.last_checked_profiles);
        self.model.set_last_checked_usernames_timestamp(entity.last_checked_usernames);
        self.model.set_last_checked_outgoing_contacts_timestamp(entity.last_checked_outgoing_friends);
        self.model.set_last_checked_incoming_contacts_timestamp(entity.last_checked_incoming_friends);

        let block_hash = entity.dashpay_synchronization_block_hash;
        self.model.set_sync_block_hash(block_hash);
        if block_hash.is_zero() {
            self.model.set_sync_block_height(0);
        } else {
            let block_height = self.callbacks.chain.block_height_by_hash(entity.dashpay_synchronization_block_hash);
            if block_height == u32::MAX {
                self.model.set_sync_block_height(0);
            } else {
                self.model.set_sync_block_height(block_height);
            }
        }
        for KeyInfoEntity {
            index_path,
            key_id,
            key_kind,
            key_status,
            public_key_data,
            purpose,
            security_level,
        } in entity.key_paths {
            let mut added = false;
            if let Some(key_indexes) = index_path {
                let key_type = KeyKind::from(key_kind);
                let derivation_path_kind = match key_type {
                    KeyKind::ECDSA => DerivationPathKind::IdentityECDSA,
                    KeyKind::BLS | KeyKind::BLSBasic => DerivationPathKind::IdentityBLS,
                    KeyKind::ED25519 => panic!("Wrong Key Type"),
                };
                if let Ok(extended_private_key_data) = self.callbacks.chain.get_extended_private_key_data(self.model.wallet_id().as_ref().unwrap(), derivation_path_kind) {
                    let index_path = IndexPath::new(key_indexes);
                    if let Ok(private_key) = key_type.derive_key_from_extended_private_key_data_for_index_path_u32(&extended_private_key_data, index_path.harden_all_items()) {
                        if let Ok(public_key) = key_type.key_with_public_key_data(&private_key.public_key_data()) {
                            self.model.add_key_info(
                                index_path.last_index().soften(),
                                KeyInfo {
                                    key: public_key,
                                    key_status: IdentityKeyStatus::from(key_status),
                                    security_level: SecurityLevel::try_from(security_level).expect("Wrong security level"),
                                    purpose: Purpose::try_from(purpose).expect("Wrong purpose")
                                }
                            );
                            added = true;
                        }
                    }
                }
            }
            if !added {
                self.model.register_key_from_key_path_entity(key_kind as u16, &public_key_data, security_level as u16, purpose as u16, key_id, key_status as u16);
            }
        }
       if self.model.is_local || self.model.is_outgoing_invitation {
            if let Some(tx_entity) = entity.registration_funding_transaction {
                self.model.asset_lock_registration_hash = tx_entity.base.base.transaction_hash.map(|hash| hash.tx_hash);
                println!("{} AssetLockTX: Entity Attached: txHash: {}", self.log_prefix(), self.model.asset_lock_registration_hash.unwrap_or_default().to_lower_hex_string());
            } else if let Some(locked_outpoint) = self.model.locked_outpount {
                let (txid_data, vout_data) = locked_outpoint.split_at(32);
                let index: [u8; 4] = vout_data.try_into().expect("vout is not 4 bytes");
                let tx_hash: [u8; 32] = txid_data.try_into().expect("txid is not 32 bytes");

                println!("{} AssetLockTX: Load: LockedOutpoint: {}: {}", self.log_prefix(), tx_hash.to_lower_hex_string(), u32::from_le_bytes(index));
                if let Ok(Entity::AssetLockTransaction(tx_entity)) = self.callbacks.chain.storage_ref().get(Predicate::GetAssetLockTransactionByTxHash { tx_hash }, context) {
                    self.model.asset_lock_registration_hash = tx_entity.base.base.transaction_hash.map(|hash| hash.tx_hash);
                }
            }
        }

    }


    pub fn to_model_entity(&self) -> IdentityEntity {
        self.model.to_entity()
    }

    pub fn log_prefix(&self) -> String {
        self.model.log_prefix()
    }
    pub fn unique_id(&self) -> [u8; 32] {
        self.model.unique_id()
    }
    pub fn is_local(&self) -> bool {
        self.model.is_local
    }
    pub fn index(&self) -> u32 {
        self.model.index
    }
    pub fn set_index(&mut self, index: u32) {
        self.model.index = index;
    }

    pub fn maybe_private_key_for_identity_public_key(&self, identity_public_key: &IdentityPublicKey) -> Option<OpaqueKey> {
        let key_id = identity_public_key.id();
        let key_type = identity_public_key.key_type();
        let key_kind = key_kind_from_key_type(key_type);
        self.model.key_at_index(key_id).and_then(|key| {
            if key.public_key_data().eq(identity_public_key.data().as_slice()) {
                if let Some(maybe_private_key_data) = self.callbacks.get_private_key(&self.model, key_id, key_kind) {
                    key_kind.key_with_private_key_data_as_opt(&maybe_private_key_data)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    pub fn decrypted_identity_model(&mut self, model: &IdentityModel, request: ContactRequest) -> Result<OpaqueKey, Error> {
        let public_key = model.key_at_index(request.sender_key_index as u32)
            .ok_or(Error::Any(0, "Model has no keys".to_string()))?;
        self.decrypted_public_key_data_with_key(public_key, request)
    }

    pub fn decrypted_public_key_data_with_key(&self, key: OpaqueKey, request: ContactRequest) -> Result<OpaqueKey, Error> {
        let index = if self.model.unique_id.eq(&request.recipient) {
            request.sender_key_index
        } else {
            request.recipient_key_index
        } as u32;
        let kind = key.kind();
        let key_data = self.callbacks.get_private_key(&self.model, index, kind)
            .ok_or(Error::KeyError(KeyError::Any("Key should exist".to_string())))?;

        kind.key_with_private_key_data(&key_data)
            .and_then(|private_key| private_key.decrypt_data(key, &request.encrypted_public_key))
            .and_then(|data| kind.key_with_extended_private_key_data(&data))
            .map_err(Error::KeyError)
    }

/*    pub fn first_index_of_ecdsa_auth_key_create_if_needed(&self, level: SecurityLevel, save_key_if_need: bool) -> Result<u32, Error> {
        if let Some(index) = self.model.first_index_of_key_kind_and_security_level(KeyKind::ECDSA, level) {
            Ok(index)
        } else if self.model.is_local {
            self.callbacks.create_new_ecdsa_auth_key(&self.model, level, save_key_if_need)
        } else {
            Ok(u32::MAX)
        }
    }
*/
    pub fn update_with_key_id_and_public_key(&mut self, index: KeyID, public_key: IdentityPublicKey, is_active: bool, storage_context: StorageContext) -> Result<bool, Error> {
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
        let maybe_key_info = self.model.key_info_at_index(index);
        let add_key_info = maybe_key_info.as_ref().map(|key_info| key_info.has_key_with_public_key_data(&public_key_data.0)).unwrap_or_default();

        if self.model.is_local {
            if maybe_key_info.is_some() {
                if add_key_info {
                    self.model.add_key_info(index, KeyInfo::registered(key.clone(), security_level, purpose));
                    if !self.model.is_transient && !storage_context.is_none() && is_active {
                        self.callbacks.save(self.model.context_type.clone(), storage_context, SaveIdentity::KeyStatus {
                            identity_index: self.index(),
                            key_index: index,
                            key_info: KeyInfo::registered(key.clone(), security_level, purpose),
                        });
                    }
                } else {
                    return Err(Error::Any(0, "these should really match up".to_string()));
                }
            } else {
                if add_key_info {
                    self.model.add_key_info(index, KeyInfo::registered(key.clone(), security_level, purpose));
                }
                if !self.model.is_transient && !storage_context.is_none() && is_active {
                    self.callbacks.save(self.model.context_type.clone(), storage_context, SaveIdentity::KeyInfo {
                        identity_index: self.index(),
                        key_index: index,
                        key_info: KeyInfo::registered(key.clone(), security_level, purpose),
                    });
                }
            }
        } else {
            if let Some(KeyInfo { key_status, .. }) = maybe_key_info {
                if add_key_info {
                    self.model.add_key_info(index, KeyInfo::registered(key, security_level, purpose));
                    if !self.model.is_transient && !storage_context.is_none() && is_active && !key_status.is_registered() {
                        self.callbacks.save(self.model.context_type.clone(), storage_context, SaveIdentity::RemoteKeyStatus { key_index: index, key_status: IdentityKeyStatus::Registered });
                    }
                } else {
                    return Err(Error::Any(0, "these should really match up".to_string()));
                }
            } else {
                if add_key_info {
                    self.model.add_key_info(index, KeyInfo::registered(key.clone(), security_level, purpose));
                }
                if !self.model.is_transient && !storage_context.is_none() && is_active {
                    self.callbacks.save(self.model.context_type.clone(), storage_context, SaveIdentity::RemoteKeyInfo { key_index: index, key_info: KeyInfo::registered(key.clone(), security_level, purpose)});
                }
            }
        }
        println!("update_with_key_id_and_public_key.3: OK");
        Ok(true)
    }

    pub fn has_extended_public_keys(&self) -> bool {
        self.callbacks.has_extended_public_keys(&self.model)
    }

    pub fn salted_domain_hashes_for_username_full_paths_values(&mut self, username_full_paths: &Vec<String>) -> Value {
        let mut map = ValueMap::new();
        for unregistered_username_full_path in username_full_paths {
            let mut salted_domain = Vec::new();
            let is_initial = self.model.username_statuses.get(unregistered_username_full_path.as_str()).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default();
            let maybe_salt = self.model.salt_for_username(&unregistered_username_full_path);
            let salt = if is_initial || maybe_salt.is_none() {
                let random_salt = <[u8; 32]>::random();
                self.model.add_salt(unregistered_username_full_path.clone(), random_salt);
                let UsernameStatusInfo { proper, domain, status, .. } = self.model.username_statuses.get(unregistered_username_full_path.as_str()).unwrap();
                let username = proper.clone().unwrap();
                let domain = domain.clone().unwrap();
                self.save_username_in_context_if_need(SaveUsernameContext::salted_username(username, domain, random_salt, *status));
                random_salt
            } else {
                maybe_salt.unwrap()
            };
            salted_domain.extend_from_slice(&salt);
            salted_domain.extend(unregistered_username_full_path.encode_to_vec());
            map.push((Value::Text(unregistered_username_full_path.clone()), Value::Bytes32(sha256d::Hash::hash(&salted_domain).to_byte_array())));
            self.model.add_salt(unregistered_username_full_path.clone(), salt);
        }
        Value::Map(map)
    }


    pub fn salted_domain_hashes_for_username_full_paths(&mut self, username_full_paths: &Vec<String>) -> HashMap<String, [u8; 32]> {
        let mut salted_domain_hashes = HashMap::new();
        for unregistered_username_full_path in username_full_paths {
            let mut salted_domain = Vec::new();
            let is_initial = self.model.username_statuses.get(unregistered_username_full_path.as_str()).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default();
            let maybe_salt = self.model.salt_for_username(&unregistered_username_full_path);
            let salt = if is_initial || maybe_salt.is_none() {
                let random_salt = <[u8; 32]>::random();
                self.model.add_salt(unregistered_username_full_path.clone(), random_salt);
                let UsernameStatusInfo { proper, domain, status, .. } = self.model.username_statuses.get(unregistered_username_full_path.as_str()).unwrap();
                let username = proper.clone().unwrap();
                let domain = domain.clone().unwrap();
                self.save_username_in_context_if_need(SaveUsernameContext::salted_username(username, domain, random_salt, *status));
                random_salt
            } else {
                maybe_salt.unwrap()
            };
            salted_domain.extend_from_slice(&salt);
            salted_domain.extend(unregistered_username_full_path.encode_to_vec());
            salted_domain_hashes.insert(unregistered_username_full_path.clone(), sha256d::Hash::hash(&salted_domain).to_byte_array());
            self.model.add_salt(unregistered_username_full_path.clone(), salt);
        }
        salted_domain_hashes
    }

    pub fn process_salted_domain_hash_document(&mut self, username_full_path: &str, hash: [u8; 32], document: &Document) -> bool {
        match document.get("saltedDomainHash") {
            Some(Value::Bytes32(salted_domain_hash)) if hash.eq(salted_domain_hash) => {
                self.model.set_username_status(username_full_path.to_string(), UsernameStatus::Preordered);
                self.save_username_in_context_if_need(SaveUsernameContext::preordered_username_full_path(username_full_path));
                true
            }
            _ => false
        }
    }

    pub fn update_with_state_information(&mut self, identity: Identity, is_active: bool, storage_context: StorageContext) -> Result<bool, Error> {
        println!("update_with_state_information: {:?}", identity);
        self.model.credit_balance = identity.balance();
        for (key_id, public_key) in identity.public_keys_owned() {
            self.update_with_key_id_and_public_key(key_id, public_key, is_active, storage_context)?;
        }
        self.model.set_registration_status(IdentityRegistrationStatus::Registered);
        Ok(true)
    }

    pub fn update_with_username_document(&mut self, document: Document) {
        if let Some(save_username_context) = self.model.update_with_username_document(document) {
            self.save_username_in_context_if_need(save_username_context);
        }
    }

}