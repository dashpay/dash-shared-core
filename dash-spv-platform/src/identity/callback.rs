use std::collections::BTreeMap;
use std::os::raw::c_void;
use std::sync::Arc;
use dpp::prelude::Revision;
use dash_spv_chain::ChainManager;
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_keychain::{KeyChainKey, KeyChainValue};
use dash_spv_storage::StorageContext;
use crate::error::Error;
use crate::identity::controller::SaveIdentity;
use crate::identity::key_info::KeyInfo;
use crate::identity::model::{ContextType, IdentityModel};
use crate::models::contact_request::ContactRequest;
use crate::models::profile::ProfileModel;
use crate::models::transient_dashpay_user::TransientDashPayUser;
use crate::transition::registration_model::RegistrationTransitionModel;

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct IdentityCallbacks {
    pub chain: Arc<ChainManager>,
    pub save: Arc<dyn Fn(/*identity_context*/ContextType, StorageContext, SaveIdentity) -> bool>,

    // pub get_private_key: Arc<dyn Fn(/*context*/*const c_void, /*index*/u32, KeyKind) -> Option<Vec<u8>>>,

    // pub create_new_key: Arc<dyn Fn(/*context*/*const c_void, KeyKind, SecurityLevel, Purpose, bool) -> Result<u32, Error>>,
    pub active_private_keys_are_loaded: Arc<dyn Fn(ContextType, /*is_local*/bool, /*key_info_dictionaries*/ BTreeMap<u32, KeyInfo>) -> Result<bool, Error>>,
    // pub is_active: Arc<dyn Fn(*const c_void, /*is_local*/bool, /*unique_id*/ [u8; 32]) -> bool>,
    // pub is_wallet_transient: Arc<dyn Fn(*const c_void) -> bool>,

    pub has_contact_request_with_id: Arc<dyn Fn(ContextType, StorageContext, /*incoming*/bool, /*request_id*/ [u8; 32]) -> bool>,

    pub matching_dashpay_user_entity: Arc<dyn Fn(ContextType, StorageContext, /*unique_id*/ [u8; 32]) -> *const c_void>,
    pub matching_dashpay_user_entity_created_at: Arc<dyn Fn(ContextType, StorageContext, /*unique_id*/ [u8; 32]) -> u64>,
    pub matching_dashpay_user_entity_remote_profile_revision: Arc<dyn Fn(ContextType, StorageContext, /*unique_id*/ [u8; 32]) -> u64>,
    pub matching_identity_entity: Arc<dyn Fn(ContextType, StorageContext, /*unique_id*/ [u8; 32]) -> *const c_void>,

    pub load_profile: Arc<dyn Fn(ContextType, StorageContext) -> Result<ProfileModel, Error>>,
    // pub has_registration_asset_lock_transaction: Arc<dyn Fn(*const c_void) -> bool>,
    pub get_registration_transition_model: Arc<dyn Fn(ContextType) -> Option<RegistrationTransitionModel>>,

    // pub get_registration_funding_address: Arc<dyn Fn(*const c_void, u32, bool) -> String>,

    // pub has_extended_public_keys: Arc<dyn Fn(*const c_void, /*is_invitation*/bool) -> bool>,
}
impl IdentityCallbacks {
    pub fn new<
        Save: Fn(ContextType, StorageContext, SaveIdentity) -> bool + Sync + Send + 'static,
        // GetPrivateKeyAtIndex: Fn(*const c_void, u32, KeyKind) -> Option<Vec<u8>> + Sync + Send + 'static,
        // CreateNewKey: Fn(*const c_void, KeyKind, SecurityLevel, Purpose, bool) -> Result<u32, Error> + Sync + Send + 'static,
        ActivePrivateKeysAreLoaded: Fn(ContextType, bool, BTreeMap<u32, KeyInfo>) -> Result<bool, Error> + Sync + Send + 'static,
        // IsActive: Fn(*const c_void, /*is_local*/bool, /*unique_id*/[u8; 32]) -> bool + Sync + Send + 'static,
        HasContactRequestWithId: Fn(ContextType, StorageContext, /*incoming*/bool, /*request_id*/[u8; 32]) -> bool + Sync + Send + 'static,
        MatchingIdentityEntity: Fn(ContextType, StorageContext, /*unique_id*/[u8; 32]) -> *const c_void + Sync + Send + 'static,
        MatchingDashPayUserEntity: Fn(ContextType, StorageContext, /*unique_id*/[u8; 32]) -> *const c_void + Sync + Send + 'static,
        MatchingDashPayUserEntityCreatedAt: Fn(ContextType, StorageContext, /*unique_id*/[u8; 32]) -> u64 + Sync + Send + 'static,
        MatchingDashPayUserEntityRemoteProfileRevision: Fn(ContextType, StorageContext, /*unique_id*/[u8; 32]) -> u64 + Sync + Send + 'static,
        GetRegistrationTransitionModel: Fn(ContextType) -> Option<RegistrationTransitionModel> + Sync + Send + 'static,
        LoadProfile: Fn(ContextType, StorageContext) -> Result<ProfileModel, Error> + Sync + Send + 'static,
        // HasRegistrationAssetLockTransaction: Fn(*const c_void) -> bool + Sync + Send + 'static,
        // GetRegistrationFundingAddress: Fn(*const c_void, u32, bool) -> String + Sync + Send + 'static,
    >(
        chain: Arc<ChainManager>,
        save: Save,
        // get_private_key: GetPrivateKeyAtIndex,
        // create_new_key: CreateNewKey,
        active_private_keys_are_loaded: ActivePrivateKeysAreLoaded,
        // is_active: IsActive,
        has_contact_request_with_id: HasContactRequestWithId,
        matching_identity_entity: MatchingIdentityEntity,
        matching_dashpay_user_entity: MatchingDashPayUserEntity,
        matching_dashpay_user_entity_created_at: MatchingDashPayUserEntityCreatedAt,
        matching_dashpay_user_entity_remote_profile_revision: MatchingDashPayUserEntityRemoteProfileRevision,
        load_profile: LoadProfile,
        get_registration_transition_model: GetRegistrationTransitionModel,
        // get_registration_funding_address: GetRegistrationFundingAddress,
        // has_registration_asset_lock_transaction: HasRegistrationAssetLockTransaction,
    ) -> IdentityCallbacks {
        Self {
            chain,
            save: Arc::new(save),
            // get_private_key: Arc::new(get_private_key),
            // create_new_key: Arc::new(create_new_key),
            active_private_keys_are_loaded: Arc::new(active_private_keys_are_loaded),
            // is_active: Arc::new(is_active),
            has_contact_request_with_id: Arc::new(has_contact_request_with_id),
            matching_dashpay_user_entity: Arc::new(matching_dashpay_user_entity),
            matching_dashpay_user_entity_created_at: Arc::new(matching_dashpay_user_entity_created_at),
            matching_dashpay_user_entity_remote_profile_revision: Arc::new(matching_dashpay_user_entity_remote_profile_revision),
            matching_identity_entity: Arc::new(matching_identity_entity),
            load_profile: Arc::new(load_profile),
            // has_registration_asset_lock_transaction: Arc::new(has_registration_asset_lock_transaction),
            get_registration_transition_model: Arc::new(get_registration_transition_model),
            // get_registration_funding_address: Arc::new(get_registration_funding_address),
        }
    }

    pub fn save(&self, context_type: ContextType, storage_context: StorageContext, save_identity: SaveIdentity) -> bool {
        (self.save)(context_type, storage_context, save_identity)
    }

    pub fn get_stored_remote_profile_revision(&self, context_type: ContextType, identity_id: [u8; 32], storage_context: StorageContext) -> u64 {
        (self.matching_dashpay_user_entity_remote_profile_revision)(context_type, storage_context, identity_id)
    }

    pub fn save_incoming_contact_requests(&self, context_type: ContextType, storage_context: StorageContext, requests: Vec<ContactRequest>) -> bool {
        (self.save)(context_type, storage_context, SaveIdentity::ContactRequests(true, requests))
    }
    pub fn save_outgoing_contact_requests(&self, context_type: ContextType, storage_context: StorageContext, requests: Vec<ContactRequest>) -> bool {
        (self.save)(context_type, storage_context, SaveIdentity::ContactRequests(false, requests))
    }

    pub fn get_private_key(&self, model: &IdentityModel, key_index: u32, key_type: KeyKind) -> Option<Vec<u8>> {
        if let Some(wallet_id) = model.wallet_id() {
            let derivation_path = self.chain.get_derivation_path(wallet_id.as_str(), key_type.identity_derivation_kind());
            let ext_public_key_unique_id = self.chain.derivation.standalone_extended_public_key_unique_id(derivation_path);
            let key = KeyChainKey::GetDataBytesKey { key: format!("{}-{}-{}.{}", model.unique_id_string(), ext_public_key_unique_id, model.index, key_index) };
            if let Ok(KeyChainValue::Bytes(key_secret)) = self.chain.keychain.get(key) {
                return Some(key_secret);
            }
        }
        None
    }

    pub fn active_private_keys_are_loaded(&self, context_type: ContextType, is_local: bool, key_info_dictionaries: BTreeMap<u32, KeyInfo>) -> Result<bool, Error> {
        (self.active_private_keys_are_loaded)(context_type, is_local, key_info_dictionaries)
    }

    // pub fn create_new_key_from_key_info(&self, key_info: KeyInfo, identity_entity: *const c_void, index_path: Vec<u32>, derivation_path: *const c_void, storage_context: StorageContext) -> bool {
    //     assert!(identity_entity, "Entity should be present");
    //     if !identity_entity {
    //         return false;
    //     }
    //
    //
    //
    //     // DSDerivationPathEntity *derivationPathEntity = [DSDerivationPathEntity derivationPathEntityMatchingDerivationPath:derivationPath inContext:context];
    //     // NSUInteger count = [DSBlockchainIdentityKeyPathEntity countObjectsInContext:context matching:@"blockchainIdentity == %@ && derivationPath == %@ && path == %@", identityEntity, derivationPathEntity, indexPath];
    //     // if (!count) {
    //     //     DOpaqueKey *key = key_info->key;
    //     //     NSData *privateKeyData = [DSKeyManager privateKeyData:key];
    //     //     if (!privateKeyData) {
    //     //         DKeyKind kind = DKeyInfoKindIndex(key_info);
    //     //         NSAssert(self.isLocal, @"The identity is non-local");
    //     //         DSAuthenticationKeysDerivationPath *derivationPath = (DSAuthenticationKeysDerivationPath *) [self derivationPathForType:kind];
    //     //         DOpaqueKey *privateKey = [derivationPath privateKeyAtIndexPathAsOpt:[indexPath hardenAllItems]];
    //     //
    //     //         NSAssert([DSKeyManager keysPublicKeyDataIsEqual:privateKey key2:key], @"The keys don't seem to match up");
    //     //         privateKeyData = [DSKeyManager privateKeyData:privateKey];
    //     //         DOpaqueKeyDtor(privateKey);
    //     //         NSAssert(privateKeyData, @"Private key data should exist");
    //     //     }
    //     //     DSBlockchainIdentityKeyPathEntity *keyPathEntity = [DSBlockchainIdentityKeyPathEntity managedObjectInBlockedContext:context];
    //     //     keyPathEntity.derivationPath = derivationPathEntity;
    //     //     // TODO: that's wrong should convert KeyType <-> KeyKind
    //     //     keyPathEntity.keyType = DOpaqueKeyToKeyTypeIndex(key);
    //     //     keyPathEntity.keyStatus = DIdentityKeyStatusToIndex(key_info->key_status);
    //     //     NSString *identifier = [NSString stringWithFormat:@"%@-%@-%@", self.uniqueIdString, derivationPath.standaloneExtendedPublicKeyUniqueID, [[indexPath softenAllItems] indexPathString]];
    //     //
    //     //     setKeychainData(privateKeyData, identifier, YES);
    //     //
    //     //     keyPathEntity.path = indexPath;
    //     //     keyPathEntity.publicKeyData = [DSKeyManager publicKeyData:key];
    //     //     keyPathEntity.keyID = (uint32_t)[indexPath indexAtPosition:indexPath.length - 1];
    //     //     keyPathEntity.securityLevel = DSecurityLevelIndex(key_info->security_level);
    //     //     keyPathEntity.purpose = DPurposeIndex(key_info->purpose);
    //     //     [identityEntity addKeyPathsObject:keyPathEntity];
    //     //     return YES;
    //     // } else {
    //     //     return NO; //no need to save the context
    //     // }
    //
    //
    // }

    // pub fn is_active(&self, context: *const c_void, model: &IdentityModel) -> bool {
    //     (self.is_active)(context, model.is_local, model.unique_id)
    // }

    // pub fn is_wallet_transient(&self, model: &IdentityModel) -> bool {
    //     (self.is_wallet_transient)(model.context)
    // }
    pub fn matching_dashpay_user_entity_created_at(&self, context_type: ContextType, unique_id: [u8; 32], storage_context: StorageContext) -> u64 {
        (self.matching_dashpay_user_entity_created_at)(context_type, storage_context, unique_id)
    }

    // pub fn get_registration_funding_address(&self, context_type: ContextType, model: &IdentityModel) -> String {
    //     (self.get_registration_funding_address)(context_type, model.index, model.is_outgoing_invitation)
    // }

    pub fn load_profile(&self, context_type: ContextType, storage_context: StorageContext) -> Result<ProfileModel, Error> {
        (self.load_profile)(context_type, storage_context)
    }
    pub fn save_profile(&self, context_type: ContextType, storage_context: StorageContext, user: TransientDashPayUser) -> bool {
        (self.save)(context_type, storage_context, SaveIdentity::Profile(user))
    }

    pub fn save_profile_revision(&self, context_type: ContextType, storage_context: StorageContext, revision: Revision) -> bool {
        (self.save)(context_type, storage_context, SaveIdentity::ProfileRevision(revision))
    }

    // pub fn has_registration_asset_lock_transaction(&self, context: *const c_void) -> bool {
    //     (self.has_registration_asset_lock_transaction)(context)
    // }
    pub fn get_registration_transition_model(&self, context_type: ContextType) -> Option<RegistrationTransitionModel> {
        (self.get_registration_transition_model)(context_type)
    }

    pub fn has_incoming_contact_request_with_id(&self, context_type: ContextType, storage_context: StorageContext, id: [u8; 32]) -> bool {
        (self.has_contact_request_with_id)(context_type, storage_context, true, id)
    }
    pub fn has_outgoing_contact_request_with_id(&self, context_type: ContextType, storage_context: StorageContext, id: [u8; 32]) -> bool {
        (self.has_contact_request_with_id)(context_type, storage_context, false, id)
    }

    pub fn has_extended_public_keys(&self, model: &IdentityModel) -> bool {
        if !model.is_local && !model.is_outgoing_invitation {
            false
        } else if model.is_local {
            let wallet_context = self.chain.get_wallet_by_id(&model.wallet_id().as_ref().unwrap());
            self.chain.wallet_has_extended_public_key_in_context(wallet_context, DerivationPathKind::IdentityBLS) &&
                self.chain.wallet_has_extended_public_key_in_context(wallet_context, DerivationPathKind::IdentityECDSA) &&
                self.chain.wallet_has_extended_public_key_in_context(wallet_context, DerivationPathKind::IdentityRegistrationFunding) &&
                self.chain.wallet_has_extended_public_key_in_context(wallet_context, DerivationPathKind::IdentityTopupFunding)
        } else if model.is_outgoing_invitation {
            self.chain.wallet_has_extended_public_key(&model.wallet_id().as_ref().unwrap(), DerivationPathKind::InvitationFunding)
        } else {
            false
        }
        // return is_outgoing_invitation
        //     ? [identity.wallet hasExtendedPublicKeyForDerivationPathOfKind:DSDerivationPathKind_InvitationFunding]
        // : [identity.wallet hasExtendedPublicKeyForDerivationPathOfKind:DSDerivationPathKind_IdentityBLS]
        // && [identity.wallet hasExtendedPublicKeyForDerivationPathOfKind:DSDerivationPathKind_IdentityECDSA]
        // && [identity.wallet hasExtendedPublicKeyForDerivationPathOfKind:DSDerivationPathKind_IdentityRegistrationFunding]
        // && [identity.wallet hasExtendedPublicKeyForDerivationPathOfKind:DSDerivationPathKind_IdentityTopupFunding];

    }

}