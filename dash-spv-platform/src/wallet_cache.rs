use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::Arc;
use dashcore::hashes::{sha256d, Hash};
use dashcore::prelude::DisplayHex;
use dashcore::transaction::outpoint::OutPoint;
use dpp::identity::IdentityPublicKey;
use dash_spv_chain::{ChainManager, TransactionModel};
use dash_spv_chain::derivation::DerivationRef;
use dash_spv_chain::notification::NotificationRef;
use dash_spv_crypto::crypto::byte_util::Zeroable;
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;
use dash_spv_crypto::keys::OpaqueKey;
use dash_spv_crypto::util::from_hash160_for_script_map;
use dash_spv_crypto::util::address::address::with_public_key_data_and_script_pub_key;
use dash_spv_keychain::{IdentityDictionaryItemValue, KeyChainKey, KeyChainValue, KeychainRef};
use dash_spv_macro::ChainManager;
use dash_spv_storage::predicate::Predicate;
use dash_spv_storage::{StorageContext, StorageRef};
use dash_spv_storage::entities::invitation::InvitationEntity;
use dash_spv_storage::entity::Entity;
use dash_spv_storage::error::StorageError;
use crate::document::usernames::UsernameStatus;
use crate::error::Error;
use crate::identity::callback::IdentityCallbacks;
use crate::identity::controller::{IdentityController, SaveIdentity};
use crate::identity::invitation::{InvitationLinkInfo, InvitationModel};
use crate::identity::model::IdentityModel;
use crate::notifications::InvitationDidUpdate;

pub const WALLET_BLOCKCHAIN_USERS_KEY: &str = "WALLET_BLOCKCHAIN_USERS_KEY";
pub const WALLET_BLOCKCHAIN_INVITATIONS_KEY: &str = "WALLET_BLOCKCHAIN_INVITATIONS_KEY";

#[derive(ChainManager)]
pub struct WalletCache {
    pub wallet_id: String,
    pub chain: Arc<ChainManager>,
    pub identity_callbacks: Arc<IdentityCallbacks>,

    pub identities: HashMap<[u8; 32], IdentityController>,
    pub default_identity_index: Option<u32>,
    pub invitations: HashMap<[u8; 36], InvitationModel>,

    pub invitations_to_identities: HashMap<[u8; 36], [u8; 32]>,
}

impl WalletCache {
    pub fn new(
        wallet_id: String,
        chain: Arc<ChainManager>,
        identity_callbacks: Arc<IdentityCallbacks>,
    ) -> WalletCache {
        Self {
            wallet_id,
            chain,
            identities: Default::default(),
            default_identity_index: None,
            invitations: Default::default(),
            invitations_to_identities: Default::default(),
            identity_callbacks
        }
    }

    pub fn wallet_id_ref(&self) -> &str {
        self.wallet_id.as_str()
    }

    pub fn wallet_identities_key(&self) -> String {
        format!("{WALLET_BLOCKCHAIN_USERS_KEY}_{}", self.wallet_id)
    }
    pub fn wallet_identities_default_index_key(&self) -> String {
        format!("{WALLET_BLOCKCHAIN_USERS_KEY}_{}_DEFAULT_INDEX", self.wallet_id)
    }
    pub fn wallet_invitations_key(&self) -> String {
        format!("{WALLET_BLOCKCHAIN_INVITATIONS_KEY}_{}", self.wallet_id)
    }

    pub fn wallet(&self) -> *const c_void {
        self.chain.get_wallet_by_id(self.wallet_id_ref())
    }

    pub fn identity_by_unique_id_mut(&mut self, unique_id: &[u8; 32]) -> Option<&mut IdentityController> {
        self.identities.get_mut(unique_id)
    }
    pub fn invitation_by_outpoint_data_mut(&mut self, outpoint_data: &[u8; 36]) -> Option<&mut InvitationModel> {
        self.invitations.get_mut(outpoint_data)
    }
    pub fn identity_by_index_mut(&mut self, index: u32) -> Option<&mut IdentityController> {
        self.identities.values_mut().find_map(|controller| (controller.index() == index).then_some(controller))
    }
}
#[ferment_macro::export]
impl WalletCache {

    pub fn mark_address_hash_as_used(&self, hash: &[u8; 20], kind: DerivationPathKind) {
        let address = from_hash160_for_script_map(hash, self.chain.controller.chain_type.script_map_ref());
        let derivation_path = self.chain.get_derivation_path(self.wallet_id_ref(), kind);
        self.chain.derivation_ref().mark_address_as_used(derivation_path, address);
    }



    pub fn unregister_identity(&mut self, unique_id: &[u8; 32], storage_context: StorageContext) {
        self.identities.remove(unique_id);
        let keychain_ref = self.chain.keychain_ref();
        let keychain_key = KeyChainKey::wallet_identities_key(self.wallet_id_ref());
        let maybe_keychain_wallet_identities = keychain_ref.get(keychain_key.clone());

        if let Ok(KeyChainValue::IdentityDictionary(mut dict)) = maybe_keychain_wallet_identities {
            dict.remove(unique_id);
            let _ = keychain_ref.set(keychain_key, KeyChainValue::IdentityDictionary(dict), false);
        }
        let _ = self.storage_ref()
            .delete(Predicate::delete_identity(unique_id), storage_context);

    }

    pub fn add_identity(&mut self, controller: IdentityController) -> bool {
        if controller.unique_id().eq(&[0u8; 32]) {
            return false;
        }
        self.identities.insert(controller.unique_id(), controller);
        true
    }

    pub fn contains_identity(&self, identity_id: &[u8; 32]) -> bool {
        self.identities.contains_key(identity_id)
    }

    pub fn maybe_asset_lock_transaction_by_tx_hash(&self, tx_hash: [u8; 32], storage_context: StorageContext) -> Result<Entity, StorageError> {
        self.chain.storage_ref().get(Predicate::GetAssetLockTransactionByTxHash { tx_hash }, storage_context)
    }

    pub fn load_identity(&mut self, identity_id: [u8; 32], key_chain_data: IdentityDictionaryItemValue) -> Result<IdentityController, Error> {
        let storage_context = StorageContext::Chain;
        if let Ok(Entity::Identity(entity)) = self .chain.storage_ref().get(Predicate::GetInvitationByIdentityId { identity_id }, storage_context) {
            let mut identity = match key_chain_data {
                IdentityDictionaryItemValue::Index { index } => {
                    IdentityController::with_model(IdentityModel::with_index_and_unique_id(index, identity_id, self.wallet_id.clone()), Arc::clone(&self.identity_callbacks))
                }
                IdentityDictionaryItemValue::Outpoint { index, locked_outpoint_data } => {
                    IdentityController::with_model(IdentityModel::with_index_and_locked_outpoint(index, locked_outpoint_data, self.wallet_id.clone()), Arc::clone(&self.identity_callbacks))
                }
            };
            identity.apply_identity_entity(entity, storage_context);
            Ok(identity)
        } else {
            let identity = match key_chain_data {
                IdentityDictionaryItemValue::Index { index } => {
                    IdentityModel::with_index_and_unique_id(index, identity_id, self.wallet_id.clone())
                }
                IdentityDictionaryItemValue::Outpoint { index, locked_outpoint_data } => {
                    let outpoint = OutPoint::from(locked_outpoint_data.clone());
                    if let Ok(entity) = self.maybe_asset_lock_transaction_by_tx_hash(outpoint.txid.to_byte_array(), storage_context) {
                        if let Some(transaction) = self.chain.get_transaction_by_entity(entity) {
                            if let Some(script_pub_key_hash) = transaction.maybe_credit_burn_public_key_hash() {
                                if self.check_derivation_path_index_for_credit_burn_public_key_hash(script_pub_key_hash.as_byte_array(), DerivationPathKind::IdentityRegistrationFunding, index) {
                                    IdentityModel::with_asset_lock_transaction(index, transaction, self.wallet_id.clone())
                                } else {
                                    assert!(false, "We should implement this");
                                    return Err(Error::DerivationIndexesDoesntMatch);
                                }
                            } else {
                                return Err(Error::AssetLockTransactionShouldBeKnown);
                            }

                        } else {
                            // We also don't have the registration funding transaction
                            IdentityModel::with_index_and_unique_id(index, identity_id, self.wallet_id.clone())
                        }
                    } else {
                        IdentityModel::with_index_and_unique_id(index, identity_id, self.wallet_id.clone())
                    }
                }
            };

            self.storage_ref().set(Entity::Identity(identity.to_entity()), StorageContext::Platform);
            let controller = IdentityController::with_model(identity, Arc::clone(&self.identity_callbacks));
            self.register_identity(controller.clone());
            Ok(controller)
        }

    }


    pub fn setup_identities(&mut self) -> Result<HashMap<[u8; 32], IdentityController>, Error> {
        if !self.identities.is_empty() {
            return Ok(self.identities.clone());
        }

        let maybe_keychain_wallet_identities = self.chain.keychain_ref().get(KeyChainKey::wallet_identities_key(self.wallet_id_ref()));

        if let Err(error) = maybe_keychain_wallet_identities {
            println!("[PlatformSDK] Error getting identities from keychain {}: {error:?}", self.wallet_id);
            return Err(Error::KeychainError(error));
        }

        let maybe_keychain_wallet_default_identity_index = self.chain.keychain_ref().get(KeyChainKey::wallet_identities_default_index_key(self.wallet_id_ref()));
        if let Err(error) = maybe_keychain_wallet_default_identity_index {
            println!("[PlatformSDK] Error getting default identity index from keychain {}: {error:?}", self.wallet_id);
            return Err(Error::KeychainError(error));
        }

        if let Ok(KeyChainValue::None) = maybe_keychain_wallet_identities {
            return Ok(HashMap::default());
        }

        let default_index = if let Ok(KeyChainValue::Int64(index)) = maybe_keychain_wallet_default_identity_index {
            index as u32
        } else {
            0
        };

        if let Ok(KeyChainValue::IdentityDictionary(keychain_dictionary)) = maybe_keychain_wallet_identities {
            for (identity_id, value) in keychain_dictionary {
                if let Ok(controller) = self.load_identity(identity_id, value) {
                    let index = controller.index();
                    self.identities.insert(controller.unique_id(), controller);
                    if index == default_index {
                        self.default_identity_index = Some(index);
                    }
                }
            }
        }
        Ok(self.identities.clone())
    }

    pub fn check_derivation_path_index_for_credit_burn_public_key_hash(&self, hash: &[u8; 20], kind: DerivationPathKind, index: u32) -> bool {
        let derivation_path = self.chain.get_derivation_path(self.wallet_id_ref(), kind);
        let public_key_data = self.chain.public_key_data_at_index_path(derivation_path, vec![index]);
        let chain_script_map = self.chain.chain_type_ref().script_map();
        let derived_address = with_public_key_data_and_script_pub_key(&public_key_data, chain_script_map.pubkey);
        let address_from_hash = from_hash160_for_script_map(hash, &chain_script_map);
        derived_address == address_from_hash
    }



    pub fn default_identity(&self) -> Option<&IdentityController> {
        self.identity_by_index(self.default_identity_index.unwrap_or_default())
    }

    pub fn has_default_identity(&self) -> bool {
        self.default_identity_index.is_some()
    }

    pub fn set_default_identity_index(&mut self, index: u32) {
        self.default_identity_index = Some(index);
    }

    pub fn identity_by_index(&self, index: u32) -> Option<&IdentityController> {
        self.identities.values().find_map(|controller| controller.index().eq(&index).then_some(controller))
    }
    pub fn identity_by_unique_id(&self, unique_id: &[u8; 32]) -> Option<IdentityController> {
        self.identities.get(unique_id).cloned()
    }

    pub fn identities(&self) -> Vec<IdentityController> {
        self.identities.values().cloned().collect()
    }

    pub fn identity_by_public_key(&self, public_key: &IdentityPublicKey) -> Option<IdentityController> {
        self.identities.values()
            .find_map(|controller|
                controller.model
                    .has_identity_public_key(public_key)
                    .then_some(controller.clone()))

    }
    pub fn identity_private_key_by_public_key(&self, public_key: &IdentityPublicKey) -> Option<OpaqueKey> {
        self.identities.values()
            .find_map(|controller|
                controller.maybe_private_key_for_identity_public_key(public_key))
    }

    pub fn identities_count(&self) -> usize {
        self.identities.len()
    }

    pub fn contains_identity_with_id(&self, identity_id: &[u8; 32]) -> bool {
        self.identities.values().any(|controller| controller.model.locked_outpount.is_some() && controller.unique_id().eq(identity_id))
    }


    pub fn unused_identity_index(&self) -> u32 {
        self.identities.values()
            .map(|controller| controller.index())
            .max()
            .map(|max_index| max_index + 1)
            .unwrap_or_default()
    }


    pub fn register_identity(&mut self, identity: IdentityController) -> bool {
        if self.contains_identity(&identity.model.unique_id) {
            return false;
        }
        let keychain_ref = self.chain.keychain_ref();
        let maybe_keychain_wallet_identities = keychain_ref.get(KeyChainKey::wallet_identities_key(self.wallet_id_ref()));

        if let Err(error) = maybe_keychain_wallet_identities {
            println!("[PlatformSDK] Error getting identities from keychain {}: {error:?}", self.wallet_id);
            return false;
        }
        if let Ok(KeyChainValue::IdentityDictionary(mut map)) = maybe_keychain_wallet_identities {
            map.insert(identity.unique_id(), identity.model.to_keychain_value());
            _ = keychain_ref.set(
                KeyChainKey::wallet_identities_key(self.wallet_id_ref()),
                KeyChainValue::IdentityDictionary(map),
                false
            );
        } else if let Ok(KeyChainValue::None) = maybe_keychain_wallet_identities {
            _ = keychain_ref.set(
                KeyChainKey::wallet_identities_key(self.wallet_id_ref()),
                KeyChainValue::IdentityDictionary(HashMap::from_iter([(identity.unique_id(), identity.model.to_keychain_value())])),
                false
            );
        }
        let index = identity.index();
        let added = self.add_identity(identity);

        if self.default_identity_index.is_none() && index == 0 {
            self.default_identity_index = Some(index);
        }
        added
    }

    pub fn wipe_identities_in_context(&mut self, storage_context: StorageContext) {
        let unique_ids = self.identities.values().map(|identity| identity.unique_id()).collect::<Vec<_>>();
        self.identities.clear();
        self.default_identity_index = None;
        let keychain_ref = self.chain.keychain_ref();
        let keychain_key = KeyChainKey::wallet_identities_key(self.wallet_id_ref());
        unique_ids.iter().for_each(|unique_id| {
            let maybe_keychain_wallet_identities = keychain_ref.get(keychain_key.clone());
            if let Ok(KeyChainValue::IdentityDictionary(mut dict)) = maybe_keychain_wallet_identities {
                dict.remove(unique_id);
                let _ = keychain_ref.set(keychain_key.clone(), KeyChainValue::IdentityDictionary(dict), false);
            }
            let _ = self.storage_ref()
                .delete(Predicate::delete_identity(unique_id), storage_context);
        });
    }

    pub fn current_dashpay_username_for_identity_id(&self, unique_id: &[u8; 32]) -> Option<String> {
        self.identity_by_unique_id(unique_id)
            .and_then(|controller| controller.model.first_dashpay_username())
    }


    pub fn load_invitation(&mut self, locked_outpoint: [u8; 36], index: u32) -> Result<InvitationModel, Error> {
        let storage_context = StorageContext::Chain;
        let identity_id = sha256d::Hash::hash(&locked_outpoint).to_byte_array();

        if let Ok(Entity::Invitation(InvitationEntity { link, name, tag, identity: identity_entity, .. })) = self.chain.storage_ref().get(Predicate::GetInvitationByIdentityId { identity_id }, storage_context) {
            let mut identity = IdentityModel::with_index_and_unique_id(index, identity_id, self.wallet_id.clone());
            identity.locked_outpount = Some(locked_outpoint);
            identity.is_outgoing_invitation = true;
            identity.is_from_incoming_invitation = false;
            identity.is_local = false;
            let invitation = InvitationModel::with_identity_and_entity(identity_id, self.wallet_id.clone(), InvitationLinkInfo::new(link, name, tag));
            // identity.set_associated_invitation(invitation);

            if let Some(identity_entity) = identity_entity {
                let mut controller = IdentityController::with_model(identity, Arc::clone(&self.identity_callbacks));
                controller.apply_identity_entity((*identity_entity).into(), StorageContext::Chain);
            }
            Ok(invitation)
        } else {
            let outpoint = OutPoint::from(locked_outpoint);
            let identity = if let Ok(entity) = self.maybe_asset_lock_transaction_by_tx_hash(outpoint.txid.to_byte_array(), storage_context) {
                if let Some(transaction) = self.chain.get_transaction_by_entity(entity) {
                    if let Some(script_pub_key_hash) = transaction.maybe_credit_burn_public_key_hash() {
                        if self.check_derivation_path_index_for_credit_burn_public_key_hash(script_pub_key_hash.as_byte_array(), DerivationPathKind::InvitationFunding, index) {
                            IdentityModel::with_asset_lock_transaction(index, transaction, self.wallet_id.clone())
                        } else {
                            assert!(false, "We should implement this");
                            return Err(Error::DerivationIndexesDoesntMatch);
                        }
                    } else {
                        return Err(Error::AssetLockTransactionShouldBeKnown);
                    }
                } else {
                    return Err(Error::AssetLockTransactionShouldBeKnown);
                }
            } else {
                IdentityModel::with_locked_outpoint(index, identity_id, locked_outpoint, self.wallet_id.clone())
            };
            let invitation = InvitationModel::with_identity(identity_id, self.wallet_id.clone());
            // model.set_associated_invitation(locked_outpoint);
            _ = self.storage_ref().set(Entity::Identity(identity.to_entity()), StorageContext::Platform);

            self.register_invitation(invitation.clone());
            self.chain.notification_ref()
                .invitation_did_update(ferment::boxed(InvitationDidUpdate::new(self.chain.chain_type_ref().clone(), invitation.clone())) as *mut c_void);
            Ok(invitation)
        }
    }

    pub fn register_identity_in_wallet_for_asset_lock_transaction(&mut self, mut identity: IdentityController, transaction: &TransactionModel) {
        identity.model.asset_lock_registration_hash = Some(transaction.transaction.txid().to_byte_array());
        identity.model.unique_id = transaction.credit_burn_identity_identifier();
        let entity = identity.model.to_entity();
        self.register_identity(identity);
        _ = self.storage_ref()
            .set(Entity::Identity(entity), StorageContext::Platform);
        if let Some(asset_lock_registration_hash) = transaction.maybe_credit_burn_public_key_hash() {
            //we need to also set the address of the funding transaction to being used so future identities past the initial gap limit are found
            self.mark_address_hash_as_used(asset_lock_registration_hash.as_byte_array(), DerivationPathKind::IdentityRegistrationFunding);
        }
    }

    pub fn register_registration_transaction(&mut self, transaction: TransactionModel, index: u32) {
        let locked_outpoint = transaction.locked_outpoint();
        let maybe_credit_burn_public_key_hash = transaction.maybe_credit_burn_public_key_hash();
        let unique_id = sha256d::Hash::hash(&locked_outpoint).to_byte_array();
        let mut model = IdentityModel::with_index_and_unique_id(index, unique_id, self.wallet_id.clone());
        model.locked_outpount = Some(locked_outpoint);
        model.asset_lock_registration_hash = Some(transaction.transaction.txid().to_byte_array());
        model.unique_id = transaction.credit_burn_identity_identifier();
        model.set_asset_lock_registration_model(transaction);
        let entity = model.to_entity();
        let controller = IdentityController::with_model(model, Arc::clone(&self.identity_callbacks));
        self.register_identity(controller);
        _ = self.storage_ref()
            .set(Entity::Identity(entity), StorageContext::Platform);
        if let Some(asset_lock_registration_hash) = maybe_credit_burn_public_key_hash {
            //we need to also set the address of the funding transaction to being used so future identities past the initial gap limit are found
            self.mark_address_hash_as_used(asset_lock_registration_hash.as_byte_array(), DerivationPathKind::IdentityRegistrationFunding);
        }
    }

    pub fn register_topup_transaction(&mut self, transaction: TransactionModel, identity_id: [u8; 32]) {
        if let Some(controller) = self.identities.get_mut(&identity_id) {
            assert!(controller.model.is_local, "This should not be performed on a non local blockchain identity");
            if !controller.model.is_local {
                return;
            }
            let tx_hash = transaction.transaction.txid().to_byte_array();
            let credit_burn_public_key_hash = transaction.maybe_credit_burn_public_key_hash();
            controller.model.asset_lock_topup_models.push(transaction);
            controller.save(StorageContext::Platform, SaveIdentity::NewTopUpTransaction { identity_id, tx_hash });
            if let Some(credit_burn_public_key_hash) = credit_burn_public_key_hash {
                //we need to also set the address of the funding transaction to being used so future identities past the initial gap limit are found
                self.mark_address_hash_as_used(credit_burn_public_key_hash.as_byte_array(), DerivationPathKind::IdentityTopupFunding);
            }
        } else {
            assert!(false, "TopUp unknown identity {}", identity_id.to_lower_hex_string());
        }
    }

    pub fn create_identity_using_index(&self, index: u32) -> IdentityModel {
        IdentityModel::with_index(index, self.wallet_id.clone())
    }
    pub fn create_identity_for_username(&self, username: String) -> IdentityModel {
        let mut model = self.create_identity_using_index(self.unused_identity_index());
        model.add_username(username, "dash".to_string(), UsernameStatus::Initial);
        model
    }

    pub fn create_identity_for_username_using_index(&self, username: String, index: u32) -> IdentityModel {
        let mut model = self.create_identity_using_index(index);
        model.add_username(username, "dash".to_string(), UsernameStatus::Initial);
        model
    }





    pub fn setup_invitations(&mut self) -> Result<HashMap<[u8; 36], InvitationModel>, Error> {
        if !self.invitations.is_empty() {
            return Ok(self.invitations.clone());
        }

        let maybe_keychain_wallet_invitations = self.keychain_ref().get(KeyChainKey::wallet_invitations_key(self.wallet_id_ref()));
        if let Err(error) = maybe_keychain_wallet_invitations {
            println!("[PlatformSDK] Error getting invitations from keychain {}: {error:?}", self.wallet_id);
            return Err(Error::KeychainError(error));
        }

        if let Ok(KeyChainValue::None) = maybe_keychain_wallet_invitations {
            return Ok(HashMap::default());
        }

        if let Ok(KeyChainValue::InvitationDictionary(keychain_dictionary)) = maybe_keychain_wallet_invitations {
            for (outpoint_data, index) in keychain_dictionary {
                if let Ok(invitation) = self.load_invitation(outpoint_data, index) {
                    self.invitations.insert(outpoint_data, invitation);
                }
            }
        }
        Ok(self.invitations.clone())
    }

    pub fn invitation_for_unique_id(&self, unique_id: &[u8; 32]) -> Option<InvitationModel> {
        if unique_id.is_zero() {
            return None;
        }
        self.invitations.values()
            .find_map(|invitation| {
                let equal = match invitation.identity_id() {
                    None => false,
                    Some(identity_id) => identity_id.eq(unique_id)
                };
                equal.then_some(invitation)
            })
            .cloned()
    }

    pub fn invitations_count(&self) -> usize {
        self.invitations.len()
    }

    pub fn unregister_invitation(&mut self, invitation_outpoint: &[u8; 36]) {
        self.invitations.remove(invitation_outpoint);
        let keychain_key = KeyChainKey::wallet_invitations_key(self.wallet_id_ref());
        let maybe_keychain_wallet_invitations = self.keychain_ref().get(keychain_key.clone());

        if let Ok(KeyChainValue::InvitationDictionary(mut dict)) = maybe_keychain_wallet_invitations {
            dict.remove(invitation_outpoint);
            let _ = self.keychain_ref().set(keychain_key, KeyChainValue::InvitationDictionary(dict), false);
        }
    }

    pub fn add_invitation(&mut self, out_point: [u8; 36], invitation: InvitationModel) {
        self.invitations.insert(out_point, invitation);
    }

    pub fn register_invitation(&mut self, invitation: InvitationModel) {
        if let Some(identity_id) = invitation.identity_id() {
            if let Some(identity) = self.identities.get(&identity_id) {
                let identity_index = identity.index();
                if let Some(locked_outpoint_data) = identity.model.locked_outpoint() {
                    self.add_invitation(locked_outpoint_data, invitation);
                    let keychain_key = KeyChainKey::wallet_invitations_key(self.wallet_id_ref());
                    match self.keychain_ref().get(keychain_key.clone()) {
                        Ok(KeyChainValue::None) => {
                            if let Err(err) = self.keychain_ref().set(keychain_key, KeyChainValue::InvitationDictionary(HashMap::from_iter([(locked_outpoint_data.into(), identity_index)])), false) {
                                println!("[PlatformSDK] Error: setting invitations in keychain {}: {err:?}", self.wallet_id);
                            }
                        },
                        Ok(KeyChainValue::InvitationDictionary(mut keychain_dictionary)) => {
                            keychain_dictionary.insert(locked_outpoint_data.into(), identity_index);
                            if let Err(err) = self.keychain_ref().set(keychain_key, KeyChainValue::InvitationDictionary(keychain_dictionary), false) {
                                println!("[PlatformSDK] Error: setting invitations in keychain {}: {err:?}", self.wallet_id);
                            }

                        },
                        Err(err) => {
                            println!("[PlatformSDK] Error: getting invitations from keychain {}: {err:?}", self.wallet_id);
                        },
                        _ => {
                            println!("[PlatformSDK] Error: unexpected invitation keychain value format {}", self.wallet_id);
                        }
                    }
                }
            } else {
                assert!(false, "the invitation you are trying to register has no identity with id: {}", identity_id.to_lower_hex_string())
            }
        } else {
            assert!(false, "the invitation you are trying to register has no identity id")
        }
    }

    pub fn contains_invitation(&self, identity_locked_outpoint: &[u8; 36]) -> bool {
        self.invitations.get(identity_locked_outpoint).is_some()
    }

    pub fn wipe_invitations_in_context(&mut self, storage_context: StorageContext) {
        let identity_ids = self.invitations.values().filter_map(|invitation| invitation.identity_id()).collect::<Vec<_>>();
        self.invitations.clear();
        let _ = self.keychain_ref().set(KeyChainKey::wallet_invitations_key(self.wallet_id_ref()), KeyChainValue::InvitationDictionary(HashMap::default()), false);
        let _ = self.storage_ref().delete(Predicate::DeleteInvitations { identity_ids }, storage_context);
    }

    pub fn create_invitation_with_link(&self, link: String) -> InvitationModel {
        InvitationModel::with_link(InvitationLinkInfo::new(link, None, None), self.wallet_id.clone())
    }
    pub fn create_invitation_with_identity(&self, identity_id: [u8; 32]) -> InvitationModel {
        InvitationModel::with_identity(identity_id, self.wallet_id.clone())
    }

    pub fn create_invitation_using_index(&self, index: u32) -> InvitationModel {
        let mut identity = IdentityModel::with_index(index, self.wallet_id.clone());
        identity.is_outgoing_invitation = true;
        identity.is_local = false;
        // identity.set_associated_invitation(invitation);

        let invitation = self.create_invitation_with_identity(identity.unique_id());
        invitation
    }

    pub fn create_invitation_using_index_and_transaction(&self, index: u32, transaction: TransactionModel) -> InvitationModel {
        let outpoint = transaction.locked_outpoint();
        let unique_id = if outpoint == [0u8; 36] {
            [0u8; 32]
        } else {
            sha256d::Hash::hash(&outpoint).to_byte_array()
        };
        let mut identity = IdentityModel::with_index_and_unique_id(index, unique_id, self.wallet_id.clone());
        identity.is_outgoing_invitation = true;
        identity.is_local = false;
        identity.locked_outpount = Some(outpoint);
        identity.set_asset_lock_registration_model(transaction);
        _ = self.storage_ref().set(Entity::Identity(identity.to_entity()), StorageContext::Platform);

        // identity.set_associated_invitation(invitation);

        let invitation = self.create_invitation_with_identity(identity.unique_id());
        invitation
    }


    pub fn create_invitation_with_id_if_not_exist(&mut self, identity_id: [u8; 32], index: u32, asset_lock_transaction_model: TransactionModel) -> Option<InvitationModel> {
        if self.invitation_for_unique_id(&identity_id).is_some() {
            return None;
        }
        let maybe_credit_burn_public_key_hash = asset_lock_transaction_model.maybe_credit_burn_public_key_hash();
        let invitation = self.create_invitation_using_index_and_transaction(index, asset_lock_transaction_model);
        self.register_invitation(invitation.clone());
        if let Some(maybe_credit_burn_public_key_hash) = maybe_credit_burn_public_key_hash {
            self.mark_address_hash_as_used(maybe_credit_burn_public_key_hash.as_byte_array(), DerivationPathKind::InvitationFunding);
        }
        Some(invitation)
    }

}