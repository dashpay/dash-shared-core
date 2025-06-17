use std::collections::BTreeMap;
use std::sync::Arc;
use dpp::identity::IdentityPublicKey;
use dash_spv_chain::ChainManager;
use dash_spv_crypto::keys::OpaqueKey;
use crate::identity::controller::IdentityController;
use crate::identity::model::IdentityModel;
use crate::wallet_cache::WalletCache;

pub struct PlatformCache {
    pub chain: Arc<ChainManager>,
    pub wallets: BTreeMap<String, WalletCache>,
    pub foreign_identities: BTreeMap<[u8; 32], IdentityController>,
}

impl PlatformCache {

    pub fn new(chain: Arc<ChainManager>) -> PlatformCache {
        Self {
            wallets: Default::default(),
            foreign_identities: Default::default(),
            chain,
        }
    }

    pub fn wallet_by_unique_id(&self, wallet_id: &str) -> Option<&WalletCache> {
        self.wallets.get(wallet_id)
    }
    pub fn wallet_by_unique_id_mut(&mut self, wallet_id: &str) -> Option<&mut WalletCache> {
        self.wallets.get_mut(wallet_id)
    }
    pub fn identity_by_unique_id_mut(&mut self, wallet_id: &str, unique_id: &[u8; 32]) -> Option<&mut IdentityController> {
        self.wallets.get_mut(wallet_id).and_then(|wallet| wallet.identities.get_mut(unique_id))
    }
    pub fn identity_by_index(&self, wallet_id: &str, index: u32) -> Option<&IdentityController> {
        self.wallets.get(wallet_id).and_then(|wallet| wallet.identity_by_index(index))
    }
    pub fn identity_by_index_mut(&mut self, wallet_id: &str, index: u32) -> Option<&mut IdentityController> {
        self.wallets.get_mut(wallet_id).and_then(|wallet| wallet.identity_by_index_mut(index))
    }
    pub fn unsynced_identities_at_block_height(&self, block_height: u32) -> Vec<&IdentityController> {
        self.wallets.iter().flat_map(|(_, map)| {
            Vec::from_iter(map.identities.values()
                .filter_map(|controller|
                    controller.is_unsynced_at_block_height(block_height)
                        .then_some(controller)))
        }).collect()
    }
    pub fn unsynced_identities_count_at_block_height(&self, block_height: u32) -> usize {
        let mut count = 0;
        for wallet in self.wallets.values() {
            for ctrl in wallet.identities.values() {
                if ctrl.is_unsynced_at_block_height(block_height) {
                    count += 1;
                }
            }
        }
        count
    }

    pub fn unsynced_identity_handles_at_block_height(&self, block_height: u32) -> Vec<(String, [u8; 32])> {
        self.wallets.iter()
            .flat_map(|(wallet_id, wallet)| {
                wallet.identities.iter()
                    .filter_map(|(identity_id, controller)| {
                        controller.is_unsynced_at_block_height(block_height)
                            .then_some((wallet_id.clone(), identity_id.clone()))
                    })
            })
            .collect()
    }

    pub fn unsynced_identities_at_block_height_mut(&mut self, block_height: u32) -> Vec<&mut IdentityController> {
        self.wallets.iter_mut().flat_map(|(_, map)| {
            Vec::from_iter(map.identities.values_mut()
                .filter_map(|controller|
                    controller.is_unsynced_at_block_height(block_height)
                        .then_some(controller)))
        }).collect()
    }

    // pub fn unsynced_identities_for_wallet_id_at_block_height(&self, wallet_id: &str, block_height: u32) -> Vec<&IdentityController> {
    //     self.identities_for_wallet_id(wallet_id)
    //         .map(|map|
    //             Vec::from_iter(map.values()
    //                 .filter_map(|controller|
    //                     controller.is_unsynced_at_block_height(block_height)
    //                         .then_some(controller))))
    //         .unwrap_or_default()
    // }

    // pub fn default_identity_for_wallet(&self, wallet_id: &str) -> Option<IdentityController> {
    //     if let Some(wallet) = self.wallets.get(wallet_id) {
    //         wallet.default_identity()
    //     } else {
    //         None
    //     }
    // }

    pub fn has_active_identity(&self, model: &IdentityModel) -> bool {
        if let Some(wallet_id) = model.wallet_id() {
            if model.is_local() {
                self.wallets.get(&wallet_id)
                    .map(|wallet| wallet.identities.get(&model.unique_id).is_some())
                    .unwrap_or_default()
            } else {
                self.foreign_identities.get(&model.unique_id).is_some()
            }
        } else {
            self.foreign_identities.get(&model.unique_id).is_some()
        }
    }

}

#[ferment_macro::export]
impl PlatformCache {

    // pub fn default_identity_for_wallet_cloned(&self, wallet_id: &str) -> Option<IdentityController> {
    //     if let Some(Some(default_index)) = self.default_identity_indexes.get(wallet_id) {
    //         self.identities.get(wallet_id).and_then(|map| map.get(default_index)).cloned()
    //     } else {
    //         None
    //     }
    // }
    //
    // pub fn has_default_identity_for_wallet(&self, wallet_id: &str) -> bool {
    //     self.default_identity_indexes.get(wallet_id).map(|maybe_index| maybe_index.is_some()).unwrap_or_default()
    // }
    //
    // pub fn set_default_identity_for_wallet(&mut self, wallet_id: &str, index: u32) {
    //     self.default_identity_indexes.insert(wallet_id.to_string(), Some(index));
    // }
    //
    // pub fn add_identity(&mut self, wallet_id: String, controller: IdentityController) -> bool {
    //     if controller.unique_id().eq(&[0u8; 32]) {
    //         return false;
    //     }
    //     self.identities.entry(wallet_id)
    //         .or_insert(BTreeMap::default())
    //         .insert(controller.model.index, controller);
    //     true
    // }
    // pub fn add_identities(&mut self, wallet_id: String, identities: Vec<IdentityController>) {
    //     let map = self.identities.entry(wallet_id)
    //         .or_insert(BTreeMap::default());
    //     identities.into_iter().for_each(|controller| {
    //         if !controller.unique_id().eq(&[0u8; 32]) {
    //             map.insert(controller.model.index, controller);
    //         }
    //     });
    // }
    // pub fn identity_by_wallet_id_and_index(&self, wallet_id: &str, index: u32) -> Option<IdentityController> {
    //     self.identities.get(wallet_id).and_then(|map| map.get(&index).cloned())
    // }
    // pub fn identity_by_wallet_id_and_unique_id(&self, wallet_id: &str, unique_id: &[u8; 32]) -> Option<IdentityController> {
    //     self.identities.get(wallet_id).and_then(|identities| identities.values()
    //         .find_map(|controller|
    //             controller.unique_id().eq(unique_id).then_some(controller.clone())))
    // }
    //
    // pub fn identities_by_wallet_id(&self, wallet_id: &str) -> Option<Vec<IdentityController>> {
    //     self.identities.get(wallet_id).map(|map| Vec::from_iter(map.values().cloned()))
    // }
    //
    // pub fn identity_by_unique_id(&self, unique_id: &[u8; 32]) -> Option<IdentityController> {
    //     self.identities.values()
    //         .find_map(|identities|
    //             identities.values()
    //                 .find_map(|controller|
    //                     controller.unique_id().eq(unique_id).then_some(controller.clone())))
    // }

    pub fn identity_by_public_key(&self, public_key: &IdentityPublicKey) -> Option<IdentityController> {
        self.wallets.values()
            .find_map(|wallet|
                wallet.identities.values()
                    .find_map(|controller|
                        controller.model.has_identity_public_key(public_key)
                            .then_some(controller.clone())))

    }
    pub fn identity_private_key_by_public_key(&self, public_key: &IdentityPublicKey) -> Option<OpaqueKey> {
        self.wallets.values()
            .find_map(|wallet|
                wallet.identities.values()
                    .find_map(|controller|
                        controller.maybe_private_key_for_identity_public_key(public_key)))
    }


    // pub fn setup_wallet_invitations(&mut self, wallet_id: &str, wallet_context: *const c_void) -> Result<BTreeMap<[u8; 36], InvitationModel>, Error> {
    //     self.wallets.entry(wallet_id.to_string()).or_insert(WalletCache::new())
    //     // let wallet_invitations = self.invitations.entry(wallet_id.to_string()).or_insert(BTreeMap::new());
    //     if !wallet_invitations.is_empty() {
    //         return Ok(wallet_invitations.clone());
    //     }
    //
    //     let maybe_keychain_wallet_invitations = self.chain.keychain.get(KeyChainKey::wallet_invitations_key(wallet_id));
    //     if let Err(error) = maybe_keychain_wallet_invitations {
    //         println!("[PlatformSDK] Error getting invitations from keychain {wallet_id}: {error:?}");
    //         return Err(Error::KeychainError(error));
    //     }
    //
    //     if let Ok(KeyChainValue::None) = maybe_keychain_wallet_invitations {
    //         return Ok(BTreeMap::default());
    //     }
    //
    //     if let Ok(KeyChainValue::InvitationDictionary(keychain_dictionary)) = maybe_keychain_wallet_invitations {
    //         for (outpoint_data, index) in keychain_dictionary {
    //             if let Some(invitation) = (self.maybe_invitation)(wallet_context, outpoint_data, index) {
    //                 wallet_invitations.insert(outpoint_data, invitation);
    //             }
    //         }
    //     }
    //     Ok(wallet_invitations.clone())
    // }

    // pub fn wallet_invitation_for_unique_id(&self, wallet_id: &str, unique_id: &[u8; 32]) -> Option<InvitationModel> {
    //     if unique_id.is_zero() {
    //         return None;
    //     }
    //     self.invitations.get(wallet_id)
    //         .and_then(|map|
    //             map.values()
    //                 .find_map(|invitation|
    //                     invitation.identity_unique_id()
    //                         .eq(unique_id)
    //                         .then_some(invitation))
    //                 .cloned())
    //
    // }
    //
    // pub fn wallet_invitations_count(&self, wallet_id: &str) -> usize {
    //     self.invitations.get(wallet_id)
    //         .map(|map| map.len())
    //         .unwrap_or_default()
    // }
    //
    // pub fn unused_invitation_index_for_wallet_id(&self, wallet_id: &str) -> u32 {
    //     self.invitations.get(wallet_id)
    //         .and_then(|map|
    //             map.values()
    //                 .map(|invitation| invitation.identity_index())
    //                 .max()
    //                 .map(|max_index| max_index + 1))
    //         .unwrap_or_default()
    // }
    //
    // pub fn unregister_invitation(&mut self, wallet_id: &str, invitation_outpoint: &[u8; 36]) {
    //     if let Some(wallet_invitations) = self.invitations.get_mut(wallet_id) {
    //         wallet_invitations.remove(invitation_outpoint);
    //     }
    //
    //     let keychain_key = KeyChainKey::wallet_invitations_key(wallet_id);
    //     let maybe_keychain_wallet_invitations = self.chain.keychain.get(keychain_key.clone());
    //
    //     if let Ok(KeyChainValue::InvitationDictionary(mut dict)) = maybe_keychain_wallet_invitations {
    //         dict.remove(invitation_outpoint);
    //         let _ = self.chain.keychain.set(keychain_key, KeyChainValue::InvitationDictionary(dict), false);
    //     }
    // }
    //
    // pub fn add_invitation(&mut self, wallet_id: &str, out_point: [u8; 36], invitation: InvitationModel) {
    //     self.invitations.entry(wallet_id.to_string())
    //         .or_insert(BTreeMap::default())
    //         .insert(out_point, invitation);
    // }
    //
    // pub fn register_invitation(&mut self, wallet_id: &str, invitation: InvitationModel) {
    //     let identity_index = invitation.identity_index();
    //     if let Some(locked_outpoint_data) = invitation.identity_locked_outpoint() {
    //         if let Entry::Vacant(vacant) = self.invitations.entry(wallet_id.to_string()).or_insert(BTreeMap::default()).entry(locked_outpoint_data.into()) {
    //             vacant.insert(invitation);
    //         }
    //         let keychain_key = KeyChainKey::wallet_invitations_key(wallet_id);
    //         match self.chain.keychain.get(keychain_key.clone()) {
    //             Ok(KeyChainValue::None) => {
    //                 if let Err(err) = self.chain.keychain.set(keychain_key, KeyChainValue::InvitationDictionary(HashMap::from_iter([(locked_outpoint_data.into(), identity_index)])), false) {
    //                     println!("[PlatformSDK] Error: setting invitations in keychain {wallet_id}: {err:?}");
    //                 }
    //             },
    //             Ok(KeyChainValue::InvitationDictionary(mut keychain_dictionary)) => {
    //                 keychain_dictionary.insert(locked_outpoint_data.into(), identity_index);
    //                 if let Err(err) = self.chain.keychain.set(keychain_key, KeyChainValue::InvitationDictionary(HashMap::from_iter([(locked_outpoint_data.into(), identity_index)])), false) {
    //                     println!("[PlatformSDK] Error: setting invitations in keychain {wallet_id}: {err:?}");
    //                 }
    //
    //             },
    //             Err(err) => {
    //                 println!("[PlatformSDK] Error: getting invitations from keychain {wallet_id}: {err:?}");
    //             },
    //             _ => {
    //                 println!("[PlatformSDK] Error: unexpected invitation keychain value format {wallet_id}");
    //             }
    //         }
    //     }
    // }
    //
    // pub fn contains_invitation(&self, wallet_id: &str, identity_locked_outpoint: &[u8; 36]) -> bool {
    //     self.invitations.get(wallet_id)
    //         .and_then(|map| map.get(identity_locked_outpoint))
    //         .is_some()
    // }
    //
    // pub fn wipe_invitations_in_context(&mut self, wallet_id: &str, context: StorageContext) {
    //     if let Some(wallet_invitations) = self.invitations.get_mut(wallet_id) {
    //         wallet_invitations.iter_mut()
    //             .for_each(|(locked_outpoint_data, invitation)| {
    //                 self.unregister_invitation(wallet_id, locked_outpoint_data);
    //                 let _ = self.chain.storage.delete(Predicate::DeleteInvitation { identity_id: invitation.identity_unique_id() }, context);
    //             });
    //     }
    // }
    //
    // pub fn create_invitation_with_id_if_not_exist(&mut self, wallet_id: &str, identity_id: [u8; 32], index: u32, asset_lock_transaction_model: AssetLockTransactionModel) {
    //     // self.wallet_invitation_for_unique_id(wallet_id, &identity_id)
    //     // DSInvitation *invitation = [self invitationForUniqueId:identityId];
    //     // if (!invitation) {
    //     //     invitation = [[DSInvitation alloc] initAtIndex:index withAssetLockTransaction:transaction inWallet:self];
    //     //     [invitation registerInWalletForAssetLockTransaction:transaction];
    //     // }
    //
    //     if self.wallet_invitation_for_unique_id(wallet_id, &identity_id).is_some() {
    //         return;
    //     }
    //
    //     let invitation = InvitationModel::with_index_and_asset_lock_transaction_model(index, asset_lock_transaction_model, self.chain.invitation_controller.clone(), self.chain.wallet_context);
    //
    //
    //
    //
    //     // if let Entry::Vacant(vacant) = self.invitations.entry(wallet_id.to_string())
    //     //     .or_insert(BTreeMap::default())
    //     //     .entry() {
    //     //     Entry::Vacant(_) => {}
    //     //     Entry::Occupied(_) => {}
    //     // }
    // }
    //
    //

}

fn first_unused_index(map: &BTreeMap<u32, IdentityController>) -> Option<u32> {
    map.keys().max().map(|max_index| max_index + 1)
}