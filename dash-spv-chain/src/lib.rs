pub mod wallet;
pub mod derivation;
pub mod chain;
pub mod notification;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::os::raw::c_void;
use dashcore::transaction::Transaction;
use dashcore::transaction::txout::TxOut;
use dashcore::hashes::{sha256d, Hash};
use dashcore::hash_types::ScriptHash;
use dashcore::transaction::special_transaction::TransactionPayload;
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;
use dash_spv_crypto::network::ChainType;
use dash_spv_crypto::util::from_hash160_for_script_map;
use dash_spv_keychain::{IdentityDictionaryItemValue, KeyChainError, KeyChainKey, KeyChainValue, KeychainController, KeychainRef};
use dash_spv_storage::controller::StorageController;
use dash_spv_storage::entity::Entity;
use dash_spv_storage::StorageRef;
use crate::chain::{ChainController, ChainRef};
use crate::derivation::{DerivationController, DerivationRef};
use crate::notification::{NotificationController, NotificationRef};
use crate::wallet::{WalletController, WalletRef};

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum ChainError {
    Cancelled,
    SigningError(String),
    TransactionPublishError(String),
    InstantSendLockError(String)
}

pub struct ChainManager {
    pub controller: ChainController,
    pub keychain: KeychainController,
    pub storage: StorageController,
    pub wallet: WalletController,
    pub derivation: DerivationController,
    pub notification: NotificationController,
}

impl ChainManager {
    pub fn new(
        controller: ChainController,
        keychain: KeychainController,
        storage: StorageController,
        wallet: WalletController,
        derivation: DerivationController,
        notification: NotificationController,
    ) -> Self {
        Self {
            controller,
            keychain,
            storage,
            wallet,
            derivation,
            notification,
        }
    }
}


impl ChainManager {

    /// Chain Callbacks
    pub fn get_chain(&self) -> *const c_void {
        self.controller.get_chain_by_chain_type()
    }
    pub fn chain_type_ref(&self) -> &ChainType {
        &self.controller.chain_type
    }
    pub fn get_wallet_by_id(&self, wallet_id: &str) -> *const c_void {
        self.controller.get_wallet(wallet_id)
    }

    pub fn block_height_by_hash(&self, hash: [u8; 32]) -> u32 {
        self.controller.get_block_height_by_hash(hash)
    }
    pub fn block_hash_by_height(&self, height: u32) -> Option<[u8; 32]> {
        self.controller.get_block_hash_by_height(height)
    }

    pub fn get_transaction_by_entity(&self, entity: Entity) -> Option<TransactionModel> {
        self.controller.get_transaction_by_entity(entity)
    }

    /// Derivation Callbacks
    pub fn get_derivation_path(&self, wallet_id: &str, kind: DerivationPathKind) -> *const c_void {
        let wallet_context = self.controller.get_wallet(wallet_id);
        self.derivation.derivation_path_for_wallet(wallet_context, kind)
    }

    pub fn public_key_data_at_index_path_for_derivation_kind(&self, wallet_id: &str, index_path: Vec<u32>, derivation_kind: DerivationPathKind) -> Vec<u8> {
        let derivation_path = self.get_derivation_path(wallet_id, derivation_kind);
        self.public_key_data_at_index_path(derivation_path, index_path)

    }
    pub fn get_derivation_path_in_context(&self, wallet_context: *const c_void, kind: DerivationPathKind) -> *const c_void {
        self.derivation.derivation_path_for_wallet(wallet_context, kind)
    }

    pub fn public_key_data_at_index_path(&self, derivation_context: *const c_void, index_path: Vec<u32>) -> Vec<u8> {
        self.derivation.public_key_data_at_index_path(derivation_context, index_path)
    }

    /// Wallet Callbacks

    pub fn is_wallet_transient(&self, wallet_id: &str) -> bool {
        let wallet_context = self.controller.get_wallet(wallet_id);
        self.wallet.is_transient(wallet_context)
    }
    pub fn is_wallet_transient_in_context(&self, wallet_context: *const c_void) -> bool {
        self.wallet.is_transient(wallet_context)
    }

    pub fn wallet_has_extended_public_key(&self, wallet_id: &str, kind: DerivationPathKind) -> bool {
        let wallet_context = self.controller.get_wallet(wallet_id);
        self.derivation.has_extended_public_key_for_derivation_path_of_kind(wallet_context, kind)
    }

    pub fn wallet_has_extended_public_key_in_context(&self, wallet_context: *const c_void, kind: DerivationPathKind) -> bool {
        self.derivation.has_extended_public_key_for_derivation_path_of_kind(wallet_context, kind)
    }

    pub fn get_extended_private_key_data(&self, wallet_id: &str, kind: DerivationPathKind) -> Result<Vec<u8>, KeyChainError> {
        let derivation_path = self.get_derivation_path(wallet_id, kind);
        let key = self.derivation.wallet_based_extended_private_key_location_string(derivation_path);
        let keychain_key = KeyChainKey::GetDataBytesKey { key };
        match self.keychain_ref().get(keychain_key) {
            Ok(KeyChainValue::Bytes(extended_private_key_data)) => Ok(extended_private_key_data),
            Ok(value) => Err(KeyChainError::WrongDataFormat(format!("Expected Bytes, got {value:?}"))),
            Err(err) => Err(err)
        }
    }

    // pub fn save_identities_into_keychain(&self, wallet_id: &str, dict: HashMap<[u8; 32], IdentityDictionaryItemValue>) -> Result<bool, KeyChainError> {
    //     self.keychain.set(KeyChainKey::wallet_identities_key(wallet_id), KeyChainValue::IdentityDictionary(dict), false)
    // }

    pub fn maybe_keychain_identity(&self, wallet_id: &str, index: u32, unique_id: [u8; 32], locked_outpoint: Option<[u8; 36]>) -> Result<KeyChainValue, KeyChainError> {
        match self.keychain.get(KeyChainKey::wallet_identities_key(wallet_id)) {
            Ok(KeyChainValue::None) => {
                if let Some(outpoint) = &locked_outpoint {
                    let value = if ![0u8; 32].eq(&outpoint[..32]) {
                        IdentityDictionaryItemValue::Outpoint { index, locked_outpoint_data: outpoint.clone() }
                    } else {
                        IdentityDictionaryItemValue::Index { index }
                    };
                    Ok(KeyChainValue::IdentityDictionary(HashMap::from_iter([(unique_id, value)])))
                } else {
                    Err(KeyChainError::WrongDataFormat("No locked outpoint provided".to_string()))
                }
            },
            Ok(KeyChainValue::IdentityDictionary(mut map)) => {
                if let Some(outpoint) = &locked_outpoint {
                    let value = if ![0u8; 32].eq(&outpoint[..32]) {
                        IdentityDictionaryItemValue::Outpoint { index, locked_outpoint_data: outpoint.clone() }
                    } else {
                        IdentityDictionaryItemValue::Index { index }
                    };
                    match map.entry(unique_id) {
                        Entry::Occupied(mut acc) => {
                            acc.insert(value);
                        }
                        Entry::Vacant(vacant) => {
                            vacant.insert(value);
                        }
                    }
                    Ok(KeyChainValue::IdentityDictionary(map))
                } else {
                    Err(KeyChainError::WrongDataFormat("No locked outpoint provided".to_string()))
                }
            },
            Err(err) => Err(err),
            _ => Err(KeyChainError::WrongDataFormatForKey(format!("Wrong identity keychain value for wallet: {}", wallet_id)))
        }
    }
    pub fn save_invitation_into_keychain(&self, wallet_id: &str, locked_outpoint: [u8; 36], index: u32) -> Result<bool, KeyChainError> {
        let keychain_key = KeyChainKey::wallet_invitations_key(wallet_id);
        match self.keychain.get(keychain_key.clone()) {
            Ok(KeyChainValue::None) => {
                self.keychain.set(keychain_key, KeyChainValue::InvitationDictionary(HashMap::from_iter([(locked_outpoint, index)])), false)
            },
            Ok(KeyChainValue::InvitationDictionary(mut keychain_dictionary)) => {
                keychain_dictionary.insert(locked_outpoint.clone(), index);
                self.keychain.set(keychain_key, KeyChainValue::InvitationDictionary(keychain_dictionary), false)
            },
            Err(err) => {
                println!("[PlatformSDK] Error: getting invitations from keychain {}: {err:?}", wallet_id);
                Err(err)
            },
            _ => {
                println!("[PlatformSDK] Error: unexpected invitation keychain value format {}", wallet_id);
                Err(KeyChainError::WrongDataFormat("Expected InvitationDictionary".to_string()))
            }
        }
    }
    pub fn save_identity_into_keychain(&self, wallet_id: &str, unique_id: [u8; 32], item: IdentityDictionaryItemValue) -> Result<bool, KeyChainError> {
        let key = KeyChainKey::wallet_identities_key(wallet_id);
        match self.keychain.get(key.clone()) {
            Err(error) => {
                println!("[PlatformSDK] Error getting identities from keychain {}: {error:?}", wallet_id);
                Err(error)
            },
            Ok(KeyChainValue::IdentityDictionary(mut map)) => {
                map.insert(unique_id, item);
                self.keychain.set(key, KeyChainValue::IdentityDictionary(map), false)
            },
            Ok(KeyChainValue::None) => {
                self.keychain.set(key, KeyChainValue::IdentityDictionary(HashMap::from_iter([(unique_id, item)])), false)
            },
            _ => {
                println!("[PlatformSDK] Error: unexpected invitation keychain value format {}", wallet_id);
                Err(KeyChainError::WrongDataFormat("Expected InvitationDictionary".to_string()))
            }
        }
    }

    pub fn mark_address_hash_as_used(&self, hash: &[u8; 20], derivation_path_kind: DerivationPathKind, wallet_id: &str) {
        let address = from_hash160_for_script_map(hash, self.controller.chain_type.script_map_ref());
        let derivation_path = self.get_derivation_path(wallet_id, derivation_path_kind);
        self.derivation_ref().mark_address_as_used(derivation_path, address);

    }
}

impl ChainRef for ChainManager {
    fn chain_ref(&self) -> &ChainController {
        &self.controller
    }
}

impl StorageRef for ChainManager {
    fn storage_ref(&self) -> &StorageController {
        &self.storage
    }
}
impl KeychainRef for ChainManager {
    fn keychain_ref(&self) -> &KeychainController {
        &self.keychain
    }
}
impl WalletRef for ChainManager {
    fn wallet_ref(&self) -> &WalletController {
        &self.wallet
    }
}
impl DerivationRef for ChainManager {
    fn derivation_ref(&self) -> &DerivationController {
        &self.derivation
    }
}

impl NotificationRef for ChainManager {
    fn notification_ref(&self) -> &NotificationController {
        &self.notification
    }
}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct TransactionModel {
    pub transaction: Transaction,
    pub core_chain_locked_height: u32,
    pub is_verified: bool,
}

#[ferment_macro::export]
impl TransactionModel {
    pub fn maybe_credit_burn_public_key_hash(&self) -> Option<ScriptHash> {
        if let Some(TransactionPayload::AssetLockPayloadType(ref payload)) = self.transaction.special_transaction_payload {
            if let Some(TxOut { script_pubkey, .. }) = payload.credit_outputs.first() {
                return Some(script_pubkey.script_hash())
            }
        }
        None
    }

    pub fn locked_outpoint(&self) -> [u8; 36] {
        let mut result: [u8; 36] = [0; 36];
        let (one, two) = result.split_at_mut(32);
        one.copy_from_slice(self.transaction.txid().as_raw_hash().as_byte_array().as_slice());
        let output_index_bytes: [u8; 4] = 0u32.to_le_bytes();
        two.copy_from_slice(&output_index_bytes);
        result
    }

    pub fn credit_burn_identity_identifier(&self) -> [u8; 32] {
        let locked_outpoint = self.locked_outpoint();
        if locked_outpoint.eq(&[0u8; 36]) {
            [0u8; 32]
        } else {
            sha256d::Hash::hash(&locked_outpoint).into()
        }
    }

    pub fn transaction_type_requires_inputs(&self) -> bool {
        match self.transaction.special_transaction_payload {
            Some(TransactionPayload::AssetUnlockPayloadType(..)) |
            Some(TransactionPayload::QuorumCommitmentPayloadType(..)) => false,
            _ => true
        }
    }
}