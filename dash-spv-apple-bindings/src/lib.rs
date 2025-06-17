#![allow(dead_code)]
#![allow(unused_variables)]

mod address;
#[cfg(not(test))]
pub mod custom;
#[cfg(not(test))]
mod fermented;
#[cfg(not(test))]
mod fermented_extended;
#[cfg(not(test))]
mod fermented_post;

#[cfg(test)]
mod tests;
mod ffi_core_provider;

pub extern crate dash_spv_masternode_processor;
pub extern crate dash_spv_coinjoin;

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::os::raw::c_void;
use std::sync::Arc;
use dashcore::hashes::Hash;
use dashcore::hash_types::QuorumHash;
use dashcore::network::constants::Network;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use data_contracts::SystemDataContract;
use dpp::data_contract::DataContract;
use dpp::identity::identity_public_key::IdentityPublicKey;
use dpp::identity::{Purpose, SecurityLevel};
use drive_proof_verifier::error::ContextProviderError;
use dash_spv_chain::{chain::ChainController, ChainError, ChainManager, TransactionModel};
use dash_spv_chain::derivation::DerivationController;
use dash_spv_chain::notification::NotificationController;
use dash_spv_chain::wallet::WalletController;
use dash_spv_crypto::network::{ChainType, IHaveChainSettings};
use dash_spv_masternode_processor::processing::MasternodeProcessor;
use dash_spv_platform::{PlatformSDK, PlatformSyncStateNotification};
use dash_spv_crypto::crypto::byte_util::Reversed;
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::keys::OpaqueKey;
use dash_spv_keychain::{KeyChainError, KeyChainKey, KeyChainValue, KeychainController};
use dash_spv_masternode_processor::processing::processor::DiffConfig;
use dash_spv_platform::error::Error;
use dash_spv_platform::identity::callback::IdentityCallbacks;
use dash_spv_platform::identity::controller::SaveIdentity;
use dash_spv_platform::identity::key_info::KeyInfo;
use dash_spv_platform::models::profile::ProfileModel;
use dash_spv_platform::transition::registration_model::RegistrationTransitionModel;
use dash_spv_storage::controller::StorageController;
use dash_spv_storage::entities::transaction::TransactionEntity;
use dash_spv_storage::entity::Entity;
use dash_spv_storage::error::StorageError;
use dash_spv_storage::predicate::Predicate;
use dash_spv_storage::StorageContext;
use crate::ffi_core_provider::FFICoreProvider;

#[ferment_macro::opaque]
pub struct DashSPVCore {
    pub chain: Arc<ChainManager>,
    pub processor: Arc<MasternodeProcessor>,
    pub platform: Arc<PlatformSDK>,
    context: *const c_void,
}

impl Debug for DashSPVCore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}] [SPVCore]", self.processor.provider.chain_type().name()).as_str())
    }
}

#[ferment_macro::export]
impl DashSPVCore {

    pub fn with_callbacks<
        NotifyMainThread: Fn(&str, *mut c_void) + Send + Sync + 'static,
        GetChain: Fn(ChainType) -> *const c_void + Send + Sync + 'static,
        GetWallet: Fn(*const c_void, &str) -> *const c_void + Send + Sync + 'static,
        GetTransactionByEntity: Fn(*const c_void, TransactionEntity) -> Option<TransactionModel> + Send + Sync + 'static,
        GetBlockHeightByBlockHash: Fn(*const c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        GetBlockHashByBlockHeight: Fn(*const c_void, u32) -> Option<[u8; 32]> + Send + Sync + 'static,
        // platform
        GetDataContract: Fn(*const c_void, [u8; 32]) -> Option<DataContract> + Send + Sync + 'static,
        GetPlatformActivationHeight: Fn(*const c_void) -> u32 + Send + Sync + 'static,
        Sign: Fn(*const c_void, IdentityPublicKey) -> Option<OpaqueKey> + Send + Sync + 'static,
        CanSign: Fn(*const c_void, IdentityPublicKey) -> bool + Send + Sync + 'static,
        GetDataContractFromCache: Fn(*const c_void, SystemDataContract) -> DataContract + Send + Sync + 'static,
        // wallet
        GetAccountByIndex: Fn(*const c_void, u32) -> *const c_void + Send + Sync + 'static,
        PublishAssetLockTransaction: Fn(*const c_void, u64, Vec<u8>, String) -> Result<TransactionModel, ChainError> + Send + Sync + 'static,
        IsWalletTransient: Fn(*const c_void) -> bool + Send + Sync + 'static,
        // derivation
        GetDerivationPath: Fn(*const c_void, String, DerivationPathKind) -> *const c_void + Send + Sync + 'static,
        GetPublicKeyDataAtIndexPath: Fn(/*derivation_context*/*const c_void, Vec<u32>) -> Vec<u8> + Send + Sync + 'static,
        GetAddressAtIndexPath: Fn(/*derivation_context*/*const c_void, Vec<u32>) -> String + Send + Sync + 'static,
        HasExtendedPublicKeyForDerivationPathOfKind: Fn(/*derivation_context*/*const c_void, DerivationPathKind) -> bool + Send + Sync + 'static,
        GetStandaloneExtendedPublicKeyUniqueId: Fn(/*derivation_context*/*const c_void) -> String + Send + Sync + 'static,
        GetWalletBasedExtendedPrivateKeyLocationString: Fn(/*derivation_context*/*const c_void) -> String + Send + Sync + 'static,
        MarkAddressAsUsed: Fn(/*derivation_context*/*const c_void, /*address*/String) + Send + Sync + 'static,

        // SignAndPublishAssetLockTransaction: Fn(*const c_void, ) + Send + Sync + 'static,
        // MaybeWalletIdentity: Fn(/*wallet_context*/*const c_void, [u8; 32], IdentityDictionaryItemValue) -> Option<IdentityController> + Send + Sync + 'static,
        // MaybeWalletInvitation: Fn(/*wallet_context*/*const c_void, [u8; 36], u32) -> Option<InvitationModel> + Send + Sync + 'static,
        NotifyPlatformSyncState: Fn(*const c_void, Vec<PlatformSyncStateNotification>) + Send + Sync + 'static,
        // masternode
        UpdateMasternodesAddressUsage: Fn(*const c_void, Vec<QualifiedMasternodeListEntry>) + Send + Sync + 'static,

        // identities
        IdentitySave: Fn(*const c_void, StorageContext, SaveIdentity) -> bool + Sync + Send + 'static,
        IdentityGetPrivateKeyAtIndex: Fn(*const c_void, u32, KeyKind) -> Option<Vec<u8>> + Sync + Send + 'static,
        IdentityCreateNewKey: Fn(*const c_void, KeyKind, SecurityLevel, Purpose, bool) -> Result<u32, Error> + Sync + Send + 'static,
        IdentityActivePrivateKeysAreLoaded: Fn(*const c_void, bool, BTreeMap<u32, KeyInfo>) -> Result<bool, Error> + Sync + Send + 'static,
        IdentityIsActive: Fn(*const c_void, /*is_local*/bool, /*unique_id*/[u8; 32]) -> bool + Sync + Send + 'static,
        IdentityHasContactRequestWithId: Fn(*const c_void, StorageContext, /*incoming*/bool, /*request_id*/[u8; 32]) -> bool + Sync + Send + 'static,
        IdentityMatchingEntity: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> *const c_void + Sync + Send + 'static,
        IdentityMatchingDashPayUserEntity: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> *const c_void + Sync + Send + 'static,
        IdentityMatchingDashPayUserEntityCreatedAt: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> u64 + Sync + Send + 'static,
        IdentityMatchingDashPayUserEntityRemoteProfileRevision: Fn(*const c_void, StorageContext, /*unique_id*/[u8; 32]) -> u64 + Sync + Send + 'static,
        IdentityGetRegistrationTransitionModel: Fn(*const c_void) -> Option<RegistrationTransitionModel> + Sync + Send + 'static,
        IdentityLoadProfile: Fn(*const c_void, StorageContext) -> Result<ProfileModel, Error> + Sync + Send + 'static,
        IdentityHasRegistrationAssetLockTransaction: Fn(*const c_void) -> bool + Sync + Send + 'static,
        IdentityGetRegistrationFundingAddress: Fn(*const c_void, u32, bool) -> String + Sync + Send + 'static,

        IdentityHasExtendedPublicKeys: Fn(*const c_void, bool) -> bool + Sync + Send + 'static,

        // keychain
        KeychainGet: Fn(KeyChainKey) -> Result<KeyChainValue, KeyChainError> + Send + Sync + 'static,
        KeychainSet: Fn(KeyChainKey, KeyChainValue, bool) -> Result<bool, KeyChainError> + Send + Sync + 'static,
        KeychainHas: Fn(KeyChainKey) -> Result<bool, KeyChainError> + Send + Sync + 'static,
        KeychainDel: Fn(KeyChainKey) -> Result<bool, KeyChainError> + Send + Sync + 'static,

        // core data
        DBGet: Fn(StorageContext, Predicate) -> Result<Entity, StorageError> + Send + Sync + 'static,
        DBGetMany: Fn(StorageContext, Predicate) -> Result<Vec<Entity>, StorageError> + Send + Sync + 'static,
        DBSet: Fn(StorageContext, Entity) -> Result<bool, StorageError> + Send + Sync + 'static,
        DBSetMany: Fn(StorageContext, Vec<Entity>) -> Result<bool, StorageError> + Send + Sync + 'static,
        DBHas: Fn(StorageContext, Predicate) -> Result<bool, StorageError> + Send + Sync + 'static,
        DBDel: Fn(StorageContext, Predicate) -> Result<bool, StorageError> + Send + Sync + 'static,
        DBCount: Fn(StorageContext, Predicate) -> Result<usize, StorageError> + Send + Sync + 'static,
        DBGetRaw: Fn(StorageContext, Predicate) -> *const c_void + Send + Sync + 'static,
        DBSetRaw: Fn(StorageContext, *const c_void) -> Result<bool, StorageError> + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        diff_config: Option<DiffConfig>,
        address_list: Option<Vec<&'static str>>,

        notify_main_thread: NotifyMainThread,
        // chain
        get_chain: GetChain,
        get_wallet: GetWallet,
        get_transaction_by_entity: GetTransactionByEntity,
        // wallet
        get_account_by_index: GetAccountByIndex,
        publish_asset_lock_transaction: PublishAssetLockTransaction,
        is_wallet_transient: IsWalletTransient,

        // platform
        get_data_contract: GetDataContract,
        get_platform_activation_height: GetPlatformActivationHeight,
        callback_signer: Sign,
        callback_can_sign: CanSign,
        get_data_contract_from_cache: GetDataContractFromCache,

        // derivation
        get_derivation_path: GetDerivationPath,
        get_public_key_data_at_index_path: GetPublicKeyDataAtIndexPath,
        get_address_at_index_path: GetAddressAtIndexPath,
        has_extended_public_key_for_derivation_path_of_kind: HasExtendedPublicKeyForDerivationPathOfKind,
        get_standalone_extended_public_key_unique_id: GetStandaloneExtendedPublicKeyUniqueId,
        get_wallet_based_extended_private_key_location_string: GetWalletBasedExtendedPrivateKeyLocationString,
        mark_address_as_used: MarkAddressAsUsed,

        // identity
        identity_save: IdentitySave,
        // identity_get_private_key_at_index: IdentityGetPrivateKeyAtIndex,
        identity_create_new_key: IdentityCreateNewKey,
        identity_active_private_keys_are_loaded: IdentityActivePrivateKeysAreLoaded,
        identity_is_active: IdentityIsActive,
        identity_has_contact_request_with_id: IdentityHasContactRequestWithId,
        identity_matching_entity: IdentityMatchingEntity,
        identity_matching_dashpay_user_entity: IdentityMatchingDashPayUserEntity,
        identity_matching_dashpay_user_entity_created_at: IdentityMatchingDashPayUserEntityCreatedAt,
        identity_matching_dashpay_user_entity_remote_profile_revision: IdentityMatchingDashPayUserEntityRemoteProfileRevision,
        identity_get_registration_transition_model: IdentityGetRegistrationTransitionModel,
        identity_load_profile: IdentityLoadProfile,
        identity_has_registration_asset_lock_transaction: IdentityHasRegistrationAssetLockTransaction,
        identity_get_registration_funding_address: IdentityGetRegistrationFundingAddress,
        identity_has_extended_public_keys: IdentityHasExtendedPublicKeys,


        // sign_and_publish_asset_lock_transaction: SignAndPublishAssetLockTransaction,
        // maybe_wallet_identity: MaybeWalletIdentity,
        // maybe_wallet_invitation: MaybeWalletInvitation,
        notify_platform_sync_state: NotifyPlatformSyncState,

        get_block_height_by_hash: GetBlockHeightByBlockHash,
        get_block_hash_by_height: GetBlockHashByBlockHeight,
        update_address_usage_of_masternodes: UpdateMasternodesAddressUsage,

        keychain_get: KeychainGet,
        keychain_set: KeychainSet,
        keychain_has: KeychainHas,
        keychain_del: KeychainDel,

        storage_get: DBGet,
        storage_get_many: DBGetMany,
        storage_set: DBSet,
        storage_set_many: DBSetMany,
        storage_has: DBHas,
        storage_del: DBDel,
        storage_count: DBCount,
        storage_get_raw: DBGetRaw,
        storage_set_raw: DBSetRaw,

        context: *const c_void
    ) -> Self {
        let chain = ChainManager::new(
            ChainController::new(
                chain_type.clone(),
                get_chain,
                get_wallet,
                get_transaction_by_entity,
                get_block_height_by_hash,
                get_block_hash_by_height,
            ),
            KeychainController::new(
                keychain_get,
                keychain_set,
                keychain_has,
                keychain_del
            ),
            StorageController::new(
                storage_get,
                storage_get_many,
                storage_set,
                storage_set_many,
                storage_has,
                storage_del,
                storage_count,
                storage_get_raw,
                storage_set_raw
            ),
            WalletController::new(
                get_account_by_index,
                is_wallet_transient,
                publish_asset_lock_transaction
            ),
            DerivationController::new(
                get_derivation_path,
                get_public_key_data_at_index_path,
                get_address_at_index_path,
                has_extended_public_key_for_derivation_path_of_kind,
                get_standalone_extended_public_key_unique_id,
                get_wallet_based_extended_private_key_location_string,
                mark_address_as_used
            ),
            NotificationController::new(
                notify_main_thread
            )
        );
        let chain_arc = Arc::new(chain);

        let provider = Arc::new(FFICoreProvider::new(
            chain_type.clone(),
            get_block_height_by_hash,
            get_block_hash_by_height,
            update_address_usage_of_masternodes,
            context));
        let network = Network::from(chain_type.clone());
        let processor = MasternodeProcessor::from_diff_config(provider.clone(), network, diff_config);
        let processor_arc = Arc::new(processor);
        let processor_arc_clone = Arc::clone(&processor_arc);
        let get_quorum_public_key = Arc::new(move |llmq_type: u32, llmq_hash: [u8; 32], core_chain_locked_height: u32| {
            let llmq_type = LLMQType::from_u16(llmq_type as u16);
            let llmq_hash = QuorumHash::from_byte_array(llmq_hash.reversed());
            processor_arc_clone.engine.find_quorum_public_key(&llmq_type, &llmq_hash)
                .map(|key| key.0)
                .ok_or(ContextProviderError::InvalidQuorum(format!("Quorum not found: {}: {}", llmq_type, llmq_hash.to_string())))
        });

        let identity_callbacks = IdentityCallbacks::new(
            Arc::clone(&chain_arc),
            identity_save,
            // identity_get_private_key_at_index,
            identity_create_new_key,
            identity_active_private_keys_are_loaded,
            identity_is_active,
            identity_has_contact_request_with_id,
            identity_matching_entity,
            identity_matching_dashpay_user_entity,
            identity_matching_dashpay_user_entity_created_at,
            identity_matching_dashpay_user_entity_remote_profile_revision,
            identity_get_registration_transition_model,
            identity_load_profile,
            identity_has_registration_asset_lock_transaction,
            identity_get_registration_funding_address,
        );

        let platform = Arc::new(PlatformSDK::new(
            Arc::clone(&chain_arc),
            identity_callbacks,
            get_quorum_public_key,
            get_data_contract,
            get_platform_activation_height,
            callback_signer,
            callback_can_sign,
            get_data_contract_from_cache,
            notify_platform_sync_state,
            address_list,
            chain_type,
            context
        ));
        // let dapi_address_handler = Arc::clone(&platform);
        // processor.dapi_address_handler = Some(dapi_address_handler);
        // let processor_arc = Arc::new(processor);
        Self {
            chain: chain_arc,
            processor: processor_arc,
            platform,
            context,
        }
    }
}

