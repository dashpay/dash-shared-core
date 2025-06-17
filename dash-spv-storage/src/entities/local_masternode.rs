use crate::entities::provider_registration_transaction::ProviderRegistrationTransactionEntity;
use crate::entities::provider_update_registrar_transaction::ProviderUpdateRegistrarTransactionEntity;
use crate::entities::provider_update_revocation_transaction::ProviderUpdateRevocationTransactionEntity;
use crate::entities::provider_update_service_transaction::ProviderUpdateServiceTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct LocalMasternodeEntity {
    pub holding_keys_index: i32,
    pub holding_keys_wallet_unique_id: String,
    pub operator_keys_index: i32,
    pub operator_keys_wallet_unique_id: String,
    pub owner_keys_index: i32,
    pub owner_keys_wallet_unique_id: String,
    pub voting_keys_index: i32,
    pub voting_keys_wallet_unique_id: String,
    pub provider_registration_transaction: Option<Box<ProviderRegistrationTransactionEntity>>,
    pub provider_update_registrar_transaction: Vec<ProviderUpdateRegistrarTransactionEntity>,
    pub provider_update_revocation_transaction: Vec<ProviderUpdateRevocationTransactionEntity>,
    pub provider_update_service_transaction: Vec<ProviderUpdateServiceTransactionEntity>,
}
