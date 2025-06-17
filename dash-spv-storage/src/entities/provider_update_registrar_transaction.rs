use crate::entities::local_masternode::LocalMasternodeEntity;
use crate::entities::special_transaction::SpecialTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ProviderUpdateRegistrarTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub operator_key: Vec<u8>,
    pub payload_signature: Vec<u8>,
    pub provider_mode: i16,
    pub provider_registration_transaction_hash: Vec<u8>,
    pub script_payout: Vec<u8>,
    pub voting_key_hash: Vec<u8>,
    pub local_masternode: Option<Box<LocalMasternodeEntity>>,
}
