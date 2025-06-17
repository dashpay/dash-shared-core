use crate::entities::local_masternode::LocalMasternodeEntity;
use crate::entities::special_transaction::SpecialTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ProviderUpdateRevocationTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub payload_signature: Vec<u8>,
    pub provider_registration_transaction_hash: Vec<u8>,
    pub reason: i16,
    pub local_masternode: Option<Box<LocalMasternodeEntity>>,
}
