use crate::entities::local_masternode::LocalMasternodeEntity;
use crate::entities::special_transaction::SpecialTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ProviderUpdateServiceTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub ip_address: Vec<u8>,
    pub payload_signature: Vec<u8>,
    pub platform_http_port: i16,
    pub platform_node_id: Vec<u8>,
    pub platform_p2p_port: i16,
    pub port: i16,
    pub provider_registration_transaction_hash: Vec<u8>,
    pub provider_type: i16,
    pub script_payout: Vec<u8>,

    pub local_masternode: Option<LocalMasternodeEntity>,
}
