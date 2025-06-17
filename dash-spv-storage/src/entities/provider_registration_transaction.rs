use crate::entities::local_masternode::LocalMasternodeEntity;
use crate::entities::special_transaction::SpecialTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ProviderRegistrationTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub collateral_outpoint: Vec<u8>,
    pub ip_address: Vec<u8>,
    pub operator_key: Vec<u8>,
    pub operator_reward: i16,
    pub owner_key_hash: Vec<u8>,
    pub payload_signature: Vec<u8>,
    pub platform_http_port: i16,
    pub platform_node_id: Vec<u8>,
    pub platform_p2p_port: i16,
    pub port: i16,
    pub provider_mode: i16,
    pub provider_type: i16,
    pub script_payout: Vec<u8>,
    pub voting_key_hash: Vec<u8>,
    pub local_masternode: Option<Box<LocalMasternodeEntity>>,
}
