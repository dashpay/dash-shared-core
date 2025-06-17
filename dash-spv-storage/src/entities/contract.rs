use crate::entities::chain::ChainEntity;
use crate::entities::identity::IdentityEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ContractEntity {
    pub entropy: Vec<u8>,
    pub local_contract_identifier: String,
    pub registered_blockchain_identity_unique_id: Vec<u8>,
    pub state: i16,
    // Relationships
    pub chain: Option<ChainEntity>,
    pub creator: Option<IdentityEntity>,
}
