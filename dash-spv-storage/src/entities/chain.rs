use crate::entities::account::AccountEntity;
use crate::entities::chain_lock::ChainLockEntity;
use crate::entities::contract::ContractEntity;
use crate::entities::dashpay_user::DashpayUserEntity;
use crate::entities::derivation_path::DerivationPathEntity;
use crate::entities::governance_object::GovernanceObjectEntity;
use crate::entities::governance_vote::GovernanceVoteEntity;
use crate::entities::identity::IdentityEntity;
use crate::entities::invitation::InvitationEntity;
use crate::entities::merkle_block::MerkleBlockEntity;
use crate::entities::peer::PeerEntity;
use crate::entities::spork_hash::SporkHashEntity;
use crate::entities::transaction_hash::TransactionHashEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ChainEntity {
    pub base_block_hash: Vec<u8>,
    pub checkpoints: Vec<u8>,
    pub devnet_identifier: String,
    pub devnet_version: i16,
    pub sync_block_chain_work: Vec<u8>,
    pub sync_block_hash: Vec<u8>,
    pub sync_block_height: i32,
    pub sync_block_timestamp: i64,
    pub sync_locators: Vec<u8>, // originally Transformable
    pub total_governance_objects: i32,
    pub r#type: i16,
    // Relationships (IDs, can be expanded)
    pub accounts: Vec<AccountEntity>,
    pub blocks: Vec<MerkleBlockEntity>,
    pub contacts: Vec<DashpayUserEntity>,
    pub contracts: Vec<ContractEntity>,
    pub derivation_paths: Vec<DerivationPathEntity>,
    pub governance_objects: Vec<GovernanceObjectEntity>,
    pub identities: Vec<IdentityEntity>,
    pub invitations: Vec<InvitationEntity>,
    pub last_chain_lock: Option<Box<ChainLockEntity>>,
    pub peers: Vec<PeerEntity>,
    pub sporks: Vec<SporkHashEntity>,
    pub transaction_hashes: Vec<TransactionHashEntity>,
    pub votes: Vec<GovernanceVoteEntity>,
}
