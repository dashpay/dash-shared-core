use crate::entities::account::AccountEntity;
use crate::entities::address::AddressEntity;
use crate::entities::asset_lock_transaction::AssetLockTransactionEntity;
use crate::entities::asset_unlock_transaction::AssetUnlockTransactionEntity;
use crate::entities::chain::ChainEntity;
use crate::entities::chain_lock::ChainLockEntity;
use crate::entities::coinbase_transaction::CoinbaseTransactionEntity;
use crate::entities::contract::ContractEntity;
use crate::entities::dashpay_user::DashpayUserEntity;
use crate::entities::derivation_path::DerivationPathEntity;
use crate::entities::friend_request::FriendRequestEntity;
use crate::entities::governance_object::GovernanceObjectEntity;
use crate::entities::governance_object_hash::GovernanceObjectHashEntity;
use crate::entities::governance_vote::GovernanceVoteEntity;
use crate::entities::governance_vote_hash::GovernanceVoteHashEntity;
use crate::entities::identity::IdentityEntity;
use crate::entities::identity_key_path::IdentityKeyPathEntity;
use crate::entities::identity_username::IdentityUsernameEntity;
use crate::entities::instant_send_lock::InstantSendLockEntity;
use crate::entities::invitation::InvitationEntity;
use crate::entities::local_masternode::LocalMasternodeEntity;
use crate::entities::merkle_block::MerkleBlockEntity;
use crate::entities::peer::PeerEntity;
use crate::entities::provider_registration_transaction::ProviderRegistrationTransactionEntity;
use crate::entities::provider_update_registrar_transaction::ProviderUpdateRegistrarTransactionEntity;
use crate::entities::provider_update_revocation_transaction::ProviderUpdateRevocationTransactionEntity;
use crate::entities::provider_update_service_transaction::ProviderUpdateServiceTransactionEntity;
use crate::entities::quorum_commitment_transaction::QuorumCommitmentTransactionEntity;
use crate::entities::shapeshift::ShapeshiftEntity;
use crate::entities::special_transaction::SpecialTransactionEntity;
use crate::entities::spork::SporkEntity;
use crate::entities::spork_hash::SporkHashEntity;
use crate::entities::transaction::TransactionEntity;
use crate::entities::transaction_hash::TransactionHashEntity;
use crate::entities::transaction_input::TransactionInputEntity;
use crate::entities::transaction_output::TransactionOutputEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum Entity {
    Account(AccountEntity),
    Address(AddressEntity),
    Identity(IdentityEntity),
    IdentityKeyPath(IdentityKeyPathEntity),
    IdentityUsername(IdentityUsernameEntity),
    Invitation(InvitationEntity),
    Chain(ChainEntity),
    ChainLock(ChainLockEntity),
    InstantSendLock(InstantSendLockEntity),
    LocalMasternode(LocalMasternodeEntity),
    MerkleBlock(MerkleBlockEntity),
    Peer(PeerEntity),
    Contract(ContractEntity),
    DashpayUser(DashpayUserEntity),
    DerivationPath(DerivationPathEntity),
    FriendRequest(FriendRequestEntity),
    GovernanceObject(GovernanceObjectEntity),
    GovernanceObjectHash(GovernanceObjectHashEntity),
    GovernanceVote(GovernanceVoteEntity),
    GovernanceVoteHash(GovernanceVoteHashEntity),
    ShapeShift(ShapeshiftEntity),
    Spork(SporkEntity),
    SporkHash(SporkHashEntity),

    Transaction(TransactionEntity),
    TransactionHash(TransactionHashEntity),
    TransactionInput(TransactionInputEntity),
    TransactionOutput(TransactionOutputEntity),
    SpecialTransaction(SpecialTransactionEntity),
    AssetLockTransaction(AssetLockTransactionEntity),
    AssetUnlockTransaction(AssetUnlockTransactionEntity),
    CoinbaseTransaction(CoinbaseTransactionEntity),
    ProviderRegistrationTransaction(ProviderRegistrationTransactionEntity),
    ProviderUpdateRegistrarTransaction(ProviderUpdateRegistrarTransactionEntity),
    ProviderUpdateRevocationTransaction(ProviderUpdateRevocationTransactionEntity),
    ProviderUpdateServiceTransaction(ProviderUpdateServiceTransactionEntity),
    QuorumCommitmentTransaction(QuorumCommitmentTransactionEntity),

}