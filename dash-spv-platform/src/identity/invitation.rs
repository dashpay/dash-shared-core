// use std::error::Error;
// use dpp::dashcore::OutPoint;
// use dash_spv_crypto::tx::Transaction;
// use crate::identity::model::IdentityModel;
//
// pub struct Invitation {
//
//     /// This is the identity that was made from the invitation.
//     /// There should always be an identity associated to a blockchain invitation.
//     /// This identity might not yet be registered on Dash Platform.
//     pub identity: Option<IdentityModel>,
//
//     /// This is an invitation that was created locally.
//     pub created_locally: bool,
//
//     /// This is an invitation that was created with an external link, and has not yet retrieved the identity.
//     pub needs_identity_retrieval,
//
//     /// This is the wallet holding the blockchain invitation. There should always be a wallet associated to a blockchain invitation.
//     pub wallet: Option<Wallet>,
//
//     /// A name for locally created invitation.
//     pub name: String,
//
//     /// A tag for locally created invitation.
//     pub tag: String
//
// }
// impl Invitation {
//     pub fn with_invitation_link(invitation_link: String, wallet: Wallet) -> Self {
//
//     }
//
//     pub fn accept_invitation_link<SC, E>(&self, index: u32, dashpay_username: String, auth_prompt: String, registration_sterps: IdentityRegistrationStep, step_completion: SC) -> Result<IdentityRegistrationStep, E> where SC: Fn(), E: Error {
//
//
//     /// Registers the blockchain identity if the invitation was created with an invitation link.
//     /// The blockchain identity is then associated with the invitation.
//     pub fn accept_invitation_using_wallet_index(&self, index: u32, dashpay_username: String, auth_message: String, registration_steps: IdentityRegistrationStep, step_completion: SC) -> Result<IdentityRegistrationStep, dyn Error>
//     where SC: Fn(IdentityRegistrationStep) {
//
//     }
//
//     /// Generates blockchain invitations' extended public keys by asking the user to authentication with the prompt.
//     pub fn generate_invitations_extended_public_keys_with_prompt(&self, prompt: String) -> Result<bool, dyn Error> {
//
//     }
//
//     /// Register the blockchain identity to its wallet. This should only be done once on the creation of the blockchain identity.
//     pub fn register_in_wallet(&self) {
//
//     }
//
//     /// Update the blockchain identity to its wallet.
//     pub fn update_in_wallet(&self) {
//
//     }
//
//     /// Unregister the blockchain identity from the wallet. This should only be used if the blockchain identity is not yet registered or if a progressive wallet wipe is happening.
//     /// @discussion When a blockchain identity is registered on the network it is automatically retrieved from the L1 chain on resync.
//     /// If a client wallet wishes to change their default blockchain identity in a wallet it should be done by marking the default blockchain identity index in the wallet.
//     /// Clients should not try to delete a registered blockchain identity from a wallet.
//     pub fn unregister_locally(&self) {
//
//     }
//
//     /// Register the blockchain invitation to its wallet from a credit funding registration transaction.
//     /// This should only be done once on the creation of the blockchain invitation.
//     /// @param fundingTransaction The funding transaction used to initially fund the blockchain identity.
//     pub fn registerInWalletForRegistrationFundingTransaction(funding_tx: DSCreditFundingTransaction) {
//
//     }
//
//     /// Create the invitation full link and mark the "fromIdentity" as the source of the invitation.
//     ///   @param identity The source of the invitation.
//     /// result: cancelled: bool, invitationFullLink: string
//     pub fn create_invitation_full_link_from_identity(&self, identity: IdentityModel) -> Result<(bool, String), dyn Error> {
//
//     }
//
//     pub fn init_at_index(index: u32, locked_outpoint: OutPoint, wallet: Wallet) -> Self {
//     }
//     pub fn init_at_index(index: u32, locked_outpoint: OutPoint, wallet: Wallet) -> Self {
//     }
//         // - (instancetype)initAtIndex:(uint32_t)index withLockedOutpoint:(DSUTXO)lockedOutpoint inWallet:(DSWallet *)wallet;
//         //
//         // - (instancetype)initAtIndex:(uint32_t)index withLockedOutpoint:(DSUTXO)lockedOutpoint inWallet:(DSWallet *)wallet withBlockchainInvitationEntity:(DSBlockchainInvitationEntity *)blockchainInvitationEntity;
//         //
//         // - (instancetype)initWithUniqueId:(UInt256)uniqueId isTransient:(BOOL)isTransient onChain:(DSChain *)chain;
//         //
//         // - (instancetype)initAtIndex:(uint32_t)index inWallet:(DSWallet *)wallet;
//         //
//         // - (instancetype)initAtIndex:(uint32_t)index withFundingTransaction:(DSCreditFundingTransaction *)transaction inWallet:(DSWallet *)wallet;
//         //
//         // - (void)registerInWalletForBlockchainIdentityUniqueId:(UInt256)blockchainIdentityUniqueId;
//         // - (void)registerInWalletForRegistrationFundingTransaction:(DSCreditFundingTransaction *)fundingTransaction;
//         //
//         // - (void)deletePersistentObjectAndSave:(BOOL)save inContext:(NSManagedObjectContext *)context;
//     }