// use dpp::dashcore::OutPoint;
// use platform_value::Identifier;
// use crate::identity::invitation::Invitation;
// use crate::models::transient_dashpay_user::TransientDashPayUser;
//
// bitflags! {
//     #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
//     pub struct IdentityRegistrationStep: u32 {
//         const NONE = 0;
//         const FUNDING_TX_CREATION = 1;
//         const FUNDING_TX_ACCEPTED = 2;
//         const LOCAL_IN_WALLET_PERSISTENCE = 1 << 2;
//         const PROOF_AVAILABLE = 1 << 3;
//         const IDENTITY = 1 << 4;
//         const USERNAME = 1 << 5;
//         const PROFILE = 1 << 6;
//
//
//         // Composite flags
//         const L1_STEPS = Self::FUNDING_TX_CREATION.bits() | Self::FUNDING_TX_ACCEPTED.bits() | Self::LOCAL_IN_WALLET_PERSISTENCE.bits() | Self::PROOF_AVAILABLE.bits();
//
//         const REGISTRATION_STEPS = Self::L1_STEPS.bits() | Self::IDENTITY.bits();
//         const REGISTRATION_STEPS_WITH_USERNAME = Self::REGISTRATION_STEPS.bits() | Self::USERNAME.bits();
//         const REGISTRATION_STEPS_WITH_USERNAME_AND_PROFILE = Self::REGISTRATION_STEPS_WITH_USERNAME.bits() | Self::PROFILE.bits();
//         const ALL = Self::REGISTRATION_STEPS_WITH_USERNAME_AND_PROFILE;
//         const CANCELLED = 1 << 30;
//     }
// }
//
// pub struct IdentityModel {
//     /// This is the unique identifier representing the blockchain identity.
//     /// It is derived from the credit funding transaction credit burn UTXO (as of dpp v10).
//     /// Returned as a 256 bit number
//     pub unique_id: Identifier,
//
//     /// This is the outpoint of the registration credit funding transaction.
//     /// It is used to determine the unique ID by double SHA256 its value. Returned as a UTXO { .hash , .n }
//     pub locked_outpoint: OutPoint,
//
//     /// This is if the blockchain identity is present in wallets or not.
//     /// If this is false then the blockchain identity is known for example from being a dashpay friend.
//     pub is_local: bool,
//
//     /// This is if the blockchain identity is made for being an invitation.
//     /// All invitations should be marked as non local as well.
//     pub is_outgoing_invitation: bool,
//
//     /// This is if the blockchain identity is made from an invitation we received.
//     pub is_from_incoming_invitation: bool,
//
//     /// This is TRUE if the blockchain identity is an effemeral identity returned when searching.
//     pub is_transient: bool,
//
//     /// This is TRUE only if the blockchain identity is contained within a wallet.
//     /// It could be in a cleanup phase where it was removed from the wallet but still being help in memory by callbacks.
//     pub is_active: bool,
//
//     /// This references transient Dashpay user info if on a transient blockchain identity.
//     pub transient_dashpay_user: Option<TransientDashPayUser>,
//
//
//     /// This is the bitwise steps that the identity has already performed in registration.
//     pub steps_completed: IdentityRegistrationStep,
//
//     /// This is the wallet holding the blockchain identity.
//     /// There should always be a wallet associated to a blockchain identity if the blockchain identity is local, but never if it is not.
//     pub wallet: *const std::os::raw::c_void,
//
//     /// This is invitation that is identity originated from.
//     pub associated_invitation: Option<Invitation>,
//
//     /// This is the index of the blockchain identity in the wallet.
//     /// The index is the top derivation used to derive an extended set of keys for the identity.
//     /// No two local blockchain identities should be allowed to have the same index in a wallet.
//     /// For example m/.../.../.../index/key */
//     pub index: u32,
//
//     /// Related to DPNS. This is the list of usernames that are associated to the identity in the domain "dash".
//     /// These usernames however might not yet be registered or might be invalid.
//     /// This can be used in tandem with the statusOfUsername: method
//     pub dashpay_usernames: Vec<String>,
//
//     /// Related to DPNS. This is the list of usernames with their .dash domain that are associated to the identity in the domain "dash".
//     /// These usernames however might not yet be registered or might be invalid.
//     /// This can be used in tandem with the statusOfUsername: method
//     pub dashpay_username_full_paths: Vec<String>,
//
//     /// Related to DPNS. This is current and most likely username associated to the identity.
//     /// It is not necessarily registered yet on L2 however so its state should be determined with the statusOfUsername: method
//     ///  @discussion There are situations where this is nil as it is not yet known or if no username has yet been set.
//     pub current_dashpay_username: Option<String>,
//
//     @property (nonatomic, readonly) NSString *registrationFundingAddress;
//
//     /*! @brief The known balance in credits of the identity */
//     @property (nonatomic, readonly) uint64_t creditBalance;
//
//     /*! @brief The number of registered active keys that the blockchain identity has */
//     @property (nonatomic, readonly) uint32_t activeKeyCount;
//
//     /*! @brief The number of all keys that the blockchain identity has, registered, in registration, or inactive */
//     @property (nonatomic, readonly) uint32_t totalKeyCount;
//
//     /*! @brief This is the transaction on L1 that has an output that is used to fund the creation of this blockchain identity.
//        @discussion There are situations where this is nil as it is not yet known ; if the blockchain identity is being retrieved from L2 or if we are resyncing the chain. */
//     @property (nullable, nonatomic, readonly) DSCreditFundingTransaction *registrationCreditFundingTransaction;
//
//     /*! @brief This is the hash of the transaction on L1 that has an output that is used to fund the creation of this blockchain identity.
//        @discussion There are situations where this is nil as it is not yet known ; if the blockchain identity is being retrieved from L2 or if we are resyncing the chain. */
//     @property (nonatomic, readonly) UInt256 registrationCreditFundingTransactionHash;
//
//     /*! @brief In our system a contact is a vue on a blockchain identity for Dashpay. A blockchain identity is therefore represented by a contact that will have relationships in the system. This is in the default backgroundContext. */
//     @property (nonatomic, readonly) DSDashpayUserEntity *matchingDashpayUserInViewContext;
//
//     /*! @brief This is the status of the registration of the identity. It starts off in an initial status, and ends in a confirmed status */
//     @property (nonatomic, readonly) DSBlockchainIdentityRegistrationStatus registrationStatus;
//
//     /*! @brief This is the localized status of the registration of the identity returned as a string. It starts off in an initial status, and ends in a confirmed status */
//     @property (nonatomic, readonly) NSString *localizedRegistrationStatusString;
//
//     /*! @brief This is a convenience method that checks to see if registrationStatus is confirmed */
//     @property (nonatomic, readonly, getter=isRegistered) BOOL registered;
//
//     /*! @brief This is a convenience factory to quickly make dashpay documents */
//     @property (nonatomic, readonly) DPDocumentFactory *dashpayDocumentFactory;
//
//     /*! @brief This is a convenience factory to quickly make dpns documents */
//     @property (nonatomic, readonly) DPDocumentFactory *dpnsDocumentFactory;
//
//     /*! @brief DashpaySyncronizationBlock represents the last L1 block height for which Dashpay would be synchronized, if this isn't at the end of the chain then we need to query L2 to make sure we don't need to update our bloom filter */
//     @property (nonatomic, readonly) uint32_t dashpaySyncronizationBlockHeight;
//
//     /*! @brief DashpaySyncronizationBlock represents the last L1 block hash for which Dashpay would be synchronized */
//     @property (nonatomic, readonly) UInt256 dashpaySyncronizationBlockHash;
// }
//
// impl IdentityModel {
//
//     /// Related to registering the identity. This is the address used to fund the registration of the identity.
//     /// Dash sent to this address in the special credit funding transaction will be converted to L2 credits
//     pub fn registration_funding_address(&self) -> String {
//         if (self.registrationCreditFundingTransaction) {
//
//             return [DSKeyManager addressFromHash160:self.registrationCreditFundingTransaction.creditBurnPublicKeyHash forChain:self.chain];
//         } else {
//             DSCreditFundingDerivationPath *derivationPathRegistrationFunding;
//             if (self.isOutgoingInvitation) {
//                 derivationPathRegistrationFunding = [[DSDerivationPathFactory sharedInstance] blockchainIdentityInvitationFundingDerivationPathForWallet:self.wallet];
//             } else {
//                 derivationPathRegistrationFunding = [[DSDerivationPathFactory sharedInstance] blockchainIdentityRegistrationFundingDerivationPathForWallet:self.wallet];
//             }
//
//             return [derivationPathRegistrationFunding addressAtIndex:self.index];
//         }
//
//     }
// }