use crate::derivation::UInt256IndexPath;

pub enum DerivationPathKind {

}

pub enum DerivationPathReference {
    Unknown = 0,
    BIP32 = 1,
    BIP44 = 2,
    BlockchainIdentities = 3,
    ProviderFunds = 4,
    ProviderVotingKeys = 5,
    ProviderOperatorKeys = 6,
    ProviderOwnerKeys = 7,
    ContactBasedFunds = 8,
    ContactBasedFundsRoot = 9,
    ContactBasedFundsExternal = 10,
    BlockchainIdentityCreditRegistrationFunding = 11,
    BlockchainIdentityCreditTopupFunding = 12,
    BlockchainIdentityCreditInvitationFunding = 13,
    ProviderPlatformNodeKeys = 14,
    Root = 255,
}

pub enum DerivationPathType {

}

pub struct DerivationPath {
    pub base: UInt256IndexPath,

}

// impl DerivationPath {
//     pub fn derivation_path_with_indexes(indexes: [UInt256; 32], hardened: [bool; 32], length: u32, type_: DerivationPathType, signingAlgorithm: dash_spv_crypto_keys_key_KeyKind, reference: DerivationPathReference, onChain: DSChain) -> Self {
//         // Self {}
//     }
//
//     pub fn master_identity_contacts_derivation_path_for_account_number(account_number: u32) -> Self {
//         let indexes = UInt256
//         let hardened = vec![true, true, true, true];
//     }
// }

// + (instancetype)masterBlockchainIdentityContactsDerivationPathForAccountNumber:(uint32_t)accountNumber
// onChain:(DSChain *)chain {
// UInt256 indexes[] = {uint256_from_long(FEATURE_PURPOSE), uint256_from_long(chain.coinType), uint256_from_long(FEATURE_PURPOSE_DASHPAY), uint256_from_long(accountNumber)};
// //todo full uint256 derivation
// BOOL hardenedIndexes[] = {YES, YES, YES, YES};
//
// dash_spv_crypto_keys_key_KeyKind *key_kind = dash_spv_crypto_keys_key_KeyKind_ECDSA_ctor();
// return [self derivationPathWithIndexes:indexes
// hardened:hardenedIndexes
// length:4
// type:DSDerivationPathType_PartialPath
// signingAlgorithm:key_kind
// reference:DSDerivationPathReference_ContactBasedFundsRoot
// onChain:chain];
// }
//
