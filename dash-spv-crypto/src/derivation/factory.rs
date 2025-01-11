use std::collections::HashMap;
use dashcore::bip32::DerivationPath;

pub struct Factory {
    pub voting_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub owner_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub operator_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub evonode_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub provider_funds_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub identity_registration_funding_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub identity_topup_funding_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub identity_invitation_funding_key_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub identity_bls_derivation_path_by_wallet: HashMap<String, DerivationPath>,
    pub identity_ecdsa_derivation_path_by_wallet: HashMap<String, DerivationPath>,

    // @property (nonatomic, strong) NSMutableDictionary *votingKeysDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *ownerKeysDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *operatorKeysDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *platformNodeKeysDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *providerFundsDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *blockchainIdentityRegistrationFundingDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *blockchainIdentityTopupFundingDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *blockchainIdentityInvitationFundingDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *blockchainIdentityBLSDerivationPathByWallet;
    // @property (nonatomic, strong) NSMutableDictionary *blockchainIdentityECDSADerivationPathByWallet;
}

