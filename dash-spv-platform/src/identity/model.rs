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

use std::collections::HashMap;
use dpp::identity::{Identity, IdentityPublicKey};
use dpp::identity::identity_public_key::{Purpose, SecurityLevel};
use dash_spv_crypto::keys::key::KeyKind;
use dash_spv_crypto::keys::{IKey, OpaqueKey};
use crate::document::usernames::UsernameStatus;
use crate::identity::manager::identity_public_key;

#[ferment_macro::export]
#[derive(Clone, PartialEq, Eq)]
pub enum IdentityKeyStatus {
    Unknown = 0,
    Registered = 1,
    Registering = 2,
    NotRegistered = 3,
    Revoked = 4,
}
impl From<u8> for IdentityKeyStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => IdentityKeyStatus::Unknown,
            1 => IdentityKeyStatus::Registered,
            2 => IdentityKeyStatus::Registering,
            3 => IdentityKeyStatus::NotRegistered,
            4 => IdentityKeyStatus::Revoked,
            _ => panic!("Invalid value for IdentityKeyStatus {value}"),
        }
    }
}
impl From<&IdentityKeyStatus> for u8 {
    fn from(value: &IdentityKeyStatus) -> Self {
        match value {
            IdentityKeyStatus::Unknown => 0,
            IdentityKeyStatus::Registered => 1,
            IdentityKeyStatus::Registering => 2,
            IdentityKeyStatus::NotRegistered => 3,
            IdentityKeyStatus::Revoked => 4,
        }
    }
}

#[ferment_macro::export]
impl IdentityKeyStatus {
    pub fn to_index(&self) -> u8 {
        u8::from(self)
    }
    pub fn from_index(index: u8) -> IdentityKeyStatus {
        IdentityKeyStatus::from(index)
    }

    pub fn string(&self) -> String {
        match self {
            IdentityKeyStatus::Unknown => "Unknown",
            IdentityKeyStatus::Registered => "Registered",
            IdentityKeyStatus::Registering => "Registering",
            IdentityKeyStatus::NotRegistered => "Not Registered",
            IdentityKeyStatus::Revoked => "Revoked",
        }.to_string()
    }

    pub fn string_description(&self) -> String {
        format!("Status of Key or Username is {}", self.string())
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, IdentityKeyStatus::Unknown)
    }
    pub fn is_registered(&self) -> bool {
        matches!(self, IdentityKeyStatus::Registered)
    }
    pub fn is_registering(&self) -> bool {
        matches!(self, IdentityKeyStatus::Registering)
    }
    pub fn is_not_registered(&self) -> bool {
        matches!(self, IdentityKeyStatus::NotRegistered)
    }
    pub fn is_revoked(&self) -> bool {
        matches!(self, IdentityKeyStatus::Revoked)
    }
}


#[ferment_macro::export]
#[derive(Clone, PartialEq, Eq)]
pub enum IdentityRegistrationStatus {
    Unknown = 0,
    Registered = 1,
    Registering = 2,
    NotRegistered = 3, //sent to DAPI, not yet confirmed
}

impl From<u8> for IdentityRegistrationStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => IdentityRegistrationStatus::Unknown,
            1 => IdentityRegistrationStatus::Registered,
            2 => IdentityRegistrationStatus::Registering,
            3 => IdentityRegistrationStatus::NotRegistered,
            _ => panic!("Invalid value for IdentityRegistrationStatus {value}"),
        }
    }
}
impl From<&IdentityRegistrationStatus> for u8 {
    fn from(value: &IdentityRegistrationStatus) -> Self {
        match value {
            IdentityRegistrationStatus::Unknown => 0,
            IdentityRegistrationStatus::Registered => 1,
            IdentityRegistrationStatus::Registering => 2,
            IdentityRegistrationStatus::NotRegistered => 3,
        }
    }
}

#[ferment_macro::export]
impl IdentityRegistrationStatus {
    pub fn to_index(&self) -> u8 {
        u8::from(self)
    }
    pub fn from_index(index: u8) -> IdentityRegistrationStatus {
        IdentityRegistrationStatus::from(index)
    }
    pub fn is_unknown(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::Unknown)
    }
    pub fn is_registered(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::Registered)
    }
    pub fn is_registering(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::Registering)
    }
    pub fn is_not_registered(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::NotRegistered)
    }

    pub fn string(&self) -> String {
        match self {
            IdentityRegistrationStatus::Unknown => "Unknown",
            IdentityRegistrationStatus::Registered => "Registered",
            IdentityRegistrationStatus::Registering => "Registering",
            IdentityRegistrationStatus::NotRegistered => "Not Registered",
        }.to_string()
    }
}
#[ferment_macro::export]
#[derive(Clone)]
pub struct KeyInfo {
    pub key: OpaqueKey,
    pub key_type: KeyKind,
    pub key_status: IdentityKeyStatus,
    pub security_level: SecurityLevel,
    pub purpose: Purpose,
}

#[ferment_macro::export]
#[derive(Clone)]
pub struct UsernameStatusInfo {
    pub proper: Option<String>,
    pub domain: Option<String>,
    pub status: UsernameStatus,
    pub salt: Vec<u8>,
}

impl UsernameStatusInfo {
    pub fn with_status(status: UsernameStatus) -> Self {
        Self {
            proper: None,
            domain: None,
            status,
            salt: vec![],
        }
    }
    pub fn confirmed(&self) -> Self {
        let mut s = self.clone();
        s.status = UsernameStatus::Confirmed;
        s
    }
}
#[ferment_macro::opaque]
pub struct IdentityModel {
    pub identity: Option<Identity>,
    pub identity_registration_status: IdentityRegistrationStatus,
    pub key_info_dictionaries: HashMap<u32, KeyInfo>,
    pub username_domains: HashMap<String, Vec<u8>>,
    pub username_salts: HashMap<String, Vec<u8>>,
    pub username_statuses: HashMap<String, UsernameStatusInfo>,
}

#[ferment_macro::export]
impl IdentityModel {

    pub fn new(status: IdentityRegistrationStatus) -> Self {
        Self {
            identity_registration_status: status,
            identity: None,
            key_info_dictionaries: Default::default(),
            username_domains: Default::default(),
            username_salts: Default::default(),
            username_statuses: Default::default()
        }
    }

    pub fn set_registration_status(&mut self, status: IdentityRegistrationStatus) {
        self.identity_registration_status = status;
    }
    pub fn registration_status(&self) -> IdentityRegistrationStatus {
        self.identity_registration_status.clone()
    }
    pub fn registration_status_index(&self) -> u8 {
        u8::from(&self.identity_registration_status)
    }
    pub fn is_registered(&self) -> bool {
        self.identity_registration_status == IdentityRegistrationStatus::Registered
    }
    pub fn set_identity(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }
    pub fn identity(&self) -> Option<Identity> {
        self.identity.clone()
    }

    pub fn add_username(&mut self, username: String, domain: String, status: UsernameStatus) {
        let full_path = Self::full_path_for_username(&username, &domain);
        self.username_statuses.insert(full_path, UsernameStatusInfo {
            proper: Some(username),
            domain: Some(domain),
            status,
            salt: Default::default(),
        });
    }
    pub fn add_username_with_salt(&mut self, username: String, domain: String, status: UsernameStatus, salt: Vec<u8>)  {
        let full_path = Self::full_path_for_username(&username, &domain);
        self.username_statuses.insert(full_path, UsernameStatusInfo {
            proper: Some(username),
            domain: Some(domain),
            status,
            salt,
        });
    }

    pub fn add_key_info(&mut self, index: u32, key_info: KeyInfo) {
        self.key_info_dictionaries.insert(index, key_info);
    }

    pub fn add_salt(&mut self, username: String, salt: Vec<u8>) {
        self.username_salts.insert(username, salt);
    }

    pub fn salt_for_username(&self, username: &str) -> Option<Vec<u8>> {
        self.username_salts.get(username).cloned()
    }

    pub fn full_path_for_username(username: &str, domain: &str) -> String {
        username.to_lowercase() + "." + &domain.to_lowercase()
    }

    pub fn username_full_paths_with_status(&self, status: UsernameStatus) -> Vec<String> {
        self.username_statuses.iter().filter_map(|(full_path, info)| {
            if status.eq(&info.status) {
                Some(full_path.clone())
            } else {
                None
            }
        }).collect()
    }

    pub fn unregistered_username_full_paths(&self) -> Vec<String> {
        self.username_full_paths_with_status(UsernameStatus::Initial)
    }
    pub fn confirmed_username_full_paths(&self) -> Vec<String> {
        self.username_full_paths_with_status(UsernameStatus::Confirmed)
    }

    pub fn unregistered_username_full_paths_count(&self) -> usize {
        self.unregistered_username_full_paths().len()
    }
    pub fn confirmed_username_full_paths_count(&self) -> usize {
        self.confirmed_username_full_paths().len()
    }

    pub fn status_of_username(&self, username: &str, domain: &str) -> Option<UsernameStatus> {
        self.status_of_username_full_path(Self::full_path_for_username(username, domain))
    }

    pub fn status_of_dashpay_username(&self, username: String) -> Option<UsernameStatus> {
        self.status_of_username_full_path(Self::full_path_for_username(&username, "dash"))
    }
    pub fn status_of_username_full_path(&self, username_full_path: String) -> Option<UsernameStatus> {
        self.username_statuses.get(&username_full_path).map(|s| s.status.clone())
    }
    pub fn status_index_of_username_full_path(&self, username_full_path: String) -> Option<u8> {
        self.username_statuses.get(&username_full_path).map(|s| s.status.clone().into())
    }
    pub fn status_of_username_full_path_is_initial(&self, username_full_path: String) -> bool {
        self.username_statuses.get(&username_full_path).map(|s| s.status == UsernameStatus::Initial).unwrap_or_default()
    }
    pub fn username_of_username_full_path(&self, username_full_path: &str) -> Option<String> {
        self.username_statuses.get(username_full_path).and_then(|s| s.proper.clone())
    }
    pub fn domain_of_username_full_path(&self, username_full_path: String) -> Option<String> {
        self.username_statuses.get(&username_full_path).and_then(|s| s.domain.clone())
    }

    pub fn dashpay_username_full_paths(&self) -> Vec<String> {
        self.username_statuses.keys().cloned().collect()
    }
    pub fn username_statuses(&self) -> HashMap<String, UsernameStatusInfo> {
        self.username_statuses.clone()
    }

    pub fn usernames_and_domains(&self, username_full_paths: Vec<String>) -> Vec<(String, String)> {
        username_full_paths.iter().filter_map(|username_full_path| {
            if let Some(UsernameStatusInfo { proper, domain, .. }) = self.username_statuses.get(username_full_path) {
                match (proper, domain) {
                    (Some(proper), Some(domain)) => Some((proper.clone(), domain.clone())),
                    _ => None
                }
            } else {
                None
            }
        }).collect()
    }

    pub fn dashpay_usernames(&self) -> Vec<String> {
        self.username_statuses.iter().filter_map(|(full_path, _)| self.username_of_username_full_path(full_path)).collect()
    }
    pub fn has_dashpay_username(&self, username: &str) -> bool {
        self.username_statuses.iter().any(|(full_path, _)| {
            if let Some(u) = self.username_of_username_full_path(full_path) {
                u.eq(username)
            } else {
                false
            }
        })
    }

    pub fn set_username_full_paths(&mut self, username_full_paths: Vec<String>, status: UsernameStatus) {
        username_full_paths.into_iter().for_each(|full_path | self.set_username_status(full_path, status.clone()));
    }

    pub fn set_username_status(&mut self, username_full_path: String, status: UsernameStatus) {
        if let Some(status_info) = self.username_statuses.get_mut(&username_full_path) {
            status_info.status = status;
        } else {
            self.username_statuses.insert(username_full_path, UsernameStatusInfo::with_status(status));
        }
    }
    pub fn set_username_status_confirmed(&mut self, username: String, normalized_parent_domain_name: String, label: String) -> bool {
        // TODO: check it (migrated as is, but it maybe wrong)
        let full_path_username = Self::full_path_for_username(&username, "dash");
        let maybe_status = self.username_statuses.get(&username);
        let is_new = maybe_status.is_none();
        let status_info = if let Some(status_info) = maybe_status {
            status_info.confirmed()
        } else {
            UsernameStatusInfo {
                proper: Some(label),
                domain: Some(normalized_parent_domain_name),
                status: UsernameStatus::Confirmed,
                salt: vec![],
            }
        };
        self.username_statuses.insert(full_path_username, status_info);
        is_new
    }
    pub fn set_username_status_confirmed2(&mut self, username: String, domain: String, lowercase_username: String) -> bool {
        // TODO: check it (migrated as is, but it maybe wrong)
        let full_path_username = Self::full_path_for_username(&username, &domain);
        let maybe_status = self.username_statuses.get(&Self::full_path_for_username(&lowercase_username, &domain));
        let is_new = maybe_status.is_none();
        let status_info = if let Some(status_info) = maybe_status {
            status_info.confirmed()
        } else {
            UsernameStatusInfo {
                proper: Some(username),
                domain: Some(domain),
                status: UsernameStatus::Confirmed,
                salt: vec![],
            }
        };
        self.username_statuses.insert(full_path_username, status_info);
        is_new
    }


    pub fn active_key_count(&self) -> usize {
        self.key_info_dictionaries.values().filter(|KeyInfo { key_status, .. }| IdentityKeyStatus::Registered.eq(key_status)).count()
    }
    pub fn total_key_count(&self) -> usize {
        self.key_info_dictionaries.len()
    }
    pub fn key_info_dictionaries(&self) -> HashMap<u32, KeyInfo> {
        self.key_info_dictionaries.clone()
    }

    pub fn active_keys_for_key_type(&self, kind: KeyKind) -> Vec<OpaqueKey> {
        self.key_info_dictionaries.values().filter_map(|info| info.key_type.eq(&kind).then_some(&info.key)).cloned().collect()
    }

    pub fn verify_signature(&mut self, signature: Vec<u8>, kind: KeyKind, digest: [u8; 32]) -> bool {
        for info in self.key_info_dictionaries.values_mut() {
            if info.key_type.eq(&kind) {
                if let Ok(true) = info.key.verify(&digest, &signature) {
                    return true;
                }
            }
        }
        false
    }

    pub fn key_info_at_index(&self, index: u32) -> Option<KeyInfo> {
        self.key_info_dictionaries.get(&index).map(|info| info.clone())
    }

    pub fn status_of_key_at_index(&self, index: u32) -> Option<IdentityKeyStatus> {
        self.key_info_dictionaries.get(&index).map(|info| info.key_status.clone())
    }

    pub fn key_at_index(&self, index: u32) -> Option<OpaqueKey> {
        self.key_info_dictionaries.get(&index).map(|info| info.key.clone())
    }


    pub fn first_identity_public_key(&self, security_level: SecurityLevel, purpose: Purpose) -> Option<IdentityPublicKey> {
        self.key_info_dictionaries.iter().find_map(|(index, KeyInfo { key, security_level: level, purpose: p, .. })| {
            if security_level.eq(level) && purpose.eq(p) {
                Some(identity_public_key(*index, key.clone(), security_level, purpose))
            } else {
                None
            }
        })

    }

}
