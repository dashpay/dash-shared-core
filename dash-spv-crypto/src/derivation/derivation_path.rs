use std::ops::Index;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use bitflags::bitflags;
use dashcore::bip32::DerivationPath;
use dashcore::dip9::{DerivationPathReference, DerivationPathType};
use dashcore::secp256k1::hashes::hex::DisplayHex;
use indexmap::{IndexMap, IndexSet};
use dash_spv_keychain::{KeyChainKey, KeyChainValue, KeychainController};
use crate::derivation::{IIndexPath, IndexPath, BIP32_HARD};
use crate::keys::{DeriveKey, ECDSAKey, IKey, KeyError, OpaqueKey};
use crate::keys::key::KeyKind;
use crate::network::{ChainType, IHaveChainSettings};
use crate::util::address::address;
use crate::util::{from_hash160_for_script_map, is_valid_dash_address_for_script_map};


pub const SEQUENCE_GAP_LIMIT_EXTERNAL: usize = 10;
pub const SEQUENCE_GAP_LIMIT_INTERNAL: usize = 5;
pub const SEQUENCE_GAP_LIMIT_INITIAL: usize = 100;

pub const SEQUENCE_UNUSED_GAP_LIMIT_EXTERNAL: usize = 10;
pub const SEQUENCE_UNUSED_GAP_LIMIT_INTERNAL: usize = 5;
pub const SEQUENCE_UNUSED_GAP_LIMIT_INITIAL: usize = 15;

pub const SEQUENCE_DASHPAY_GAP_LIMIT_INCOMING: usize = 6;
pub const SEQUENCE_DASHPAY_GAP_LIMIT_OUTGOING: usize = 3;
pub const SEQUENCE_DASHPAY_GAP_LIMIT_INITIAL: usize = 10;

pub struct AddressInfo {
    pub index: u32,
    pub address: String,
    pub is_used: bool,
    pub standalone: bool,
    pub internal: Option<bool>,
    pub identity_index: Option<u32>,
}

#[derive(Clone)]
pub enum AccountKind {
    Standalone(StandaloneInfo),
    Account(AccountInfo),
}
impl AccountKind {
    pub fn is_transient(&self) -> bool {
        match self {
            AccountKind::Standalone(_) => true,
            AccountKind::Account(info) => info.is_transient
        }
    }
}

#[derive(Clone, Debug)]
pub enum SecretSource<'a> {
    Seed(&'a [u8]),
    ExtendedPrivateKeyData(&'a [u8]),
}

#[derive(Clone, Debug)]
pub struct AccountInfo {
    pub account_number: u32,
    pub wallet_unique_id: String,
    pub is_transient: bool,
}

#[derive(Clone, Debug)]
pub struct StandaloneInfo {
    pub extended_public_key_identifier: String
}

pub trait KeychainAccessible {
    fn keychain_ref(&self) -> &KeychainController;
}
pub trait DBAccessible {
    fn db_ref(&self) -> &DBController;
}

pub trait AccountKindAccessible {
    fn account_ref(&self) -> &AccountKind;
    fn account_is_transient(&self) -> bool {
        self.account_ref().is_transient()
    }
}

pub enum DerivationError {
    AddressesMustBeLoaded,
    UnsupportedSettings(RegisterAddressesSettings),
    PublicKeyGeneration,
}
impl From<KeyError> for DerivationError {
    fn from(_value: KeyError) -> Self {
        DerivationError::PublicKeyGeneration
    }
}
pub enum DerivationStorageContext {
    Index(u32),
    IndexedAddress(u32, String),
    IndexedAddressIdentity(u32, String, u32),
    Addresses(IndexMap<u32, String>, FundsDirection),
    LoadAddresses(AccountKind),
}

bitflags! {
    #[derive(Clone, PartialEq)]
    pub struct FundsDirection: u32 {
        const Internal = 1;
        const External = 2;
        const All = Self::Internal.bits() | Self::External.bits();
    }
}
#[derive(Clone)]
pub enum RegisterAddressesSettings {
    GapLimit(usize),
    GapLimitFunds(usize, FundsDirection),
    GapLimitIdentity(usize, u32),
}

pub trait RegisterAddressesWithSettings {
    fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<(u32, String)>, DerivationError>;
    fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<(u32, String)>, DerivationError>;
}

pub trait KeyDataAtIndexPath<T> {
    fn private_key_at_index_path(&self, index_path: IndexPath<T>, source: SecretSource) -> Result<OpaqueKey, KeyError>;
    fn public_key_at_index_path(&self, index_path: IndexPath<T>) -> Result<OpaqueKey, KeyError>;
    fn public_key_data_at_index_path(&self, index_path: IndexPath<T>) -> Result<Vec<u8>, KeyError>;
}

#[derive(Clone)]
pub enum DerivationPathKind {
    Funds(Funds),
    IncomingFunds(IncomingFunds),
    AssetSwap(AssetSwap),
    Authentication(Authentication),
    MasternodeHoldings(MasternodeHoldings),
}

impl DerivationPathKind {
    pub fn is_simple_indexed(&self) -> bool {
        match self {
            DerivationPathKind::AssetSwap(_) |
            DerivationPathKind::Authentication(_) |
            DerivationPathKind::MasternodeHoldings(_) => true,
            _ => false
        }
    }
}

#[derive(Clone)]
pub struct Funds {
    // pub base: DerivationPathModel,
    pub all_change_addresses: IndexSet<String>,
    pub all_receive_addresses: IndexSet<String>,
    pub internal_addresses: Vec<(u32, String)>,
    pub external_addresses: Vec<(u32, String)>,

    pub is_for_first_account: bool,
    pub has_known_balance_internal: bool,
    pub checked_initial_has_known_balance: bool,
}

// impl AccountKindAccessible for Funds {
//     fn account_ref(&self) -> &AccountKind {
//         self.base.account_ref()
//     }
// }
//
// impl DBAccessible for Funds {
//     fn db_ref(&self) -> &DBController {
//         self.base.db_ref()
//     }
// }

// impl Funds {
    // pub fn addresses(&self, internal: bool) -> Vec<(u32, String)> {
    //     Vec::from_iter(if internal {
    //         self.internal_addresses.iter().cloned()
    //     } else {
    //         self.external_addresses.iter().cloned()
    //     })
    // }
    /// returns the first unused external address
    // pub fn receive_address(&mut self) -> Option<String> {
    //     //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
    //     if let Ok(addr) = self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitFunds(1, FundsDirection::External)) {
    //         addr.last().map(|(_, address)| address.clone())
    //     } else {
    //         self.all_receive_addresses.last().cloned()
    //     }
    // }
    // pub fn change_address(&mut self) -> Option<String> {
    //     //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
    //     self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitFunds(1, FundsDirection::Internal))
    //         .ok()
    //         .and_then(|addresses| addresses.last().map(|(_, address)| address.clone()))
    // }

    // pub fn contains_change_address(&self, address: &str) -> bool {
    //     self.all_change_addresses.contains(address)
    // }
    // pub fn contains_receive_address(&self, address: &str) -> bool {
    //     self.all_receive_addresses.contains(address)
    // }
    //
    // pub fn used_receive_addresses(&self) -> Vec<String> {
    //     self.all_receive_addresses.intersection(&self.base.used_addresses)
    //         .cloned()
    //         .collect()
    // }
    // pub fn used_change_addresses(&self) -> Vec<String> {
    //     self.all_change_addresses.intersection(&self.base.used_addresses)
    //         .cloned()
    //         .collect()
    // }
    //
    // pub fn should_use_reduced_gap_limit(&mut self) -> bool {
    //     if !self.checked_initial_has_known_balance {
    //         if let AccountKind::Account(AccountInfo { wallet_unique_id, .. }) = self.account_ref() {
    //             if let Ok(KeyChainValue::Int64(has_known_balance)) = self.base.keychain_ref().get(KeyChainKey::HasKnownBalanceUniqueIDString { reference: self.base.reference as u32, unique_id: wallet_unique_id.clone() }) {
    //                 self.has_known_balance_internal = has_known_balance == 1;
    //                 self.checked_initial_has_known_balance = true;
    //             }
    //         }
    //     }
    //     !self.has_known_balance_internal && !(self.is_for_first_account && self.base.reference == DerivationPathReference::BIP44)
    // }

    // pub fn addresses_for_export(&self, internal_start: usize, internal_len: usize, external_start: usize, external_len: usize) -> Vec<String> {
    //     let mut addresses = (internal_start..internal_start + internal_len)
    //         .into_iter()
    //         .filter_map(|index| {
    //             let index_path = IndexPath::index_path_with_indexes(vec![1, index as u32]);
    //             if let Ok(pub_key) = self.public_key_data_at_index_path(index_path) {
    //                 ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone())
    //             } else {
    //                 None
    //             }
    //         })
    //         .collect::<Vec<_>>();
    //     addresses.extend((external_start..external_start + external_len)
    //         .into_iter()
    //         .filter_map(|index| {
    //             let index_path = IndexPath::index_path_with_indexes(vec![0, index as u32]);
    //             if let Ok(pub_key) = self.public_key_data_at_index_path(index_path) {
    //                 ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone())
    //             } else {
    //                 None
    //             }
    //         }));
    //     addresses
    // }

    /// gets an address at an index path
    // pub fn address_at_index(&self, index: u32, internal: bool) -> Result<String, KeyError> {
    //     let pub_key = self.public_key_data_at_index(index, internal)?;
    //     if let Some(address ) = ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone()) {
    //         Ok(address)
    //     } else {
    //         Err(KeyError::Any("Can't generate address from public key data".to_string()))
    //     }
    // }

    // pub fn index_path_of_known_address(&self, address: &str) -> Option<IndexPath<u32>> {
    //     if let Some(index) = self.all_change_addresses.get_index_of(address) {
    //         Some(IndexPath::index_path_with_indexes(vec![1, index as u32]))
    //     } else if let Some(index) = self.all_receive_addresses.get_index_of(address) {
    //         Some(IndexPath::index_path_with_indexes(vec![0, index as u32]))
    //     } else {
    //         None
    //     }
    // }


    // pub fn public_key_data_at_index(&self, n: u32, internal: bool) -> Result<Vec<u8>, KeyError> {
    //     let path = IndexPath::new(vec![ if internal { 1 } else { 0 }, n]);
    //     self.base.public_key_data_at_index_path(path)
    // }
    //
// }

#[derive(Clone)]
pub struct IncomingFunds {
    // pub base: DerivationPathModel,
    pub external_addresses: Vec<(u32, String)>,
    pub contact_source_identity_unique_id: [u8; 32],
    pub contact_destination_identity_unique_id: [u8; 32],
}

// impl IncomingFunds {
//     /// returns the first unused external address
//     pub fn receive_address(&mut self) -> Option<String> {
//         self.receive_address_in_context(self.base.controller.context)
//     }
//
//     pub fn receive_address_in_context(&mut self, context: *const std::os::raw::c_void) -> Option<String> {
//         self.receive_address_at_offset_in_context(0, context)
//     }
//
//     pub fn receive_address_at_offset(&mut self, offset: usize) -> Option<String> {
//         self.receive_address_at_offset_in_context(offset, self.base.controller.context)
//     }
//     pub fn receive_address_at_offset_in_context(&mut self, offset: usize, context: *const std::os::raw::c_void) -> Option<String> {
//         //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
//         if let Ok(addr) = self.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimit(offset + 1), context) {
//             addr.last().map(|(_, address)| address).cloned()
//         } else {
//             self.external_addresses.last().map(|(_, addr)| addr.clone())
//         }
//     }
// }
//
// #[derive(Clone)]
// pub struct SimpleIndexed {
//     pub base: DerivationPathModel,
//     pub ordered_addresses: Vec<(u32, String)>,
// }
//
// impl KeychainAccessible for SimpleIndexed {
//     fn keychain_ref(&self) -> &KeychainController {
//         self.base.keychain_ref()
//     }
// }
//
// impl DBAccessible for SimpleIndexed {
//     fn db_ref(&self) -> &DBController {
//         self.base.db_ref()
//     }
// }




// pub trait SimpleIndexed {
//     fn first_unused_index(&self) -> usize;
//     fn addresses_to_index(&mut self, index: u32) -> Vec<String>;
//     fn addresses_to_index_using_cache(&mut self, index: u32, use_cache: bool, add_to_cache: bool) -> Vec<String>;
//     fn private_keys_for_range(&self, from: u32, len: u32, secret_source: SecretSource) -> Vec<OpaqueKey>;
//     fn private_keys_to_index(&self, index: u32, secret_source: SecretSource) -> Vec<OpaqueKey>;
//     fn address_at_index(&self, index: u32) -> Result<String, KeyError>;
// }

//
//
// impl_simple_indexed!(Authentication);
// impl_simple_indexed!(MasternodeHoldings);
// impl_simple_indexed!(AssetSwap);
//
// impl RegisterAddressesWithSettings for Funds {
//     fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<(u32, String)>, DerivationError> {
//         self.register_addresses_with_settings_and_context(settings, self.base.controller.context)
//     }
//
//     fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<(u32, String)>, DerivationError> {
//         match settings {
//             RegisterAddressesSettings::GapLimitFunds(gap_limit, direction) => {
//                 if !self.account_is_transient() {
//                     return Err(DerivationError::AddressesMustBeLoaded);
//                 }
//                 let mut ret = self.addresses(direction == FundsDirection::Internal);
//                 let mut i = ret.len();
//
//                 // keep only the trailing contiguous block of addresses with no transactions
//                 while i > 0 && !self.base.address_is_used(&ret[i - 1].1) {
//                     i -= 1;
//                 }
//
//                 if i > 0 {
//                     ret.drain(..i);
//                 }
//                 if ret.len() >= gap_limit {
//                     ret.drain(gap_limit..);
//                     return Ok(ret);
//                 }
//
//                 if gap_limit > 1 { // get receiveAddress and changeAddress first to avoid blocking
//                     let _ = self.receive_address();
//                     let _ = self.change_address();
//                 }
//
//                 //It seems weird to repeat this, but it's correct because of the original call receive address and change address
//                 ret = self.addresses(direction == FundsDirection::Internal);
//                 i = ret.len();
//
//                 let mut n = i as u32;
//
//                 // keep only the trailing contiguous block of addresses with no transactions
//                 while i > 0 && !self.base.address_is_used(&ret[i - 1].1) {
//                     i -= 1;
//                 }
//                 if i > 0 {
//                     ret.drain(..i);
//                 }
//                 if ret.len() >= gap_limit {
//                     ret.drain(gap_limit..);
//                     return Ok(ret);
//                 }
//                 let mut add_addresses = IndexMap::new();
//                 while ret.len() < gap_limit { // generate new addresses up to gapLimit
//                     let pub_key = self.public_key_data_at_index(n, direction == FundsDirection::Internal).map_err(DerivationError::from)?;
//                     if let Some(addr) = ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone()) {
//                         self.base.all_addresses.insert(addr.clone());
//                         if direction == FundsDirection::Internal {
//                             self.internal_addresses.push((n, addr.clone()));
//                         } else {
//                             self.external_addresses.push((n, addr.clone()));
//                         }
//                         ret.push((n, addr.clone()));
//                         add_addresses.insert(n, addr);
//                         n += 1;
//                     } else {
//                         print!("[{}] error generating keys", self.base.chain_type.name());
//                         return Err(DerivationError::PublicKeyGeneration);
//                     }
//                 }
//
//                 if !self.account_is_transient() {
//                     self.db_ref().store_in_context(context, DerivationStorageContext::Addresses(add_addresses, direction));
//                 }
//                 Ok(ret)
//             }
//             settings => Err(DerivationError::UnsupportedSettings(settings))
//         }
//     }
// }
// impl AccountKindAccessible for IncomingFunds {
//     fn account_ref(&self) -> &AccountKind {
//         self.base.account_ref()
//     }
// }
// impl DBAccessible for IncomingFunds {
//     fn db_ref(&self) -> &DBController {
//         self.base.db_ref()
//     }
// }
// impl RegisterAddressesWithSettings for IncomingFunds {
//     fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<(u32, String)>, DerivationError> {
//         self.register_addresses_with_settings_and_context(settings, self.base.controller.context)
//     }
//
//     fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<(u32, String)>, DerivationError> {
//         match settings {
//             RegisterAddressesSettings::GapLimit(gap_limit) => {
//                 if !self.account_is_transient() {
//                     if !self.base.controller.addresses_loaded {
//                         sleep(Duration::from_millis(1000)); //quite hacky, we need to fix this
//                     }
//                     if !self.base.controller.addresses_loaded {
//                         return Err(DerivationError::AddressesMustBeLoaded);
//                     }
//                 }
//                 let mut ret = Vec::from_iter(self.external_addresses.iter().cloned());
//                 let mut i = ret.len();
//                 // keep only the trailing contiguous block of addresses with no transactions
//                 while i > 0 && !self.base.address_is_used(&ret[i - 1].1) {
//                     i -= 1;
//                 }
//                 if i > 0 {
//                     ret.drain(..i);
//                 }
//                 if ret.len() >= gap_limit {
//                     ret.drain(gap_limit..);
//                     return Ok(ret);
//                 }
//                 if gap_limit > 1 {
//                     // get receiveAddress and changeAddress first to avoid blocking
//                     let _ = self.receive_address_in_context(context);
//                 }
//                 // It seems weird to repeat this, but it's correct because of the original call receive address and change address
//                 ret = Vec::from_iter(self.external_addresses.clone());
//                 i = ret.len();
//
//                 let mut n = i as u32;
//
//                 // keep only the trailing contiguous block of addresses with no transactions
//                 while i > 0 && !self.base.address_is_used(&ret[i - 1].1) {
//                     i -= 1;
//                 }
//
//                 if i > 0 {
//                     ret.drain(..i);
//                 }
//                 if ret.len() >= gap_limit {
//                     ret.drain(gap_limit..);
//                     return Ok(ret);
//                 }
//
//                 let mut upper_limit = gap_limit;
//                 while ret.len() < upper_limit { // generate new addresses up to gapLimit
//                     let pub_key = self.public_key_data_at_index_path(IndexPath::index_path_with_index(n))?;
//                     if let Some(address) = ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone()) {
//                         if !self.account_is_transient() {
//                             let is_used = self.base.store_new_address_in_context(address.as_str(), n, context);
//                             if is_used {
//                                 self.base.used_addresses.insert(address.clone());
//                                 upper_limit += 1;
//                             }
//                         }
//                         self.base.all_addresses.insert(address.clone());
//                         self.external_addresses.push((n , address.clone()));
//                         ret.push((n, address));
//                         n += 1;
//
//                     } else {
//                         print!("[{}] error generating keys", self.base.chain_type.name());
//                         return Err(DerivationError::PublicKeyGeneration);
//                     }
//                 }
//                 Ok(ret)
//             },
//             settings => Err(DerivationError::UnsupportedSettings(settings))
//         }
//     }
// }

// impl AccountKindAccessible for SimpleIndexed {
//     fn account_ref(&self) -> &AccountKind {
//         self.base.account_ref()
//     }
// }
// impl RegisterAddressesWithSettings for SimpleIndexed {
//     fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<(u32, String)>, DerivationError> {
//         self.register_addresses_with_settings_and_context(settings, self.base.controller.context)
//     }
//
//     fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<(u32, String)>, DerivationError> {
//         match settings {
//             RegisterAddressesSettings::GapLimit(gap_limit) => {
//                 let mut ret = Vec::from_iter(self.ordered_addresses.clone());
//                 if !self.account_is_transient() {
//                     if !self.base.controller.addresses_loaded {
//                         return Err(DerivationError::AddressesMustBeLoaded);
//                     }
//                 }
//                 let mut i = ret.len();
//                 // keep only the trailing contiguous block of addresses that aren't used
//                 while i > 0 && !self.base.address_is_used(&ret[i - 1].1) {
//                     i -= 1;
//                 }
//                 if i > 0 {
//                     ret.drain(..i);
//                 }
//                 if ret.len() >= gap_limit {
//                     ret.drain(gap_limit..);
//                     return Ok(ret);
//                 }
//                 //It seems weird to repeat this, but it's correct because of the original call receive address and change address
//                 ret = Vec::from_iter(self.ordered_addresses.clone());
//                 i = ret.len();
//                 let mut n = i as u32;
//
//                 // keep only the trailing contiguous block of addresses with no transactions
//                 while i > 0 && !self.base.address_is_used(&ret[i - 1].1) {
//                     i -= 1;
//                 }
//                 if i > 0 {
//                     ret.drain(..i);
//                 }
//                 if ret.len() >= gap_limit {
//                     ret.drain(gap_limit..);
//                     Ok(ret)
//                 } else {
//                     while ret.len() < gap_limit { // generate new addresses up to gapLimit
//
//                         let pub_key = self.base.public_key_data_at_index_path(IndexPath::index_path_with_index(n))?;
//                         let addr = address::with_public_key_data(&pub_key, self.base.chain_type.clone());
//                         if !self.account_is_transient() {
//                             self.base.store_new_address_in_context(&addr, n, context);
//                         }
//                         self.base.all_addresses.insert(addr.clone());
//                         ret.push((n, addr.clone()));
//                         self.ordered_addresses.push((n, addr));
//                         n += 1;
//                     }
//                     Ok(ret)
//                 }
//             },
//             settings => Err(DerivationError::UnsupportedSettings(settings))
//         }
//     }
// }
// impl AccountKindAccessible for Authentication {
//     fn account_ref(&self) -> &AccountKind {
//         self.base.account_ref()
//     }
// }
// impl DBAccessible for Authentication {
//     fn db_ref(&self) -> &DBController {
//         self.base.db_ref()
//     }
// }
//
// impl RegisterAddressesWithSettings for Authentication {
//     fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<(u32, String)>, DerivationError> {
//         self.register_addresses_with_settings_and_context(settings, self.base.base.controller.context)
//     }
//
//     fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<(u32, String)>, DerivationError> {
//         match settings {
//             RegisterAddressesSettings::GapLimit(..) =>
//                 self.base.register_addresses_with_settings_and_context(settings, context),
//             RegisterAddressesSettings::GapLimitIdentity(gap_limit, identity_index) => {
//                 if !self.account_is_transient() {
//                     if !self.base.base.controller.addresses_loaded {
//                         return Err(DerivationError::AddressesMustBeLoaded);
//                     }
//                     assert_ne!(self.base.base.path_type, DerivationPathType::SINGLE_USER_AUTHENTICATION, "This should not be called for single user authentication. Use '- (NSArray *)registerAddressesWithGapLimit:(NSUInteger)gapLimit error:(NSError**)error' instead.");
//                     if self.use_hardened_keys && !self.has_extended_private_key() {
//                         return Ok(vec![]);
//                     }
//                     if self.addresses_by_identity.get(&identity_index).is_none() {
//                         self.addresses_by_identity.insert(identity_index, vec![]);
//                     }
//                     let mut ret = self.addresses_by_identity.get(&identity_index).cloned().unwrap();
//                     let mut i = ret.len();
//
//                     // keep only the trailing contiguous block of addresses with no transactions
//                     while i > 0 && !self.base.base.address_is_used(&ret[i - 1].1) {
//                         i -= 1;
//                     }
//                     if i > 0 {
//                         ret.drain(..i);
//                     }
//                     if ret.len() >= gap_limit {
//                         ret.drain(gap_limit..);
//                         return Ok(ret);
//                     }
//
//                     //It seems weird to repeat this, but it's correct because of the original call receive address and change address
//                     ret = self.addresses_by_identity.get(&identity_index).cloned().unwrap();
//                     i = ret.len();
//
//                     let mut n = i as u32;
//
//                     // keep only the trailing contiguous block of addresses with no transactions
//                     while i > 0 && !self.base.base.address_is_used(&ret[i - 1].1) {
//                         i -= 1;
//                     }
//                     if i > 0 {
//                         ret.drain(..i);
//                     }
//                     if ret.len() >= gap_limit {
//                         ret.drain(gap_limit..);
//                         return Ok(ret);
//                     }
//
//                     while ret.len() < gap_limit {
//                         // generate new addresses up to gapLimit
//                         let hardened_indexes = vec![identity_index | BIP32_HARD, n | BIP32_HARD];
//                         let soft_indexes = vec![identity_index, n];
//                         let indexes = if self.use_hardened_keys { hardened_indexes } else { soft_indexes };
//                         let pub_key = self.base.base.public_key_data_at_index_path(IndexPath::new(indexes)).map_err(DerivationError::from)?;
//                         let addr = address::with_public_key_data(&pub_key, self.base.base.chain_type.clone());
//                         if !self.account_is_transient() {
//                             self.db_ref().store_in_default_context(DerivationStorageContext::IndexedAddressIdentity(n, addr.clone(), identity_index));
//                         }
//                         self.base.base.all_addresses.insert(addr.clone());
//                         if let Some(addrs) = self.addresses_by_identity.get_mut(&identity_index) {
//                             addrs.push((n, addr.clone()));
//                         }
//                         ret.push((n, addr));
//                         n += 1;
//                     }
//                     Ok(ret)
//                 } else {
//                     Ok(vec![])
//                 }
//
//             },
//             _ => Err(DerivationError::UnsupportedSettings(settings))
//         }
//     }
// }


#[derive(Clone)]
pub struct AssetSwap {
    pub ordered_addresses: Vec<(u32, String)>,
    // pub base: SimpleIndexed,

}

#[derive(Clone)]
pub struct Authentication {
    // pub base: SimpleIndexed,
    pub ordered_addresses: Vec<(u32, String)>,
    pub use_hardened_keys: bool,
    pub should_store_extended_private_key: bool,
    pub addresses_by_identity: IndexMap<u32, Vec<(u32, String)>>,
}
// impl KeychainAccessible for DerivationPathModel {
//     fn keychain_ref(&self) -> &KeychainController {
//         self.controller.keychain_controller.as_ref()
//     }
// }
//
// impl KeychainAccessible for Authentication {
//     fn keychain_ref(&self) -> &KeychainController {
//         self.base.keychain_ref()
//     }
// }

// impl Authentication {
//     pub fn has_extended_private_key(&self) -> bool {
//         if let AccountKind::Account(AccountInfo { wallet_unique_id, ..}) = self.account_ref() {
//             if let Ok(true) = self.keychain_ref().has(KeyChainKey::wallet_based_extended_private_key_location_string(wallet_unique_id)) {
//                 return true;
//             }
//         }
//         false
//     }
//     pub fn extended_private_key_data(&self) -> Option<Vec<u8>> {
//         if let AccountKind::Account(AccountInfo { wallet_unique_id, ..}) = self.account_ref() {
//             if let Ok(KeyChainValue::Bytes(data)) = self.keychain_ref().get(KeyChainKey::wallet_based_extended_private_key_location_string(wallet_unique_id)) {
//                 return Some(data);
//             }
//         }
//         None
//     }
//
//     pub fn first_unused_public_key(&self) -> Result<Vec<u8>, KeyError> {
//         let index_path = IndexPath::index_path_with_index(self.first_unused_index() as u32);
//         self.public_key_data_at_index_path(index_path)
//     }
//
//     //
//     pub fn first_unused_private_key_from_seed(&self, seed: &[u8]) -> Result<OpaqueKey, KeyError> {
//         let index_path = IndexPath::index_path_with_index(self.first_unused_index() as u32);
//         self.private_key_at_index_path(index_path, SecretSource::Seed(seed))
//     }
// }

#[derive(Clone)]
pub struct MasternodeHoldings {
    pub ordered_addresses: Vec<(u32, String)>,
    // pub base: SimpleIndexed,
}

#[derive(Clone)]
pub struct DBController {
    pub context: *const std::os::raw::c_void,
    pub store_in_context: Arc<dyn Fn(*const std::os::raw::c_void, DerivationStorageContext) -> bool + Send + Sync>,
    pub load_in_context: Arc<dyn Fn(*const std::os::raw::c_void, AccountKind) -> Vec<AddressInfo> + Send + Sync>,
}
impl DBController {
    pub fn new<
        SC: Fn(*const std::os::raw::c_void, DerivationStorageContext) -> bool + Send + Sync + 'static,
        LAC: Fn(*const std::os::raw::c_void, AccountKind) -> Vec<AddressInfo> + Send + Sync + 'static,
    >(store_in_context: SC, load_in_context: LAC, context: *const std::os::raw::c_void) -> DBController {
        Self {
            context,
            store_in_context: Arc::new(store_in_context),
            load_in_context: Arc::new(load_in_context),
        }
    }
}

impl DBController {
    pub fn store_new_address(&self, address: &str, index: u32) -> bool {
        (self.store_in_context)(self.context, DerivationStorageContext::IndexedAddress(index, address.to_string()))
    }
    pub fn store_new_address_in_context(&self, address: &str, index: u32, context: *const std::os::raw::c_void) -> bool {
        (self.store_in_context)(context, DerivationStorageContext::IndexedAddress(index, address.to_string()))
    }

    pub fn store_in_context(&self, context: *const std::os::raw::c_void, data: DerivationStorageContext) -> bool {
        (self.store_in_context)(context, data)
    }
    pub fn store_in_default_context(&self, data: DerivationStorageContext) -> bool {
        (self.store_in_context)(self.context, data)
    }

    pub fn load_addresses_in_context(&self, context: *const std::os::raw::c_void, account_kind: AccountKind) -> Vec<AddressInfo> {
        (self.load_in_context)(context, account_kind)
    }

}

#[derive(Clone)]
pub struct DerivationPathController {
    pub context: *const std::os::raw::c_void,
    pub keychain_controller: Arc<KeychainController>,
    pub db_controller: Arc<DBController>,
    pub addresses_loaded: bool,
}
#[derive(Clone)]
pub struct DerivationPathModel {
    pub chain_type: ChainType,
    pub kind: DerivationPathKind,
    // TODO: rust-dashcore hides the details of DerivationPath
    pub path: DerivationPath,
    pub path_type: DerivationPathType,
    pub reference: DerivationPathReference,
    pub signing_algorithm: KeyKind,

    pub account_kind: AccountKind,

    pub controller: DerivationPathController,

    pub all_addresses: IndexSet<String>,
    pub used_addresses: IndexSet<String>,
    /// master public key used to generate wallet addresses
    pub extended_pub_key: Option<OpaqueKey>,
}

// impl AccountKindAccessible for DerivationPathModel {
//     fn account_ref(&self) -> &AccountKind {
//         &self.account_kind
//     }
// }
//
// impl DBAccessible for DerivationPathModel {
//     fn db_ref(&self) -> &DBController {
//         self.controller.db_controller.as_ref()
//     }
// }

impl DerivationPathModel {
    pub fn new<
        SC: Fn(*const std::os::raw::c_void, DerivationStorageContext) -> bool + Send + Sync + 'static,
        LAC: Fn(*const std::os::raw::c_void, AccountKind) -> Vec<AddressInfo> + Send + Sync + 'static,
    >(
        keychain_controller: Arc<KeychainController>,
        store_in_context: SC,
        load_addresses_in_context: LAC,
        account_kind: AccountKind,
        kind: DerivationPathKind,
        path_type: DerivationPathType,
        path: DerivationPath,
        reference: DerivationPathReference,
        signing_algorithm: KeyKind,
        context: *const std::os::raw::c_void,
        chain_type: ChainType
    ) -> Self {
        Self {
            chain_type,
            kind,
            path,
            path_type,
            reference,
            signing_algorithm,
            account_kind,
            all_addresses: IndexSet::new(),
            used_addresses: IndexSet::new(),
            controller: DerivationPathController {
                context,
                keychain_controller,
                db_controller: Arc::new(DBController::new(store_in_context, load_addresses_in_context, context)),
                addresses_loaded: false,
            },
            extended_pub_key: None,
        }
    }

    pub fn keychain_ref(&self) -> &KeychainController {
        self.controller.keychain_controller.as_ref()
    }

    pub fn db_ref(&self) -> &DBController {
        self.controller.db_controller.as_ref()
    }
    fn account_is_transient(&self) -> bool {
        self.account_kind.is_transient()
    }

    pub fn extended_public_key_keychain_key(&self) -> KeyChainKey {
        match &self.account_kind {
            AccountKind::Standalone(StandaloneInfo { extended_public_key_identifier, .. }) =>
                KeyChainKey::standalone_extended_public_key_location_string(extended_public_key_identifier),
            AccountKind::Account(AccountInfo { wallet_unique_id, .. }) =>
                KeyChainKey::wallet_based_extended_public_key_location_string(wallet_unique_id),
        }
        // if self.account_info.is_some() && (self.path.len() > 0 || self.reference == DerivationPathReference::Root) {
        //     KeyChainKey::WalletBasedExtendedPublicKeyLocationString { unique_id: self.unique_id.clone() }
        // } else {
        //     KeyChainKey::StandaloneExtendedPublicKeyLocationString { extended_public_key_identifier: self.unique_id.clone() }
        // }
    }
    pub fn extended_public_key(&self) -> Result<OpaqueKey, KeyError> {
        if let Some(ext_pub_key) = &self.extended_pub_key {
            Ok(ext_pub_key.clone())
        } else {
            let key = self.extended_public_key_keychain_key();
            if let Ok(KeyChainValue::Bytes(data)) = self.controller.keychain_controller.get(key) {
                self.signing_algorithm.key_with_extended_public_key_data(&data)
            } else {
                Err(KeyError::Any("Unable to get extended public key".to_string()))
            }
        }
    }
    pub fn has_extended_public_key(&self) -> bool {
        if self.extended_pub_key.is_some() {
            return true;
        }
        let key = self.extended_public_key_keychain_key();
        if let Ok(true) = self.controller.keychain_controller.has(key) {
            true
        } else {
            false
        }
    }

    pub fn extended_public_key_data(&self) -> Result<Vec<u8>, KeyError> {
        self.extended_public_key().and_then(|key| key.extended_public_key_data())
    }

    pub fn generate_extended_public_key_from_seed(&mut self, seed: &[u8], store_under_wallet_unique_id: Option<String>, store_private_key: bool) -> Result<OpaqueKey, KeyError> {
        if seed.is_empty() {
            return Err(KeyError::EmptySecKey);
        }
        if self.path.len() == 0 && self.reference != DerivationPathReference::Root {
            // there needs to be at least 1 length
            return Err(KeyError::UnableToDerive);
        }
        let key = self.signing_algorithm.key_with_seed_data(seed)
            .and_then(|seed_key| seed_key.private_derive_to_path(self))?;
        self.extended_pub_key = Some(key.clone());
        if let Some(wallet_unique_id) = store_under_wallet_unique_id {
            let pub_key_data = key.extended_public_key_data()?;
            let _ = self.controller.keychain_controller.set(KeyChainKey::wallet_based_extended_public_key_location_string(wallet_unique_id.as_str()), KeyChainValue::Bytes(pub_key_data), false);
            if store_private_key {
                let prv_key_data = key.extended_private_key_data()?;
                let _ = self.controller.keychain_controller.set(KeyChainKey::wallet_based_extended_private_key_location_string(wallet_unique_id.as_str()), KeyChainValue::Bytes(prv_key_data.to_vec()), true);
            }
        }
        Ok(key)
    }

    pub fn generate_extended_public_key_from_parent_derivation_path(&mut self, parent_derivation_path: &DerivationPathModel, store_under_wallet_unique_id: Option<String>) -> Result<OpaqueKey, KeyError> {
        if parent_derivation_path.signing_algorithm != self.signing_algorithm {
            return Err(KeyError::Any("The signing algorithms must be the same".to_string()));
        }
        if self.path.len() <= parent_derivation_path.path.len() {
            return Err(KeyError::Any("The length must be inferior to the parent derivation path length".to_string()));
        }
        let parent_ext_pub_key = parent_derivation_path.extended_public_key()?;
        let last_parent_index = parent_derivation_path.path.len() - 1;
        for i in 0..last_parent_index {
            let parent_index = parent_derivation_path.path.index(i);
            let index = self.path.index(i);
            if parent_index != index {
                return Err(KeyError::Any("This derivation path must start with elements of the parent derivation path".to_string()));
            }
        }
        let child_key = parent_ext_pub_key.public_derive_to_path_with_offset(self, parent_derivation_path.path.len())?;
        self.extended_pub_key = Some(child_key.clone());
        if let Some(wallet_unique_id) = store_under_wallet_unique_id {
            let pub_key_data = child_key.extended_public_key_data()?;
            let _ = self.keychain_ref().set(KeyChainKey::wallet_based_extended_public_key_location_string(wallet_unique_id.as_str()), KeyChainValue::Bytes(pub_key_data), false);
        }
        Ok(child_key)
    }


    pub fn private_key_at_index_path(&self, index_path: IndexPath<u32>, source: SecretSource) -> Result<OpaqueKey, KeyError> {
        if self.path.is_empty() {
            Err(KeyError::UnableToDerive)
        } else {
            match source {
                SecretSource::Seed(seed) => {
                    let top_key = self.signing_algorithm.key_with_seed_data(seed)?;
                    let key = top_key.private_derive_to_path(self)?;
                    key.private_derive_to_path(&index_path)
                }
                SecretSource::ExtendedPrivateKeyData(data) => {
                    self.signing_algorithm.derive_key_from_extended_private_key_data_for_index_path_u32(data, index_path)
                }
            }
        }
    }



    pub fn store_new_address(&self, address: &str, index: u32) -> bool {
        self.db_ref().store_new_address(address, index)
    }
    pub fn store_new_address_in_context(&self, address: &str, index: u32, context: *const std::os::raw::c_void) -> bool {
        self.db_ref().store_new_address_in_context(address, index, context)
    }

    /// true if the address is controlled by the wallet
    pub fn contains_address(&self, address: &str) -> bool {
        self.all_addresses.contains(address)
    }
    pub fn contains_address_hash(&self, hash: &[u8; 20]) -> bool {
        let addr = from_hash160_for_script_map(hash, &self.chain_type.script_map());
        self.contains_address(&addr)
    }
    /// true if the address was previously used as an input or output in any wallet transaction
    pub fn address_is_used(&self, address: &str) -> bool {
        self.used_addresses.contains(address)
    }

    pub fn address_at_index_path(&self, index_path: IndexPath<u32>) -> Result<String, KeyError> {
        match &self.kind {
            DerivationPathKind::Funds(_) => {
                let pub_key = self.public_key_data_at_index_path(index_path)?;
                if let Some(address ) = ECDSAKey::address_from_public_key_data(&pub_key, self.chain_type.clone()) {
                    Ok(address)
                } else {
                    Err(KeyError::Any("Can't generate address from public key data".to_string()))
                }
            },
            _ => {
                let pub_key = self.public_key_data_at_index_path(index_path)?;
                Ok(address::with_public_key_data_and_script_pub_key(&pub_key, self.chain_type.script_map().pubkey))
            }
        }
    }
    pub fn index_path_of_known_address(&self, address: &str) -> Option<IndexPath<u32>> {
        match &self.kind {
            DerivationPathKind::Funds(model) => if let Some(index) = model.all_change_addresses.get_index_of(address) {
                Some(IndexPath::index_path_with_indexes(vec![1, index as u32]))
            } else if let Some(index) = model.all_receive_addresses.get_index_of(address) {
                Some(IndexPath::index_path_with_indexes(vec![0, index as u32]))
            } else {
                None
            }
            DerivationPathKind::IncomingFunds(model) =>
                model.external_addresses.iter()
                    .find_map(|(index, addr)| addr.eq(address)
                        .then_some(IndexPath::index_path_with_index(*index))),
            DerivationPathKind::AssetSwap(AssetSwap { ordered_addresses, .. }) |
            DerivationPathKind::Authentication(Authentication { ordered_addresses, .. }) |
            DerivationPathKind::MasternodeHoldings(MasternodeHoldings { ordered_addresses, .. }) =>
                ordered_addresses.iter()
                    .find_map(|(index, addr)| addr.eq(address)
                        .then_some(IndexPath::index_path_with_index(*index))),
        }
    }

    /// inform the derivation path that the address has been used by a transaction, true if the derivation path contains the address
    pub fn register_transaction_address(&mut self, address: &str) -> bool {
        let contains = self.contains_address(address);
        if contains && !self.address_is_used(address) {
            self.used_addresses.insert(address.to_string());
            let _addresses = match &mut self.kind {
                DerivationPathKind::Funds(model) if model.all_change_addresses.contains(address) =>
                    self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitFunds(SEQUENCE_GAP_LIMIT_INTERNAL, FundsDirection::Internal)),
                DerivationPathKind::Funds(..) =>
                    self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitFunds(SEQUENCE_GAP_LIMIT_EXTERNAL, FundsDirection::External)),
                DerivationPathKind::IncomingFunds(..) =>
                    self.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_EXTERNAL)),
                DerivationPathKind::AssetSwap(..) =>
                    self.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_INTERNAL)),
                DerivationPathKind::Authentication(..) =>
                    self.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_EXTERNAL)),
                DerivationPathKind::MasternodeHoldings(..) =>
                    self.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_INTERNAL)),
            };
        }
        contains
    }
    pub fn load_addresses_in_context(&self, context: *const std::os::raw::c_void) -> Vec<AddressInfo> {
        self.db_ref().load_addresses_in_context(context, self.account_kind.clone())
    }
    pub fn load_addresses(&mut self) {
        if self.controller.addresses_loaded { return }
        let addresses = self.load_addresses_in_context(self.controller.context);

        match &mut self.kind {
            DerivationPathKind::Funds(model) => {
                for AddressInfo { internal, address, index, is_used, ..} in addresses {
                    if !is_valid_dash_address_for_script_map(&address, &self.chain_type.script_map()) {
                        #[cfg(debug_assertions)]
                        println!("{} address %@ loaded but was not valid on chain {}", self.chain_type.name(), address);
                        #[cfg(not(debug_assertions))]
                        println!("{} address %@ loaded but was not valid on chain <REDACTED>", self.chain_type.name());
                        continue;
                    }
                    let container = if internal.unwrap() { &mut model.internal_addresses } else { &mut model.external_addresses };
                    container.push((index, address.clone()));
                    self.all_addresses.insert(address.clone());
                    if is_used {
                        self.used_addresses.insert(address.clone());
                    }
                }

                self.controller.addresses_loaded = true;
                let reduced_gap_limit = self.should_use_reduced_gap_limit();
                let gap_limit = if reduced_gap_limit { SEQUENCE_UNUSED_GAP_LIMIT_INITIAL } else { SEQUENCE_GAP_LIMIT_INITIAL };
                let _ = self.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimitFunds(gap_limit, FundsDirection::Internal), self.controller.context);
                let _ = self.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimitFunds(gap_limit, FundsDirection::External), self.controller.context);
            },
            DerivationPathKind::IncomingFunds(model) => {
                for AddressInfo { address, index, is_used, ..} in addresses {
                    if !is_valid_dash_address_for_script_map(&address, &self.chain_type.script_map()) {
                        #[cfg(debug_assertions)]
                        println!("{} address %@ loaded but was not valid on chain {}", self.chain_type.name(), address);
                        #[cfg(not(debug_assertions))]
                        println!("{} address %@ loaded but was not valid on chain <REDACTED>", self.chain_type.name());
                        continue;
                    }
                    model.external_addresses.push((index, address.clone()));
                    self.all_addresses.insert(address.clone());
                    if is_used {
                        self.used_addresses.insert(address.clone());
                    }
                }
                self.controller.addresses_loaded = true;
                let _ = self.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimit(SEQUENCE_DASHPAY_GAP_LIMIT_INITIAL), self.controller.context);
            },
            DerivationPathKind::Authentication(..) => {
                self.controller.addresses_loaded = true;
                let _ = self.register_addresses_with_settings(if self.path_type == DerivationPathType::SINGLE_USER_AUTHENTICATION {
                    RegisterAddressesSettings::GapLimit(10)
                } else {
                    RegisterAddressesSettings::GapLimitIdentity(10, 0)
                });
            },
            DerivationPathKind::AssetSwap(..) |
            DerivationPathKind::MasternodeHoldings(..) => {
                self.controller.addresses_loaded = true;
                let _ = self.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(10));
            },
        }
    }

    pub fn create_identifier_for_derivation_path(&self) -> Result<String, KeyError> {
        let extended_public_key = self.extended_public_key()?;
        let identifier = extended_public_key.create_identifier()?;
        let hex = identifier.to_lower_hex_string();
        Ok(hex[..7].to_string())
    }

    pub fn receive_address(&mut self) -> Option<String> {
        match &self.kind {
            DerivationPathKind::Funds(model) => {
                //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
                if let Ok(addr) = self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitFunds(1, FundsDirection::External)) {
                    addr.last().map(|(_, address)| address.clone())
                } else {
                    model.all_receive_addresses.last().cloned()
                }
            }
            DerivationPathKind::IncomingFunds(_) => self.receive_address_in_context(self.controller.context),
            _ => None
        }
    }
    pub fn change_address(&mut self) -> Option<String> {
        //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        match &self.kind {
            DerivationPathKind::Funds(..) => {
                self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitFunds(1, FundsDirection::Internal))
                    .ok()
                    .and_then(|addresses| addresses.last().map(|(_, address)| address.clone()))
            },
            _ => None
        }
    }

    pub fn contains_change_address(&self, address: &str) -> bool {
        if let DerivationPathKind::Funds(model) = &self.kind {
            model.all_change_addresses.contains(address)
        } else {
            false
        }
    }
    pub fn contains_receive_address(&self, address: &str) -> bool {
        if let DerivationPathKind::Funds(model) = &self.kind {
            model.all_receive_addresses.contains(address)
        } else {
            false
        }
    }

    pub fn used_receive_addresses(&self) -> Vec<String> {
        if let DerivationPathKind::Funds(model) = &self.kind {
            model.all_receive_addresses.intersection(&self.used_addresses)
                .cloned()
                .collect()
        } else {
            vec![]
        }
    }
    pub fn used_change_addresses(&self) -> Vec<String> {
        if let DerivationPathKind::Funds(model) = &self.kind {
            model.all_change_addresses.intersection(&self.used_addresses)
                .cloned()
                .collect()
        } else {
            vec![]
        }
    }

    pub fn should_use_reduced_gap_limit(&mut self) -> bool {
        if let DerivationPathKind::Funds(model) = &mut self.kind {
            if !model.checked_initial_has_known_balance {
                if let AccountKind::Account(AccountInfo { wallet_unique_id, .. }) = &self.account_kind {
                    if let Ok(KeyChainValue::Int64(has_known_balance)) = self.keychain_ref().get(KeyChainKey::HasKnownBalanceUniqueIDString { reference: self.reference as u32, unique_id: wallet_unique_id.clone() }) {
                        model.has_known_balance_internal = has_known_balance == 1;
                        model.checked_initial_has_known_balance = true;
                    }
                }
            }
            !model.has_known_balance_internal && !(model.is_for_first_account && self.reference == DerivationPathReference::BIP44)
        } else {
            panic!("");
        }
    }
    pub fn addresses_for_export(&self, internal_start: usize, internal_len: usize, external_start: usize, external_len: usize) -> Vec<String> {
        match &self.kind {
            DerivationPathKind::Funds(..) => {
                let mut addresses = (internal_start..internal_start + internal_len)
                    .into_iter()
                    .filter_map(|index| {
                        let index_path = IndexPath::index_path_with_indexes(vec![1, index as u32]);
                        if let Ok(pub_key) = self.public_key_data_at_index_path(index_path) {
                            ECDSAKey::address_from_public_key_data(&pub_key, self.chain_type.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                addresses.extend((external_start..external_start + external_len)
                    .into_iter()
                    .filter_map(|index| {
                        let index_path = IndexPath::index_path_with_indexes(vec![0, index as u32]);
                        if let Ok(pub_key) = self.public_key_data_at_index_path(index_path) {
                            ECDSAKey::address_from_public_key_data(&pub_key, self.chain_type.clone())
                        } else {
                            None
                        }
                    }));
                addresses
            },
            _ => vec![]
        }
    }

    pub fn receive_address_in_context(&mut self, context: *const std::os::raw::c_void) -> Option<String> {
        self.receive_address_at_offset_in_context(0, context)
    }

    pub fn receive_address_at_offset(&mut self, offset: usize) -> Option<String> {
        self.receive_address_at_offset_in_context(offset, self.controller.context)
    }
    pub fn receive_address_at_offset_in_context(&mut self, offset: usize, context: *const std::os::raw::c_void) -> Option<String> {
        match &self.kind {
            DerivationPathKind::Funds(_) => None,
            DerivationPathKind::IncomingFunds(model) => {
                //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
                if let Ok(addr) = self.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimit(offset + 1), context) {
                    addr.last().map(|(_, address)| address).cloned()
                } else {
                    model.external_addresses.last().map(|(_, addr)| addr.clone())
                }
            },
            _ => None,
        }
    }


    pub fn has_extended_private_key(&self) -> bool {
        if let DerivationPathKind::Authentication(..) = &self.kind {
            if let AccountKind::Account(AccountInfo { wallet_unique_id, ..}) = &self.account_kind {
                if let Ok(true) = self.keychain_ref().has(KeyChainKey::wallet_based_extended_private_key_location_string(wallet_unique_id)) {
                    return true;
                }
            }
        }
        false
    }
    pub fn extended_private_key_data(&self) -> Option<Vec<u8>> {
        if let DerivationPathKind::Authentication(..) = &self.kind {
            if let AccountKind::Account(AccountInfo { wallet_unique_id, ..}) = &self.account_kind {
                if let Ok(KeyChainValue::Bytes(data)) = self.keychain_ref().get(KeyChainKey::wallet_based_extended_private_key_location_string(wallet_unique_id)) {
                    return Some(data);
                }
            }
        }
        None
    }

    pub fn first_unused_public_key(&self) -> Result<Vec<u8>, KeyError> {
        if let DerivationPathKind::Authentication(..) = &self.kind {
            let index_path = IndexPath::index_path_with_index(self.first_unused_index() as u32);
            self.public_key_data_at_index_path(index_path)
        } else {
            Err(KeyError::Any("Unsupported".to_string()))
        }
    }

    //
    pub fn first_unused_private_key_from_seed(&self, seed: &[u8]) -> Result<OpaqueKey, KeyError> {
        if let DerivationPathKind::Authentication(..) = &self.kind {
            let index_path = IndexPath::index_path_with_index(self.first_unused_index() as u32);
            self.private_key_at_index_path(index_path, SecretSource::Seed(seed))
        } else {
            Err(KeyError::Any("Unsupported".to_string()))
        }
    }

    pub fn first_unused_index(&self) -> usize {
        match &self.kind {
            DerivationPathKind::AssetSwap(AssetSwap { ordered_addresses, .. }) |
            DerivationPathKind::Authentication(Authentication { ordered_addresses, .. }) |
            DerivationPathKind::MasternodeHoldings(MasternodeHoldings { ordered_addresses, .. }) => {
                let mut i = ordered_addresses.len();
                // keep only the trailing contiguous block of addresses that aren't used
                while i > 0 && !self.address_is_used(&ordered_addresses[i - 1].1) {
                    i -= 1;
                }
                i
            }
            _ => 0
        }
    }


    pub fn addresses_to_index(&mut self, index: u32) -> Vec<String> {
        self.addresses_to_index_using_cache(index, false, false)
    }

    pub fn addresses_to_index_using_cache(&mut self, index: u32, use_cache: bool, add_to_cache: bool) -> Vec<String> {
        match &mut self.kind {
            DerivationPathKind::AssetSwap(AssetSwap { ordered_addresses, .. }) |
            DerivationPathKind::Authentication(Authentication { ordered_addresses, .. }) |
            DerivationPathKind::MasternodeHoldings(MasternodeHoldings { ordered_addresses, .. }) => {
                let mut addresses = vec![];
                for i in 0..index {
                    match ordered_addresses.iter().find_map(|(id, addr)| (*id == i).then_some(addr)) {
                        Some(address) if use_cache && ordered_addresses.len() > i as usize => {
                            addresses.push(address.clone());
                        },
                        _ => match self.public_key_data_at_index_path(IndexPath::index_path_with_index(i)) {
                            Ok(pub_key) => {
                                let addr = address::with_public_key_data(&pub_key, self.chain_type.clone());
                                addresses.push(addr.clone());
                                if add_to_cache && ordered_addresses.len() == i as usize {
                                    ordered_addresses.push((i, addr));
                                }
                            },
                            Err(err) => {
                                println!("Error getting public key data at index {i}: {err}");
                                return addresses;
                            }
                        }
                    }
                }
                addresses
            },
            _ => vec![]
        }
    }

    pub fn private_keys_for_range(&self, from: u32, len: u32, secret_source: SecretSource) -> Vec<OpaqueKey> {
        (from..from + len).into_iter()
            .map(IndexPath::index_path_with_index)
            .filter_map(|index_path| self.private_key_at_index_path(index_path, secret_source.clone()).ok())
            .collect()
    }

    pub fn private_keys_to_index(&self, index: u32, secret_source: SecretSource) -> Vec<OpaqueKey> {
        self.private_keys_for_range(0, index, secret_source)
    }

}

/// Wallets are composed of chains of addresses. Each chain is traversed until a gap of a certain number of addresses is
/// found that haven't been used in any transactions. This method returns an array of <gapLimit> unused addresses
/// following the last used address in the chain. The internal chain is used for change addresses and the external chain
/// for receive addresses.
impl RegisterAddressesWithSettings for DerivationPathModel {
    fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<(u32, String)>, DerivationError> {
        self.register_addresses_with_settings_and_context(settings, self.controller.context)
    }

    fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<(u32, String)>, DerivationError> {
        match (settings, &mut self.kind) {
            (RegisterAddressesSettings::GapLimitFunds(gap_limit, direction),
                DerivationPathKind::Funds(model)) => {
                if !self.account_is_transient() {
                    return Err(DerivationError::AddressesMustBeLoaded);
                }
                let mut ret = Vec::from_iter(if direction == FundsDirection::Internal {
                    model.internal_addresses.iter().cloned()
                } else {
                    model.external_addresses.iter().cloned()
                });

                let mut i = ret.len();

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                    i -= 1;
                }

                if i > 0 {
                    ret.drain(..i);
                }
                if ret.len() >= gap_limit {
                    ret.drain(gap_limit..);
                    return Ok(ret);
                }

                if gap_limit > 1 { // get receiveAddress and changeAddress first to avoid blocking
                    let _ = self.receive_address();
                    let _ = self.change_address();
                }

                //It seems weird to repeat this, but it's correct because of the original call receive address and change address
                ret = Vec::from_iter(if direction == FundsDirection::Internal {
                    model.internal_addresses.iter().cloned()
                } else {
                    model.external_addresses.iter().cloned()
                });
                i = ret.len();

                let mut n = i as u32;

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                    i -= 1;
                }
                if i > 0 {
                    ret.drain(..i);
                }
                if ret.len() >= gap_limit {
                    ret.drain(gap_limit..);
                    return Ok(ret);
                }
                let mut add_addresses = IndexMap::new();
                while ret.len() < gap_limit { // generate new addresses up to gapLimit
                    let index_path = IndexPath::index_path_with_indexes(vec![ if direction == FundsDirection::Internal { 1 } else { 0 }, n]);
                    let pub_key = self.public_key_data_at_index_path(index_path).map_err(DerivationError::from)?;
                    if let Some(addr) = ECDSAKey::address_from_public_key_data(&pub_key, self.chain_type.clone()) {
                        self.all_addresses.insert(addr.clone());
                        if direction == FundsDirection::Internal {
                            model.internal_addresses.push((n, addr.clone()));
                        } else {
                            model.external_addresses.push((n, addr.clone()));
                        }
                        ret.push((n, addr.clone()));
                        add_addresses.insert(n, addr);
                        n += 1;
                    } else {
                        print!("[{}] error generating keys", self.chain_type.name());
                        return Err(DerivationError::PublicKeyGeneration);
                    }
                }

                if !self.account_is_transient() {
                    self.db_ref().store_in_context(context, DerivationStorageContext::Addresses(add_addresses, direction));
                }
                Ok(ret)

            }
            (RegisterAddressesSettings::GapLimit(gap_limit),
                DerivationPathKind::IncomingFunds(model)) => {
                if !self.account_is_transient() {
                    if !self.controller.addresses_loaded {
                        sleep(Duration::from_millis(1000)); //quite hacky, we need to fix this
                    }
                    if !self.controller.addresses_loaded {
                        return Err(DerivationError::AddressesMustBeLoaded);
                    }
                }
                let mut ret = Vec::from_iter(model.external_addresses.iter().cloned());
                let mut i = ret.len();
                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                    i -= 1;
                }
                if i > 0 {
                    ret.drain(..i);
                }
                if ret.len() >= gap_limit {
                    ret.drain(gap_limit..);
                    return Ok(ret);
                }
                if gap_limit > 1 {
                    // get receiveAddress and changeAddress first to avoid blocking
                    let _ = self.receive_address_in_context(context);
                }
                // It seems weird to repeat this, but it's correct because of the original call receive address and change address
                ret = Vec::from_iter(model.external_addresses.clone());
                i = ret.len();

                let mut n = i as u32;

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                    i -= 1;
                }

                if i > 0 {
                    ret.drain(..i);
                }
                if ret.len() >= gap_limit {
                    ret.drain(gap_limit..);
                    return Ok(ret);
                }

                let mut upper_limit = gap_limit;
                while ret.len() < upper_limit { // generate new addresses up to gapLimit
                    let pub_key = self.public_key_data_at_index_path(IndexPath::index_path_with_index(n))?;
                    if let Some(address) = ECDSAKey::address_from_public_key_data(&pub_key, self.chain_type.clone()) {
                        if !self.account_is_transient() {
                            let is_used = self.store_new_address_in_context(address.as_str(), n, context);
                            if is_used {
                                self.used_addresses.insert(address.clone());
                                upper_limit += 1;
                            }
                        }
                        self.all_addresses.insert(address.clone());
                        model.external_addresses.push((n , address.clone()));
                        ret.push((n, address));
                        n += 1;

                    } else {
                        print!("[{}] error generating keys", self.chain_type.name());
                        return Err(DerivationError::PublicKeyGeneration);
                    }
                }
                Ok(ret)
            }
            (RegisterAddressesSettings::GapLimit(gap_limit),
                DerivationPathKind::AssetSwap(AssetSwap { ordered_addresses, .. }) |
                DerivationPathKind::MasternodeHoldings(MasternodeHoldings { ordered_addresses, .. }) |
                DerivationPathKind::Authentication(Authentication { ordered_addresses, .. })) => {
                let mut ret = Vec::from_iter(ordered_addresses.clone());
                if !self.account_is_transient() {
                    if !self.controller.addresses_loaded {
                        return Err(DerivationError::AddressesMustBeLoaded);
                    }
                }
                let mut i = ret.len();
                // keep only the trailing contiguous block of addresses that aren't used
                while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                    i -= 1;
                }
                if i > 0 {
                    ret.drain(..i);
                }
                if ret.len() >= gap_limit {
                    ret.drain(gap_limit..);
                    return Ok(ret);
                }
                //It seems weird to repeat this, but it's correct because of the original call receive address and change address
                ret = Vec::from_iter(ordered_addresses.clone());
                i = ret.len();
                let mut n = i as u32;

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                    i -= 1;
                }
                if i > 0 {
                    ret.drain(..i);
                }
                if ret.len() >= gap_limit {
                    ret.drain(gap_limit..);
                    Ok(ret)
                } else {
                    while ret.len() < gap_limit { // generate new addresses up to gapLimit

                        let pub_key = self.public_key_data_at_index_path(IndexPath::index_path_with_index(n))?;
                        let addr = address::with_public_key_data(&pub_key, self.chain_type.clone());
                        if !self.account_is_transient() {
                            self.store_new_address_in_context(&addr, n, context);
                        }
                        self.all_addresses.insert(addr.clone());
                        ret.push((n, addr.clone()));
                        ordered_addresses.push((n, addr));
                        n += 1;
                    }
                    Ok(ret)
                }
            }
            (RegisterAddressesSettings::GapLimitIdentity(gap_limit, identity_index),
                DerivationPathKind::Authentication(model)) => {
                if !self.account_is_transient() {
                    if !self.controller.addresses_loaded {
                        return Err(DerivationError::AddressesMustBeLoaded);
                    }
                    assert_ne!(self.path_type, DerivationPathType::SINGLE_USER_AUTHENTICATION, "This should not be called for single user authentication. Use 'RegisterAddressesSettings::GapLimit(..)' instead.");
                    if model.use_hardened_keys && !self.has_extended_private_key() {
                        return Ok(vec![]);
                    }
                    if model.addresses_by_identity.get(&identity_index).is_none() {
                        model.addresses_by_identity.insert(identity_index, vec![]);
                    }
                    let mut ret = model.addresses_by_identity.get(&identity_index).cloned().unwrap();
                    let mut i = ret.len();

                    // keep only the trailing contiguous block of addresses with no transactions
                    while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                        i -= 1;
                    }
                    if i > 0 {
                        ret.drain(..i);
                    }
                    if ret.len() >= gap_limit {
                        ret.drain(gap_limit..);
                        return Ok(ret);
                    }

                    //It seems weird to repeat this, but it's correct because of the original call receive address and change address
                    ret = model.addresses_by_identity.get(&identity_index).cloned().unwrap();
                    i = ret.len();

                    let mut n = i as u32;

                    // keep only the trailing contiguous block of addresses with no transactions
                    while i > 0 && !self.address_is_used(&ret[i - 1].1) {
                        i -= 1;
                    }
                    if i > 0 {
                        ret.drain(..i);
                    }
                    if ret.len() >= gap_limit {
                        ret.drain(gap_limit..);
                        return Ok(ret);
                    }

                    while ret.len() < gap_limit {
                        // generate new addresses up to gapLimit
                        let hardened_indexes = vec![identity_index | BIP32_HARD, n | BIP32_HARD];
                        let soft_indexes = vec![identity_index, n];
                        let indexes = if model.use_hardened_keys { hardened_indexes } else { soft_indexes };
                        let pub_key = self.public_key_data_at_index_path(IndexPath::new(indexes)).map_err(DerivationError::from)?;
                        let addr = address::with_public_key_data(&pub_key, self.chain_type.clone());
                        if !self.account_is_transient() {
                            self.db_ref().store_in_default_context(DerivationStorageContext::IndexedAddressIdentity(n, addr.clone(), identity_index));
                        }
                        self.all_addresses.insert(addr.clone());
                        if let Some(addrs) = model.addresses_by_identity.get_mut(&identity_index) {
                            addrs.push((n, addr.clone()));
                        }
                        ret.push((n, addr));
                        n += 1;
                    }
                    Ok(ret)
                } else {
                    Ok(vec![])
                }
            },
            (settings, _) => Err(DerivationError::UnsupportedSettings(settings))
        }
    }
}

impl KeyDataAtIndexPath<u32> for DerivationPathModel {
    fn private_key_at_index_path(&self, index_path: IndexPath<u32>, source: SecretSource) -> Result<OpaqueKey, KeyError> {
        if self.path.is_empty() {
            Err(KeyError::UnableToDerive)
        } else {
            match source {
                SecretSource::Seed(seed) => {
                    let top_key = self.signing_algorithm.key_with_seed_data(seed)?;
                    let key = top_key.private_derive_to_path(self)?;
                    key.private_derive_to_path(&index_path)
                }
                SecretSource::ExtendedPrivateKeyData(data) => {
                    self.signing_algorithm.derive_key_from_extended_private_key_data_for_index_path_u32(data, index_path)
                }
            }
        }

    }

    fn public_key_at_index_path(&self, index_path: IndexPath<u32>) -> Result<OpaqueKey, KeyError> {
        let data = self.public_key_data_at_index_path(index_path)?;
        self.signing_algorithm.key_with_public_key_data(&data)
    }

    fn public_key_data_at_index_path(&self, index_path: IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
        match &self.kind {
            DerivationPathKind::Authentication(..) => {
                let mut has_hardened_derivation = false;
                for i in 0..index_path.length() {
                    let derivation = index_path.index_at_position(i);
                    has_hardened_derivation |= derivation & BIP32_HARD > 0;
                    if has_hardened_derivation {
                        break;
                    }
                }
                if has_hardened_derivation || self.reference == DerivationPathReference::ProviderPlatformNodeKeys {
                    if let Some(ext_prv_key_data) = self.extended_private_key_data() {
                        let prv_key = self.private_key_at_index_path(index_path, SecretSource::ExtendedPrivateKeyData(&ext_prv_key_data))?;
                        Ok(prv_key.public_key_data())
                    } else {
                        Err(KeyError::Any("Keychain doesn't have an extended private key".to_string()))
                    }
                } else {
                    self.extended_public_key()
                        .and_then(|key| key.public_key_data_at_index_path_u32(index_path))
                }
            }

            _ => {
                self.extended_public_key()
                    .and_then(|key| key.public_key_data_at_index_path_u32(index_path))
            }
        }
    }
}

// impl KeyDataAtIndexPath<u32> for SimpleIndexed {
//     fn private_key_at_index_path(&self, index_path: IndexPath<u32>, source: SecretSource) -> Result<OpaqueKey, KeyError> {
//         self.base.private_key_at_index_path(index_path, source)
//     }
//
//     fn public_key_at_index_path(&self, index_path: IndexPath<u32>) -> Result<OpaqueKey, KeyError> {
//         self.base.public_key_at_index_path(index_path)
//     }
//
//     fn public_key_data_at_index_path(&self, index_path: IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
//         self.base.public_key_data_at_index_path(index_path)
//     }
// }
//
// impl KeyDataAtIndexPath<u32> for Authentication {
//     fn private_key_at_index_path(&self, index_path: IndexPath<u32>, source: SecretSource) -> Result<OpaqueKey, KeyError> {
//         self.base.private_key_at_index_path(index_path, source)
//     }
//
//     fn public_key_at_index_path(&self, index_path: IndexPath<u32>) -> Result<OpaqueKey, KeyError> {
//         self.base.public_key_at_index_path(index_path)
//     }
//
//     fn public_key_data_at_index_path(&self, index_path: IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
//         self.base.public_key_data_at_index_path(index_path)
//     }
// }
//
// impl KeyDataAtIndexPath<u32> for Funds {
//     fn private_key_at_index_path(&self, index_path: IndexPath<u32>, source: SecretSource) -> Result<OpaqueKey, KeyError> {
//         self.base.private_key_at_index_path(index_path, source)
//     }
//
//     fn public_key_at_index_path(&self, index_path: IndexPath<u32>) -> Result<OpaqueKey, KeyError> {
//         self.base.public_key_at_index_path(index_path)
//     }
//
//     fn public_key_data_at_index_path(&self, index_path: IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
//         self.base.public_key_data_at_index_path(index_path)
//     }
// }
//
// impl KeyDataAtIndexPath<u32> for IncomingFunds {
//     fn private_key_at_index_path(&self, index_path: IndexPath<u32>, source: SecretSource) -> Result<OpaqueKey, KeyError> {
//         self.base.private_key_at_index_path(index_path, source)
//     }
//
//     fn public_key_at_index_path(&self, index_path: IndexPath<u32>) -> Result<OpaqueKey, KeyError> {
//         self.base.public_key_at_index_path(index_path)
//     }
//
//     fn public_key_data_at_index_path(&self, index_path: IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
//         self.base.public_key_data_at_index_path(index_path)
//     }
// }

// impl From<DerivationPath> for IndexPath<[u8; 32]> {
//     fn from(value: DerivationPath) -> Self {
//         value.de
//     }
// }

#[cfg(test)]
mod tests {
    use dashcore::hashes::hex::FromHex;
    // use dash_spv_keychain::KeychainController;
    // use crate::derivation::derivation_path::DerivationPathModel;

    #[test]
    pub fn test_address_registration() {
        let seed = Vec::from_hex("467c2dd58bbd29427fb3c5467eee339021a87b21309eeabfe9459d31eeb6eba9b2a1213c12a173118c84fd49e8b4bf9282272d67bf7b7b394b088eab53b438bc").unwrap();
        // KeychainController::new(|| )
        // DerivationPathModel::new()
    }
}
