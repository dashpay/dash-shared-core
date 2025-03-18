use std::ops::Index;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use dashcore::bip32::DerivationPath;
use dashcore::dip9::{DerivationPathReference, DerivationPathType};
use indexmap::{IndexMap, IndexSet};
use dash_spv_keychain::{KeyChainKey, KeyChainValue, KeychainController};
use crate::derivation::{IIndexPath, IndexPath, BIP32_HARD};
use crate::derivation::index_path::IndexHardSoft;
use crate::keys::{BLSKey, DeriveKey, ECDSAKey, ED25519Key, IKey, KeyError, OpaqueKey};
use crate::keys::key::KeyKind;
use crate::network::{ChainType, IHaveChainSettings};
use crate::util::address::address;
use crate::util::data_ops::short_hex_string_from;
use crate::util::from_hash160_for_script_map;


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
    pub internal: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct AccountInfo {
    pub account_number: u32,
    pub wallet_unique_id: String,
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
    InternalAddresses(IndexMap<u32, String>),
    ExternalAddresses(IndexMap<u32, String>)
}

#[derive(Clone)]
pub enum RegisterAddressesSettings {
    GapLimit(usize),
    GapLimitInternal(usize, bool),
    GapLimitIdentity(usize, u32),
}

pub trait RegisterAddressesWithSettings {
    fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<String>, DerivationError>;
    fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<String>, DerivationError>;
}

// pub trait PublicKeyDataAtIndex {
//     fn public_key_data_at_index(&self, index: u32) -> Vec<u8>;
//     fn public_key_data_at_index_path<T>(&self, index_path: IndexPath<T>) -> Vec<u8>;
// }

#[derive(Clone, Debug)]
pub enum DerivationPathKind {
    Funds(FundsDerivationModel),
    IncomingFunds(IncomingFundsDerivationModel),
    AssetLock(AssetLockDerivationModel),
    Authentication(AuthenticationDerivationModel),
    MasternodeHoldings(MasternodeHoldingsDerivationModel),

}
impl DerivationPathKind {
    pub fn is_simple_indexed(&self) -> bool {
        match self {
            DerivationPathKind::AssetLock(_) |
            DerivationPathKind::Authentication(_) |
            DerivationPathKind::MasternodeHoldings(_) => true,
            _ => false
        }
    }
}

#[derive(Clone, Debug)]
pub struct FundsDerivationModel {
    pub base: DerivationPathModel,
    pub all_change_addresses: IndexSet<String>,
    pub all_receive_addresses: IndexSet<String>,
    pub internal_addresses: IndexSet<String>,
    pub external_addresses: IndexSet<String>,

    pub is_for_first_account: bool,
    pub has_known_balance_internal: bool,
    pub checked_initial_has_known_balance: bool,

}

impl FundsDerivationModel {
    pub fn addresses(&self, internal: bool) -> Vec<String> {
        Vec::from_iter(if internal {
            self.internal_addresses.iter().cloned()
        } else {
            self.external_addresses.iter().cloned()
        })
    }
    /// returns the first unused external address
    pub fn receive_address(&mut self) -> Option<String> {
        //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        if let Ok(addr) = self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitInternal(1, false)) {
            addr.last().cloned()
        } else {
            self.all_receive_addresses.last().cloned()
        }
    }
    pub fn change_address(&mut self) -> Option<String> {
        //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        self.register_addresses_with_settings(RegisterAddressesSettings::GapLimitInternal(1, true))
            .ok()
            .and_then(|addresses| addresses.last().cloned())
    }

    pub fn contains_change_address(&self, address: &str) -> bool {
        self.all_change_addresses.contains(address)
    }
    pub fn contains_receive_address(&self, address: &str) -> bool {
        self.all_receive_addresses.contains(address)
    }

    pub fn used_receive_addresses(&self) -> Vec<String> {
        self.all_receive_addresses.intersection(&self.base.used_addresses)
            .cloned()
            .collect()
    }
    pub fn used_change_addresses(&self) -> Vec<String> {
        self.all_change_addresses.intersection(&self.base.used_addresses)
            .cloned()
            .collect()
    }

    pub fn should_use_reduced_gap_limit(&mut self) -> bool {
        if !self.checked_initial_has_known_balance {
            if let Some(AccountInfo { wallet_unique_id, .. }) = &self.base.account_info {
                if let Ok(KeyChainValue::Int64(has_known_balance)) = self.base.controller.keychain_controller.get(KeyChainKey::HasKnownBalanceUniqueIDString { reference: self.base.reference.into(), unique_id: wallet_unique_id.clone() }) {
                    self.has_known_balance_internal = has_known_balance == 1;
                    self.checked_initial_has_known_balance = true;
                }
            }
        }
        !self.has_known_balance_internal && !(self.is_for_first_account && self.base.reference == DerivationPathReference::BIP44)
    }

    pub fn addresses_for_export(&self, internal_start: usize, internal_len: usize, external_start: usize, external_len: usize) -> Vec<String> {
        let mut addresses = (internal_start..internal_start + internal_len).into_iter().filter_map(|index| self.address_at_index(index as u32, true).ok()).collect::<Vec<_>>();
        addresses.extend((external_start..external_start + external_len).into_iter().filter_map(|index| self.address_at_index(index as u32, false).ok()));
        addresses
    }

    /// gets an address at an index path
    pub fn address_at_index(&self, index: u32, internal: bool) -> Result<String, KeyError> {
        let pub_key = self.public_key_data_at_index(index, internal)?;
        if let Some(address ) = ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone()) {
            Ok(address)
        } else {
            Err(KeyError::Any("Can't generate address from public key data".to_string()))
        }
    }

    pub fn index_path_of_known_address(&self, address: &str) -> Option<IndexPath<u32>> {
        if let Some(index) = self.all_change_addresses.get_index_of(address) {
            Some(IndexPath::index_path_with_indexes(vec![1, index as u32]))
        } else if let Some(index) = self.all_receive_addresses.get_index_of(address) {
            Some(IndexPath::index_path_with_indexes(vec![0, index as u32]))
        } else {
            None
        }
    }


    pub fn public_key_data_at_index(&self, n: u32, internal: bool) -> Result<Vec<u8>, KeyError> {
        let path = IndexPath::new(vec![ if internal { 1 } else { 0 }, n]);
        self.base.public_key_data_at_index_path(path)
    }

}

#[derive(Clone, Debug)]
pub struct IncomingFundsDerivationModel {
    pub base: DerivationPathModel,
    pub external_addresses: IndexSet<String>,
    pub contact_source_identity_unique_id: [u8; 32],
    pub contact_destination_identity_unique_id: [u8; 32],
}

impl IncomingFundsDerivationModel {
    /// returns the first unused external address
    pub fn receive_address(&mut self) -> Option<String> {
        self.receive_address_in_context(self.base.controller.context)
    }

    pub fn receive_address_in_context(&mut self, context: *const std::os::raw::c_void) -> Option<String> {
        self.receive_address_at_offset_in_context(0, context)
    }

    pub fn receive_address_at_offset(&mut self, offset: usize) -> Option<String> {
        self.receive_address_at_offset_in_context(offset, self.base.controller.context)
    }
    pub fn receive_address_at_offset_in_context(&mut self, offset: usize, context: *const std::os::raw::c_void) -> Option<String> {
        //TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        if let Ok(addr) = self.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimit(offset + 1), context) {
            addr.last().cloned()
        } else {
            self.external_addresses.last().cloned()
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimpleIndexedDerivationModel {
    pub base: DerivationPathModel,
    pub ordered_addresses: IndexSet<String>,
}

impl SimpleIndexedDerivationModel {
    pub fn first_unused_index(&self) -> usize {
        let mut i = self.ordered_addresses.len();
        // keep only the trailing contiguous block of addresses that aren't used
        while i > 0 && !self.base.address_is_used(&self.ordered_addresses[i - 1]) {
            i -= 1;
        }
        i
    }


    pub fn addresses_to_index(&mut self, index: u32) -> Vec<String> {
        self.addresses_to_index_using_cache(index, false, false)
    }

    pub fn addresses_to_index_using_cache(&mut self, index: u32, use_cache: bool, add_to_cache: bool) -> Vec<String> {
        let mut addresses = vec![];
        for i in 0..index {
            let maybe_addr = self.ordered_addresses.get(&i);
            if use_cache && self.ordered_addresses.len() > i as usize && maybe_addr.is_some() {
                addresses.push(maybe_addr.unwrap().clone());
            } else {
                let pub_key = self.public_key_data_at_index(i);
                let addr = address::with_public_key_data(&pub_key, self.base.chain_type.clone());
                addresses.push(addr.clone());
                if add_to_cache && self.ordered_addresses.len() == i as usize {
                    self.ordered_addresses.insert(addr);
                }
            }

        }
        addresses
    }

    pub fn private_keys_for_range(&self, from: u32, len: u32, seed: Vec<u8>) -> Vec<OpaqueKey> {
        (from..from + len).into_iter().map(|index| self.private_key_at_index(index, seed.clone())).collect()
    }

    pub fn private_keys_to_index(&self, index: u32, seed: Vec<u8>) -> Vec<OpaqueKey> {
        self.private_keys_for_range(0, index, seed)
    }

    pub fn address_at_index(&self, index: u32) -> Result<String, KeyError> {
        let index_path = IndexPath::index_path_with_index(index);
        self.base.address_at_index_path(index_path)
    }
}

// impl PublicKeyDataAtIndex for DerivationPathModel {
//     fn public_key_data_at_index(&self, index: u32) -> Vec<u8> {
//         todo!()
//     }
//
//     fn public_key_data_at_index_path<T>(&self, index_path: IndexPath<T>) -> Vec<u8> {
//         todo!()
//     }
// }


/// Wallets are composed of chains of addresses. Each chain is traversed until a gap of a certain number of addresses is
/// found that haven't been used in any transactions. This method returns an array of <gapLimit> unused addresses
/// following the last used address in the chain. The internal chain is used for change addresses and the external chain
/// for receive addresses.
impl RegisterAddressesWithSettings for FundsDerivationModel {
    fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<String>, DerivationError> {
        self.register_addresses_with_settings_and_context(settings, self.base.controller.context)
    }

    fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<String>, DerivationError> {
        match settings {
            RegisterAddressesSettings::GapLimitInternal(gap_limit, internal) => {
                if !self.base.is_transient {
                    return Err(DerivationError::AddressesMustBeLoaded);
                }
                let mut a = self.addresses(internal);
                let mut i = a.len();

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.base.address_is_used(&a[i - 1]) {
                    i -= 1;
                }

                if i > 0 {
                    a = a[i..].to_vec();
                }
                if a.len() >= gap_limit {
                    return Ok(a[..gap_limit].to_vec());
                }

                if gap_limit > 1 { // get receiveAddress and changeAddress first to avoid blocking
                    let _ = self.receive_address();
                    let _ = self.change_address();
                }

                //It seems weird to repeat this, but it's correct because of the original call receive address and change address
                a = self.addresses(internal);
                i = a.len();

                let mut n = i as u32;

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.base.address_is_used(&a[i - 1]) {
                    i -= 1;
                }
                if i > 0 {
                    a = a[i..].to_vec();
                }
                if a.len() >= gap_limit {
                    return Ok(a[..gap_limit].to_vec());
                }
                let mut add_addresses = IndexMap::new();
                while a.len() < gap_limit { // generate new addresses up to gapLimit
                    let pub_key = self.public_key_data_at_index(n, internal).map_err(DerivationError::from)?;
                    if let Some(addr) = ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone()) {
                        self.base.all_addresses.insert(addr.clone());
                        if internal {
                            self.internal_addresses.insert(addr.clone());
                        } else {
                            self.external_addresses.insert(addr.clone());
                        }
                        a.push(addr.clone());
                        add_addresses.insert(n, addr);
                        n += 1;
                    } else {
                        print!("[{}] error generating keys", self.base.chain_type.name());
                        return Err(DerivationError::PublicKeyGeneration);
                    }
                }

                if !self.base.is_transient {
                    let storage_context = if internal { DerivationStorageContext::InternalAddresses(add_addresses) } else { DerivationStorageContext::ExternalAddresses(add_addresses) };
                    self.base.controller.store_in_context(context, storage_context);
                }
                Ok(a)
            }
            settings => Err(DerivationError::UnsupportedSettings(settings))
        }
    }
}

impl RegisterAddressesWithSettings for IncomingFundsDerivationModel {
    fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<String>, DerivationError> {
        self.register_addresses_with_settings_and_context(settings, self.base.controller.context)
    }

    fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<String>, DerivationError> {
        match settings {
            RegisterAddressesSettings::GapLimit(gap_limit) => {
                if !self.base.is_transient {
                    if !self.base.addresses_loaded {
                        sleep(Duration::from_millis(1000)); //quite hacky, we need to fix this
                    }
                    if !self.base.addresses_loaded {
                        return Err(DerivationError::AddressesMustBeLoaded);
                    }
                }
                let mut a= Vec::from(self.external_addresses.iter().cloned());
                let mut i = a.len();
                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.base.address_is_used(&a[i - 1]) {
                    i -= 1;
                }
                if i > 0 {
                    a = a[i..].to_vec();
                }
                if a.len() >= gap_limit {
                    return Ok(a[..gap_limit].to_vec());
                }
                if gap_limit > 1 {
                    // get receiveAddress and changeAddress first to avoid blocking
                    let _ = self.receive_address_in_context(context);
                }
                // It seems weird to repeat this, but it's correct because of the original call receive address and change address
                a = Vec::from_iter(self.external_addresses.clone());
                i = a.len();

                let mut n = i as u32;

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.base.address_is_used(&a[i - 1]) {
                    i -= 1;
                }

                if i > 0 {
                    a = a[i..].to_vec();
                }
                if a.len() >= gap_limit {
                    return Ok(a[..gap_limit].to_vec());
                }

                let mut upper_limit = gap_limit;
                while a.len() < upper_limit { // generate new addresses up to gapLimit
                    let pub_key = self.public_key_data_at_index(n);
                    if let Some(address) = ECDSAKey::address_from_public_key_data(&pub_key, self.base.chain_type.clone()) {
                        if !self.base.is_transient {
                            let is_used = self.base.store_new_address_in_context(address.clone(), n, context);
                            if is_used {
                                self.base.used_addresses.insert(address.clone());
                                upper_limit += 1;
                            }
                        }
                        self.base.all_addresses.insert(address.clone());
                        self.external_addresses.insert(address.clone());
                        a.push(address);
                        n += 1;

                    } else {
                        print!("[{}] error generating keys", self.base.chain_type.name());
                        return Err(DerivationError::PublicKeyGeneration);
                    }
                }
                Ok(a)
            },
            settings => Err(DerivationError::UnsupportedSettings(settings))
        }
    }
}

impl RegisterAddressesWithSettings for SimpleIndexedDerivationModel {
    fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<String>, DerivationError> {
        self.register_addresses_with_settings_and_context(settings, self.base.controller.context)
    }

    fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<String>, DerivationError> {
        match settings {
            RegisterAddressesSettings::GapLimit(gap_limit) => {
                let mut r_array = Vec::from_iter(self.ordered_addresses.clone());
                if !self.base.is_transient {
                    if !self.base.addresses_loaded {
                        return Err(DerivationError::AddressesMustBeLoaded);
                    }
                }
                let mut i = r_array.len();
                // keep only the trailing contiguous block of addresses that aren't used
                while i > 0 && !self.base.address_is_used(&r_array[i - 1]) {
                    i -= 1;
                }
                if i > 0 {
                    // TODO: check i.. or i+1..
                    // [rArray removeObjectsInRange:NSMakeRange(0, i)];
                    r_array = r_array[i..].to_vec();
                }
                if r_array.len() >= gap_limit {
                    return Ok(r_array[..gap_limit].to_vec());
                }
                //It seems weird to repeat this, but it's correct because of the original call receive address and change address
                r_array = Vec::from_iter(self.ordered_addresses.clone());
                i = r_array.len();
                let mut n = i as u32;

                // keep only the trailing contiguous block of addresses with no transactions
                while i > 0 && !self.base.address_is_used(&r_array[i - 1]) {
                    i -= 1;
                }
                if i > 0 {
                    // TODO: check i.. or i+1..
                    // [rArray removeObjectsInRange:NSMakeRange(0, i)];
                    r_array = r_array[i..].to_vec();
                }
                if r_array.len() >= gap_limit {
                    Ok(r_array[..gap_limit].to_vec())
                } else {
                    while r_array.len() < gap_limit { // generate new addresses up to gapLimit
                        let pub_key = self.base.public_key_data_at_index(n);
                        let addr = address::with_public_key_data(&pub_key, self.base.chain_type.clone());
                        if !self.base.is_transient {
                            self.base.store_new_address_in_context(&addr, n, context);
                        }
                        self.base.all_addresses.insert(addr.clone());
                        r_array.push(addr.clone());
                        self.ordered_addresses.insert(addr);
                        n += 1;
                    }
                    Ok(r_array)
                }
            },
            settings => Err(DerivationError::UnsupportedSettings(settings))
        }
    }
}

impl RegisterAddressesWithSettings for AuthenticationDerivationModel {
    fn register_addresses_with_settings(&mut self, settings: RegisterAddressesSettings) -> Result<Vec<String>, DerivationError> {
        self.register_addresses_with_settings_and_context(settings, self.base.base.controller.context)
    }

    fn register_addresses_with_settings_and_context(&mut self, settings: RegisterAddressesSettings, context: *const std::os::raw::c_void) -> Result<Vec<String>, DerivationError> {
        match settings {
            RegisterAddressesSettings::GapLimit(..) =>
                self.base.register_addresses_with_settings_and_context(settings, context),
            RegisterAddressesSettings::GapLimitIdentity(gap_limit, identity_index) => {
                if !self.base.base.is_transient {
                    if !self.base.base.addresses_loaded {
                        return Err(DerivationError::AddressesMustBeLoaded);
                    }
                    assert_ne!(self.base.base.path_type, DerivationPathType::SINGLE_USER_AUTHENTICATION, "This should not be called for single user authentication. Use '- (NSArray *)registerAddressesWithGapLimit:(NSUInteger)gapLimit error:(NSError**)error' instead.");
                    if self.use_hardened_keys && !self.has_extended_private_key() {
                        return Ok(vec![]);
                    }
                    if !self.addresses_by_identity.get(&identity_index) {
                        self.addresses_by_identity.insert(identity_index, vec![]);
                    }
                    let mut a = self.addresses_by_identity.get(&identity_index).cloned().unwrap();
                    let mut i = a.len();

                    // keep only the trailing contiguous block of addresses with no transactions
                    while i > 0 && !self.base.base.address_is_used(&a[i - 1]) {
                        i -= 1;
                    }
                    if i > 0 {
                        // TODO: check i.. or i+1..
                        // [rArray removeObjectsInRange:NSMakeRange(0, i)];
                        a = a[i..].to_vec();
                    }
                    if a.len() >= gap_limit {
                        return Ok(a[..gap_limit].to_vec());
                    }

                    //It seems weird to repeat this, but it's correct because of the original call receive address and change address
                    a = self.addresses_by_identity.get(&identity_index).cloned().unwrap();
                    i = a.len();

                    let mut n = i as u32;

                    // keep only the trailing contiguous block of addresses with no transactions
                    while i > 0 && !self.base.base.address_is_used(&a[i - 1]) {
                        i -= 1;
                    }
                    if i > 0 {
                        // TODO: check i.. or i+1..
                        // [rArray removeObjectsInRange:NSMakeRange(0, i)];
                        a = a[i..].to_vec();
                    }
                    if a.len() >= gap_limit {
                        return Ok(a[..gap_limit].to_vec());
                    }

                    while a.len() < gap_limit {
                        // generate new addresses up to gapLimit
                        let hardened_indexes = vec![identity_index | BIP32_HARD, n | BIP32_HARD];
                        let soft_indexes = vec![identity_index, n];
                        let indexes = if self.use_hardened_keys { hardened_indexes } else { soft_indexes };
                        let pub_key = self.base.base.public_key_data_at_index_path(IndexPath::new(indexes)).map_err(DerivationError::from)?;
                        let addr = address::with_public_key_data(&pub_key, self.base.base.chain_type.clone());
                        if let Ok(addr) = addr {
                            if !self.base.base.is_transient {
                                self.base.base.controller.store_in_default_context(DerivationStorageContext::IndexedAddressIdentity(n, addr, identity_index));
                            }
                            self.base.base.all_addresses.insert(addr.clone());
                            if let Some(addrs) = self.addresses_by_identity.get_mut(&identity_index) {
                                addrs.push(addr);
                            }
                            a.push(addr);
                            n += 1;

                        } else {
                            return Err(DerivationError::PublicKeyGeneration);
                        }

                    }
                    Ok(a)
                }

            },
            _ => Err(DerivationError::UnsupportedSettings(settings))
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssetLockDerivationModel {
    pub base: SimpleIndexedDerivationModel,

}

#[derive(Clone, Debug)]
pub struct AuthenticationDerivationModel {
    pub base: SimpleIndexedDerivationModel,
    pub use_hardened_keys: bool,
    pub should_store_extended_private_key: bool,
    pub addresses_by_identity: IndexMap<u32, Vec<String>>,
}

impl AuthenticationDerivationModel {
    pub fn has_extended_private_key(&self) -> bool {
        if let Ok(true) = self.base.base.controller.keychain_controller.has(KeyChainKey::WalletBasedExtendedPrivateKeyLocationString { unique_id: self.base.base.unique_id.clone() }) {
            true
        } else {
            false
        }
    }
    pub fn extended_private_key_data(&self) -> Option<Vec<u8>> {
        if let Ok(KeyChainValue::Bytes(data)) = self.base.base.controller.keychain_controller.get(KeyChainKey::WalletBasedExtendedPrivateKeyLocationString { unique_id: self.base.base.unique_id.clone() }) {
            Some(data)
        } else {
            None
        }
    }

    pub fn first_unused_public_key(&self) -> Option<Vec<u8>> {
        let first_unused_index = self.base.first_unused_index();
        self.base.base.public_key_data_at_index(first_unused_index as u32)
    }

    //
    // - (NSData *)firstUnusedPublicKey {
    // return [self publicKeyDataAtIndex:(uint32_t)[self firstUnusedIndex]];
    // }

    pub fn first_unused_private_key_from_seed(&self, seed: &[u8]) -> Result<OpaqueKey, KeyError> {
        let first_unused_index = self.base.first_unused_index();
        let index_path = IndexPath::index_path_with_index(first_unused_index as u32);
        self.base.base.private_key_at_index_path(index_path, seed)
    }

    pub fn private_key_at_index_path(&self, index_path: IndexPath<u32>) -> Result<OpaqueKey, KeyError> {
        if let Some(ext_prv_key_data) = self.extended_private_key_data() {
            match self.base.base.signing_algorithm {
                KeyKind::ECDSA => ECDSAKey::key_with_extended_private_key_data(&ext_prv_key_data)
                    .and_then(|key| key.private_derive_to_path(&index_path))
                    .map(OpaqueKey::ECDSA),
                KeyKind::ED25519 => ED25519Key::key_with_extended_private_key_data(&ext_prv_key_data)
                    .and_then(|key| key.private_derive_to_path(&index_path))
                    .map(OpaqueKey::ED25519),
                _ => BLSKey::key_with_extended_private_key_data(&ext_prv_key_data, self.base.base.signing_algorithm == KeyKind::BLS)
                    .and_then(|key| key.private_derive_to_path(&index_path))
                    .map(OpaqueKey::BLS)
            }
        } else {
            Err(KeyError::UnableToDerive)
        }
    }
}

#[derive(Clone, Debug)]
pub struct MasternodeHoldingsDerivationModel {
    pub base: SimpleIndexedDerivationModel,
}

impl FundsDerivationModel {
    pub fn contains_change_address(&self, address: &str) -> bool {
        self.all_change_addresses.contains(address)
    }
}



#[derive(Clone, Debug)]
pub struct DerivationPathController {
    pub context: *const std::os::raw::c_void,
    pub keychain_controller: Arc<KeychainController>,
    // pub db_controller: Arc<DB>
    // pub get_stored_context: Arc<dyn Fn(*const std::os::raw::c_void) -> Result<CoreBlockHeight, ContextProviderError> + Send + Sync>,
    // pub set_stored_context: Arc<dyn Fn(*const std::os::raw::c_void) -> Result<CoreBlockHeight, ContextProviderError> + Send + Sync>,

    pub store_in_context: Arc<dyn Fn(*const std::os::raw::c_void, DerivationStorageContext) -> bool + Send + Sync>,
    pub load_addresses_in_context: Arc<dyn Fn(*const std::os::raw::c_void, DerivationStorageContext) -> Vec<AddressInfo> + Send + Sync>,
    // - (void)storeNewAddressInContext:(NSString *)address
    // atIndex:(uint32_t)n
    // context:(NSManagedObjectContext *)context {
    //

    // pub context: Arc<FFIThreadSafeContext>
    // pub core_data_controller:
        // pub context_controller:
    // pub context: Arc<FFIThreadSafeContext>
}
impl DerivationPathController {
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

    pub fn load_addresses_in_context(&self, context: *const std::os::raw::c_void)
}

#[derive(Clone, Debug)]
pub struct DerivationPathModel {
    pub chain_type: ChainType,
    pub kind: DerivationPathKind,
    // TODO: rust-dashcore hides the details of DerivationPath
    pub path: DerivationPath,
    pub path_type: DerivationPathType,
    pub reference: DerivationPathReference,
    pub signing_algorithm: KeyKind,

    pub account_info: Option<AccountInfo>,
    // pub unique_id: String,

    pub is_transient: bool,
    pub controller: DerivationPathController,

    pub all_addresses: IndexSet<String>,
    pub used_addresses: IndexSet<String>,
    pub addresses_loaded: bool,
    /// master public key used to generate wallet addresses
    pub extended_pub_key: Option<OpaqueKey>,

}

impl DerivationPathModel {
    pub fn new<
        SC: Fn(*const std::os::raw::c_void, DerivationStorageContext) -> bool + Send + Sync + 'static,
    >(
        keychain_controller: Arc<KeychainController>,
        store_in_context: SC,
        is_transient: bool,
        context: *const std::os::raw::c_void,
        chain_type: ChainType
    ) -> Self {
        // let context_arc = Arc::new(FFIThreadSafeContext::new(controller_context));

        Self {
            chain_type,
            addresses_loaded: false,
            is_transient,
            all_addresses: IndexSet::new(),
            used_addresses: IndexSet::new(),
            controller: DerivationPathController {
                context,
                keychain_controller,

                store_in_context: Arc::new(store_in_context),
            }
        }
    }

    pub fn extended_public_key_keychain_key(&self) -> KeyChainKey {
        if self.wallet && (self.path.len() > 0 || self.reference == DerivationPathReference::Root) {
            KeyChainKey::WalletBasedExtendedPublicKeyLocationString { unique_id: self.unique_id.clone() }
        } else {
            KeyChainKey::StandaloneExtendedPublicKeyLocationString { extended_public_key_identifier: self.unique_id.clone() }
        }
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
            let _ = self.controller.keychain_controller.set(KeyChainKey::wallet_based_extended_public_key_location_string(wallet_unique_id.clone()), KeyChainValue::Bytes(pub_key_data), false);
            if store_private_key {
                let prv_key_data = key.extended_private_key_data()?;
                let _ = self.controller.keychain_controller.set(KeyChainKey::wallet_based_extended_private_key_location_string(wallet_unique_id.to_string()), KeyChainValue::Bytes(prv_key_data.to_vec()), true);
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
            let _ = self.controller.keychain_controller.set(KeyChainKey::wallet_based_extended_public_key_location_string(wallet_unique_id), KeyChainValue::Bytes(pub_key_data), false);
        }
        Ok(child_key)
    }


    pub fn private_key_at_index_path(&self, index_path: IndexPath<u32>, seed: &[u8]) -> Result<OpaqueKey, KeyError> {
        if self.path.is_empty() {
            Err(KeyError::UnableToDerive)
        } else {
            let top_key = self.signing_algorithm.key_with_seed_data(seed)?;
            match top_key {
                OpaqueKey::ECDSA(key) =>
                    key.private_derive_to_path(self)
                        .and_then(|key| key.private_derive_to_path(&index_path))
                        .map(OpaqueKey::ECDSA),
                OpaqueKey::BLS(key) => key.private_derive_to_path(self)
                    .and_then(|key| key.private_derive_to_path(&index_path))
                    .map(OpaqueKey::BLS),

                OpaqueKey::ED25519(key) => key.private_derive_to_path(self)
                    .and_then(|key| key.private_derive_to_path(&index_path))
                    .map(OpaqueKey::ED25519),

            }
        }
    }



    pub fn store_new_address(&self, address: &str, index: u32) -> bool {
        self.controller.store_new_address(address, index)
    }
    pub fn store_new_address_in_context(&self, address: &str, index: u32, context: *const std::os::raw::c_void) -> bool {
        self.controller.store_new_address_in_context(address, index, context)
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
        let pub_key = self.public_key_data_at_index_path(index_path)?;
        Ok(address::with_public_key_data_and_script_pub_key(&pub_key, self.chain_type.script_map().pubkey))
    }
    pub fn index_path_of_known_address(&self, address: &str) -> Option<IndexPath<u32>> {
        match &self.kind {
            DerivationPathKind::Funds(model) =>
                model.index_path_of_known_address(address),
            DerivationPathKind::IncomingFunds(model) =>
                model.external_addresses.get_index_of(address)
                    .map(|index| IndexPath::index_path_with_index(index as u32)),
            DerivationPathKind::AssetLock(AssetLockDerivationModel { base, .. }) |
            DerivationPathKind::Authentication(AuthenticationDerivationModel { base, .. }) |
            DerivationPathKind::MasternodeHoldings(MasternodeHoldingsDerivationModel { base, .. }) =>
                base.ordered_addresses.get_index_of(address)
                    .map(|index| IndexPath::index_path_with_index(index as u32)),
        }
    }
    pub fn public_key_data_at_index_path(&self, index_path: IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
        match &self.kind {
            DerivationPathKind::Authentication(model) => {
                let mut has_hardened_derivation = false;
                for i in 0..index_path.length() {
                    let derivation = index_path.index_at_position(i);
                    has_hardened_derivation |= derivation & BIP32_HARD > 0;
                    if has_hardened_derivation {
                        break;
                    }
                }
                if has_hardened_derivation || self.reference == DerivationPathReference::ProviderPlatformNodeKeys {
                    if model.has_extended_private_key() {
                        let prv_key = model.private_key_at_index_path(index_path)?;
                        let data = prv_key.public_key_data();
                        Ok(data)
                    } else {
                        Err(KeyError::UnableToDerive)
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

    /// inform the derivation path that the address has been used by a transaction, true if the derivation path contains the address
    pub fn register_transaction_address(&mut self, address: &str) -> bool {
        let contains = self.contains_address(address);
        if contains && !self.address_is_used(address) {
            self.used_addresses.insert(address.to_string());
            let _addresses = match &mut self.kind {
                DerivationPathKind::Funds(model) if model.contains_change_address(address) =>
                    model.register_addresses_with_settings(RegisterAddressesSettings::GapLimitInternal(SEQUENCE_GAP_LIMIT_INTERNAL, true)),
                DerivationPathKind::Funds(model) =>
                    model.register_addresses_with_settings(RegisterAddressesSettings::GapLimitInternal(SEQUENCE_GAP_LIMIT_EXTERNAL, false)),
                DerivationPathKind::IncomingFunds(model) =>
                    model.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_EXTERNAL)),
                DerivationPathKind::AssetLock(model) =>
                    model.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_INTERNAL)),
                DerivationPathKind::Authentication(model) =>
                    model.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_EXTERNAL)),
                DerivationPathKind::MasternodeHoldings(model) =>
                    model.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(SEQUENCE_GAP_LIMIT_INTERNAL)),
            };
        }
        contains
    }
    pub fn load_addresses_in_context(&mut self, context: *const std::os::raw::c_void) -> Vec<AddressInfo> {
        self.controller.load_addresses_in_context
    }
    pub fn load_addresses(&mut self) {
        match &mut self.kind {
            DerivationPathKind::Funds(model) => {
                if !self.addresses_loaded {
                    let addresses = self.load_addresses_in_context(self.controller.context);

                    self.addresses_loaded = true;
                    let reduced_gap_limit = model.should_use_reduced_gap_limit();
                    let gap_limit = if reduced_gap_limit { SEQUENCE_UNUSED_GAP_LIMIT_INITIAL } else { SEQUENCE_GAP_LIMIT_INITIAL };
                    let _ = model.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimitInternal(gap_limit, true), self.controller.context);
                    let _ = model.register_addresses_with_settings_and_context(RegisterAddressesSettings::GapLimitInternal(gap_limit, false), self.controller.context);
                }
            },
            DerivationPathKind::IncomingFunds(..) => {
                self.load_addresses_in_context(self.controller.context);
            },
            DerivationPathKind::Authentication(model) => {
                if !self.addresses_loaded {
                    self.load_addresses_in_context(self.controller.context);
                    self.addresses_loaded = true;
                    if self.path_type = DerivationPathType::SINGLE_USER_AUTHENTICATION {
                        let _ = model.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(10));
                    } else {
                        let _ = model.register_addresses_with_settings(RegisterAddressesSettings::GapLimitIdentity(10, 0));
                    }

                }

            },
            DerivationPathKind::AssetLock(AssetLockDerivationModel { base, .. }) |
            DerivationPathKind::MasternodeHoldings(MasternodeHoldingsDerivationModel { base, .. }) => {
                if !self.addresses_loaded {
                    self.load_addresses_in_context(self.controller.context);
                    self.addresses_loaded = true;
                    let _ = base.register_addresses_with_settings(RegisterAddressesSettings::GapLimit(10));
                }
            },
        }
    }

    pub fn create_identifier_for_derivation_path(&self) -> Result<String, KeyError> {
        self.extended_public_key()
            .and_then(|ext_pub_key| ext_pub_key.create_identifier())
            .map(|id| short_hex_string_from(&id))
    }



}

// IIndexPath<Item: Clone + Debug + Encodable + IndexHardSoft + PartialEq + Extremum>

impl IIndexPath for DerivationPathModel {
    type Item = ();

    fn new(indexes: Vec<Self::Item>) -> Self {
        todo!()
    }

    fn new_hardened(indexes: Vec<Self::Item>, hardened: Vec<bool>) -> Self {
        todo!()
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        todo!()
    }

    fn hardened_indexes(&self) -> &Vec<bool> {
        todo!()
    }
}

impl IndexHardSoft for DerivationPathModel {
    fn harden(&self) -> Self {
        todo!()
    }

    fn soften(&self) -> Self {
        todo!()
    }

    fn hardened(&self) -> u64 {
        todo!()
    }

    fn softened(&self) -> u64 {
        todo!()
    }
}