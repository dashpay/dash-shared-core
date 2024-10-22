use std::fmt::{Debug, Display};
use crate::chain::{params::ScriptMap, derivation::{IIndexPath, IndexPath}};
use crate::chain::common::ChainType;
use crate::chain::derivation::index_path::{Extremum, IndexHardSoft};
use crate::consensus::Encodable;
use crate::crypto::byte_util::{UInt256, UInt384, UInt768};
use crate::keys::{BLSKey, DeriveKey, ECDSAKey, ED25519Key, IKey, KeyError};
use crate::util::address::address;
use crate::util::sec_vec::SecVec;

#[derive(Clone, Debug, PartialEq)]
#[ferment_macro::export]
pub enum KeyKind {
    ECDSA = 0,
    BLS = 1,
    BLSBasic = 2,
    ED25519 = 3,
}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum OpaqueKey {
    ECDSA(ECDSAKey),
    BLS(BLSKey),
    ED25519(ED25519Key),
}

impl From<ECDSAKey> for OpaqueKey {
    fn from(value: ECDSAKey) -> Self {
        OpaqueKey::ECDSA(value)
    }
}

impl From<BLSKey> for OpaqueKey {
    fn from(value: BLSKey) -> Self {
        OpaqueKey::BLS(value)
    }
}

impl From<ED25519Key> for OpaqueKey {
    fn from(value: ED25519Key) -> Self {
        OpaqueKey::ED25519(value)
    }
}

impl From<OpaqueKey> for ECDSAKey {
    fn from(value: OpaqueKey) -> Self {
        match value {
            OpaqueKey::ECDSA(key) => key,
            _ => panic!("trying to unwrap bls from different key type")
        }
    }
}
impl From<OpaqueKey> for BLSKey {
    fn from(value: OpaqueKey) -> Self {
        match value {
            OpaqueKey::BLS(key) => key,
            _ => panic!("trying to unwrap ecdsa from different key type")
        }
    }
}
impl From<OpaqueKey> for ED25519Key {
    fn from(value: OpaqueKey) -> Self {
        match value {
            OpaqueKey::ED25519(key) => key,
            _ => panic!("trying to unwrap ed25519 from different key type")
        }
    }
}

impl Default for KeyKind {
    fn default() -> Self {
        KeyKind::ECDSA
    }
}

impl From<i16> for KeyKind {
    fn from(orig: i16) -> Self {
        match orig {
            0 => KeyKind::ECDSA,
            1 => KeyKind::BLS,
            2 => KeyKind::BLSBasic,
            3 => KeyKind::ED25519,
            _ => KeyKind::default(),
        }
    }
}

impl From<KeyKind> for i16 {
    fn from(value: KeyKind) -> Self {
        value as i16
    }
}

impl From<&KeyKind> for u8 {
    fn from(value: &KeyKind) -> Self {
        value.clone() as u8
    }
}



impl KeyKind {
    pub fn public_key_from_extended_public_key_data(&self, data: &[u8], index_path: &IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::public_key_from_extended_public_key_data(data, index_path),
            KeyKind::ED25519 => ED25519Key::public_key_from_extended_public_key_data(data, index_path),
            _ => BLSKey::public_key_from_extended_public_key_data(data, index_path, *self == KeyKind::BLS),
        }
    }

    pub fn derive_key_from_seed(&self, seed: &[u8], derivation_path: &IndexPath<UInt256>) -> Result<OpaqueKey, KeyError> {
        self.key_with_seed_data(seed)
            .and_then(|top_key| top_key.private_derive_to_path(derivation_path))
    }
    pub fn private_keys_at_index_paths(
        &self,
        seed: &[u8],
        index_paths: Vec<IndexPath<u32>>,
        derivation_path: &IndexPath<UInt256>
    ) -> Result<Vec<OpaqueKey>, KeyError> {
        self.derive_key_from_seed(seed, derivation_path)
            .map(|derivation_path_extended_key|
                index_paths.iter()
                    .map(|index_path| derivation_path_extended_key.private_derive_to_path(index_path))
                    .flatten()
                    .collect())
    }

    pub fn serialized_private_keys_at_index_paths(
        &self,
        seed: &[u8],
        index_paths: Vec<IndexPath<u32>>,
        derivation_path: &IndexPath<UInt256>,
        chain_type: ChainType,
    ) -> Result<Vec<String>, KeyError> {
        self.derive_key_from_seed(seed, derivation_path)
            .map(|derivation_path_extended_key| {
                let script = chain_type.script_map();
                index_paths.iter()
                    .map(|index_path| derivation_path_extended_key.private_derive_to_path(index_path)
                        .map(|private_key| private_key.serialized_private_key_for_script(&script)))
                    .flatten()
                    .collect()
            })
    }
}

/// TMP solution since ferment fails with expanding such a generic type
#[ferment_macro::export]
#[derive(Clone, Debug)]
pub struct IndexPathU32 {
    pub indexes: Vec<u32>,
    pub hardened: Vec<bool>,
}
#[ferment_macro::export]
#[derive(Clone, Debug)]
pub struct IndexPathU256 {
    pub indexes: Vec<UInt256>,
    pub hardened: Vec<bool>,
}

impl From<IndexPathU256> for IndexPath<UInt256> {
    fn from(value: IndexPathU256) -> Self {
        let IndexPathU256 { indexes, hardened } = value;
        IndexPath::new_hardened(indexes, hardened)
    }
}
impl From<&IndexPathU256> for IndexPath<UInt256> {
    fn from(value: &IndexPathU256) -> Self {
        IndexPath::from(value.clone())
    }
}
impl From<IndexPathU32> for IndexPath<u32> {
    fn from(value: IndexPathU32) -> Self {
        let IndexPathU32 { indexes, hardened } = value;
        IndexPath::new_hardened(indexes, hardened)
    }
}
impl From<&IndexPathU32> for IndexPath<u32> {
    fn from(value: &IndexPathU32) -> Self {
        IndexPath::from(value.clone())
    }
}

#[ferment_macro::export]
impl KeyKind {
    pub fn public_key_from_extended_public_key_data_at_index_path(&self, data: &[u8], index_path: &IndexPathU32) -> Result<Vec<u8>, KeyError> {
        let index_path = IndexPath::from(index_path);
        self.public_key_from_extended_public_key_data(data, &index_path)
    }
    pub fn derive_key_from_seed_wrapped(&self, seed: &[u8], derivation_path: IndexPathU256) -> Result<OpaqueKey, KeyError> {
        self.key_with_seed_data(seed)
            .and_then(|top_key| top_key.private_derive_to_path(&IndexPath::from(derivation_path)))
    }

    pub fn private_keys_at_index_paths_wrapped(
        &self,
        seed: &[u8],
        index_paths: Vec<IndexPathU32>,
        derivation_path: IndexPathU256
    ) -> Result<Vec<OpaqueKey>, KeyError> {
        self.derive_key_from_seed_wrapped(seed, derivation_path)
            .map(|derivation_path_extended_key|
                index_paths.into_iter()
                    .map(|index_path| derivation_path_extended_key.private_derive_to_path(&IndexPath::from(index_path)))
                    .flatten()
                    .collect())
    }
    pub fn serialized_private_keys_at_index_paths_wrapper(
        &self,
        seed: &[u8],
        index_paths: Vec<IndexPathU32>,
        derivation_path: IndexPathU256,
        chain_type: ChainType,
    ) -> Result<Vec<String>, KeyError> {
        self.derive_key_from_seed_wrapped(seed, derivation_path)
            .map(|derivation_path_extended_key| {
                let script = chain_type.script_map();
                index_paths.into_iter()
                    .map(|index_path| derivation_path_extended_key.private_derive_to_path(&IndexPath::from(index_path))
                        .map(|private_key| private_key.serialized_private_key_for_script(&script)))
                    .flatten()
                    .collect()
            })
    }


    pub fn derivation_string(&self) -> String {
        match self {
            KeyKind::ECDSA => "",
            KeyKind::ED25519 => "_ED_",
            KeyKind::BLS | KeyKind::BLSBasic  => "_BLS_",
        }.to_string()
    }
    pub fn private_key_from_extended_private_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::init_with_extended_private_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::init_with_extended_private_key_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::init_with_extended_private_key_data(data, *self == KeyKind::BLS).map(OpaqueKey::BLS).map_err(KeyError::from),
        }
    }

    pub fn key_with_private_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_secret_data(data, true).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::key_with_secret_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::key_with_private_key_data(data, *self == KeyKind::BLS).map(OpaqueKey::BLS),
        }
    }

    pub fn key_with_seed_data(&self, seed: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::init_with_seed_data(seed).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::init_with_seed_data(seed).map(OpaqueKey::ED25519),
            _ => BLSKey::extended_private_key_with_seed_data(seed, *self == KeyKind::BLS).map(OpaqueKey::BLS)
        }
    }

    pub fn key_with_public_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_public_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::key_with_public_key_data(data).map(OpaqueKey::ED25519),
            _ => Ok(OpaqueKey::BLS(BLSKey::key_with_public_key(UInt384::from(data), *self == KeyKind::BLS))),
        }
    }

    pub fn key_with_extended_public_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::init_with_extended_public_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::init_with_extended_public_key_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::init_with_extended_public_key_data(data, *self == KeyKind::BLS).map(OpaqueKey::BLS).map_err(KeyError::from)
        }
    }

    pub fn key_with_extended_private_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::init_with_extended_private_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::init_with_extended_private_key_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::init_with_extended_private_key_data(data, *self == KeyKind::BLS).map(OpaqueKey::BLS).map_err(KeyError::from)
        }
    }

    /*pub fn private_derive_to_256bit_derivation_path_from_seed_and_store<IPATH, DPATH>(&self, seed: &Seed, derivation_path: &DPATH, store_private_key: bool) -> Option<Key>
        where IPATH: IIndexPath, DPATH: IDerivationPath + IIndexPath<Item = UInt256>  {
        if let Some(seed_key) = self.key_with_seed_data(&seed.data) {
            println!("private_derive_to_256bit_derivation_path_from_seed_and_store: seed_key: {:?}", seed_key.clone());
            let derived = seed_key.private_derive_to_256bit_derivation_path(derivation_path);
            if let Some(mut ext_pk) = derived {
                let ext_pub_data = ext_pk.extended_private_key_data();
                let ext_prv_data = ext_pk.extended_public_key_data();
                println!("private_derive_to_256bit_derivation_path_from_seed_and_store: ext_prv_data: {:?} ext_pub_data: {:?}", ext_prv_data.clone(), ext_pub_data.clone());
                if !seed.unique_id.is_empty() {
                    Keychain::set_data(derivation_path.wallet_based_extended_public_key_location_string_for_wallet_unique_id(seed.unique_id_as_str()), ext_pub_data, false)
                        .expect("");
                    if store_private_key {
                        Keychain::set_data(wallet_based_extended_private_key_location_string_for_unique_id(seed.unique_id_as_str()), ext_prv_data, true)
                            .expect("");
                    }
                }
                ext_pk.forget_private_key();
                Some(ext_pk)
            } else {
                None
            }
        } else {
            None
        }
    }*/
}

impl<U> DeriveKey<IndexPath<U>> for OpaqueKey
where U: Copy + Clone + Display + Debug + Encodable + IndexHardSoft + PartialEq + Extremum,
      ECDSAKey: DeriveKey<IndexPath<U>>,
      BLSKey: DeriveKey<IndexPath<U>>,
      ED25519Key: DeriveKey<IndexPath<U>> {
    fn private_derive_to_path(&self, path: &IndexPath<U>) -> Result<Self, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) => key.private_derive_to_path(path).map(Into::into),
            OpaqueKey::BLS(key) => key.private_derive_to_path(path).map(Into::into),
            OpaqueKey::ED25519(key) => key.private_derive_to_path(path).map(Into::into),
        }
    }
    fn public_derive_to_path_with_offset(&mut self, path: &IndexPath<U>, offset: usize) -> Result<Self, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) => key.public_derive_to_path_with_offset(path, offset).map(Into::into),
            OpaqueKey::BLS(key) => key.public_derive_to_path_with_offset(path, offset).map(Into::into),
            OpaqueKey::ED25519(key) => key.public_derive_to_path_with_offset(path, offset).map(Into::into),
        }
    }
}

#[ferment_macro::export]
impl IKey for OpaqueKey {

    fn kind(&self) -> KeyKind {
        match self {
            OpaqueKey::ECDSA(..) => KeyKind::ECDSA,
            OpaqueKey::ED25519(..) => KeyKind::ED25519,
            OpaqueKey::BLS(BLSKey { use_legacy: true, .. }) => KeyKind::BLS,
            OpaqueKey::BLS(BLSKey { use_legacy: false, .. }) => KeyKind::BLSBasic
        }
    }

    fn secret_key_string(&self) -> String {
        match self {
            OpaqueKey::ECDSA(key) => key.secret_key_string(),
            OpaqueKey::BLS(key) => key.secret_key_string(),
            OpaqueKey::ED25519(key) => key.secret_key_string(),
        }
    }

    fn has_private_key(&self) -> bool {
        match self {
            OpaqueKey::ECDSA(key) => key.has_private_key(),
            OpaqueKey::BLS(key) => key.has_private_key(),
            OpaqueKey::ED25519(key) => key.has_private_key(),
        }
    }
    fn address_with_public_key_data(&self, script_map: &ScriptMap) -> String {
        address::with_public_key_data(&self.public_key_data(), script_map)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            OpaqueKey::ECDSA(key) => key.compact_sign(UInt256::from(data)).to_vec(),
            OpaqueKey::BLS(key) => key.sign(data),
            OpaqueKey::ED25519(key) => key.sign(data)
        }
    }

    fn verify(&mut self, message_digest: &[u8], signature: &[u8]) -> bool {
        match self {
            OpaqueKey::ECDSA(key) => key.verify(message_digest, signature),
            OpaqueKey::BLS(key) => key.verify_uint768(UInt256::from(message_digest), UInt768::from(signature)),
            OpaqueKey::ED25519(key) => key.verify(message_digest, signature),
        }
    }

    fn secret_key(&self) -> UInt256 {
        match self {
            OpaqueKey::ECDSA(key) => key.seckey,
            OpaqueKey::BLS(key) => key.secret_key(),
            OpaqueKey::ED25519(key) => key.secret_key(),
        }
    }

    fn chaincode(&self) -> UInt256 {
        match self {
            OpaqueKey::ECDSA(key) => key.chaincode(),
            OpaqueKey::BLS(key) => key.chaincode(),
            OpaqueKey::ED25519(key) => key.chaincode(),
        }
    }

    fn fingerprint(&self) -> u32 {
        match self {
            OpaqueKey::ECDSA(key) => key.fingerprint(),
            OpaqueKey::BLS(key) => key.fingerprint(),
            OpaqueKey::ED25519(key) => key.fingerprint(),
        }
    }

    fn private_key_data(&self) -> Result<Vec<u8>, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) => key.private_key_data(),
            OpaqueKey::BLS(key) => key.private_key_data(),
            OpaqueKey::ED25519(key) => key.private_key_data(),
        }
    }

    fn public_key_data(&self) -> Vec<u8> {
        match self {
            OpaqueKey::ECDSA(key) => key.public_key_data(),
            OpaqueKey::BLS(key) => key.public_key_data(),
            OpaqueKey::ED25519(key) => key.public_key_data(),
        }
    }

    fn extended_private_key_data(&self) -> Result<SecVec, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) => key.extended_private_key_data(),
            OpaqueKey::BLS(key) => key.extended_private_key_data(),
            OpaqueKey::ED25519(key) => key.extended_private_key_data(),
        }
    }

    fn extended_public_key_data(&self) -> Result<Vec<u8>, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) => key.extended_public_key_data(),
            OpaqueKey::BLS(key) => key.extended_public_key_data(),
            OpaqueKey::ED25519(key) => key.extended_public_key_data(),
        }
    }

    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String {
        match self {
            OpaqueKey::ECDSA(key) => key.serialized_private_key_for_script(script),
            OpaqueKey::BLS(key) => key.serialized_private_key_for_script(script),
            OpaqueKey::ED25519(key) => key.serialized_private_key_for_script(script),
        }
    }

    fn hmac_256_data(&self, data: &[u8]) -> UInt256 {
        match self {
            OpaqueKey::ECDSA(key) => key.hmac_256_data(data),
            OpaqueKey::BLS(key) => key.hmac_256_data(data),
            OpaqueKey::ED25519(key) => key.hmac_256_data(data),
        }
    }

    fn forget_private_key(&mut self) {
        match self {
            OpaqueKey::ECDSA(key) => key.forget_private_key(),
            OpaqueKey::BLS(key) => key.forget_private_key(),
            OpaqueKey::ED25519(key) => key.forget_private_key(),
        }

    }

    fn sign_message_digest(&self, digest: UInt256) -> Vec<u8> {
        match self {
            OpaqueKey::ECDSA(key) => key.sign_message_digest(digest),
            OpaqueKey::BLS(key) => key.sign_message_digest(digest),
            OpaqueKey::ED25519(key) => key.sign_message_digest(digest),
        }
    }
    fn private_key_data_equal_to(&self, other_private_key_data: &[u8; 32]) -> bool {
        match self {
            OpaqueKey::ECDSA(key) =>
                key.private_key_data_equal_to(other_private_key_data),
            OpaqueKey::BLS(key) =>
                key.private_key_data_equal_to(other_private_key_data),
            OpaqueKey::ED25519(key) =>
                key.private_key_data_equal_to(other_private_key_data),
        }
    }

    fn public_key_data_equal_to(&self, other: &Vec<u8>) -> bool {
        self.public_key_data().eq(other)
    }

}
