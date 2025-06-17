use std::fmt::Debug;
use dashcore::{Network, PrivateKey};
use dashcore::hashes::{sha256, sha256d, Hash};
use crate::derivation::{IIndexPath, IndexPath, index_path::{Extremum, IndexHardSoft}};
use dashcore::consensus::Encodable;
use crate::crypto::byte_util::{clone_into_array, Reversed};
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::keys::{BLSKey, DeriveKey, ECDSAKey, ED25519Key, IKey, KeyError};
use crate::keys::bls_key::g1_element_serialized;
use crate::keys::crypto_data::CryptoData;
use crate::network::ChainType;
use crate::util::address::address;
use crate::util::data_append::DataAppend;
use crate::util::script::ScriptElement;
use crate::util::sec_vec::SecVec;

#[derive(Copy, Clone, Debug, PartialEq)]
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

impl OpaqueKey {
    pub fn convert_opaque_key_to_ecdsa_private_key(&self, chain_type: &ChainType) -> Result<PrivateKey, KeyError> {
        match (chain_type, self) {
            (ChainType::MainNet, OpaqueKey::ECDSA(key)) =>
                key.private_key_data().and_then(|data| PrivateKey::from_slice(&data, Network::Dash).map_err(|err| KeyError::Any(format!("Can't convert dash_shared_core key ({self:?}) to platform key: {err}")))),
            (ChainType::TestNet, OpaqueKey::ECDSA(key)) =>
                key.private_key_data().and_then(|data| PrivateKey::from_slice(&data, Network::Testnet).map_err(|err| KeyError::Any(format!("Can't convert dash_shared_core key ({self:?}) to platform key: {err}")))),
            _ => Err(KeyError::Any(format!("Can't convert dash_shared_core key ({self:?}) to platform key"))),
        }
    }
    pub fn public_key_data_at_index_path_u32(&self, index_path: IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) =>
                key.extended_public_key_data()
                    .and_then(|data| ECDSAKey::public_key_from_extended_public_key_data(&data, &index_path)),
            OpaqueKey::BLS(key) =>
                key.extended_public_key_data()
                    .and_then(|data| BLSKey::public_key_from_extended_public_key_data(&data, &index_path, key.use_legacy)),

            OpaqueKey::ED25519(key) =>
                key.extended_public_key_data()
                    .and_then(|data| ED25519Key::public_key_data_from_extended_public_key_data(&data, &index_path)),
        }
    }

}
#[ferment_macro::export]
impl OpaqueKey {

    pub fn has_kind(&self, kind: KeyKind) -> bool {
        self.kind().eq(&kind)
    }
    pub fn hash160(&self) -> [u8; 20] {
        match self {
            OpaqueKey::ECDSA(key) => key.hash160(),
            OpaqueKey::BLS(key) => key.hash160(),
            OpaqueKey::ED25519(key) => key.hash160(),
        }
    }
    pub fn check_payload_signature(&self, key_hash: [u8; 20]) -> bool {
        self.hash160().eq(&key_hash)
    }
    pub fn create_tx_signature(&self, data: &[u8], flags: u8, tx_input_script: Vec<u8>) -> Vec<u8> {
        let mut sig = Vec::new();
        let hash = sha256d::Hash::hash(data.as_ref()).to_byte_array();
        let signed_data = match self {
            OpaqueKey::ECDSA(key) => key.sign(&hash),
            OpaqueKey::BLS(key) => key.sign(&hash),
            OpaqueKey::ED25519(key) => key.sign(&hash),
        };
        let mut s = Vec::new();
        s.extend(signed_data);
        s.push(flags);
        s.append_script_push_data(&mut sig);
        match tx_input_script.script_elements()[..] {
            // pay-to-pubkey-hash scriptSig
            [.., ScriptElement::Number(0x88/*OP_EQUALVERIFY*/), _elem] => {
                self.public_key_data().append_script_push_data(&mut sig);
            },
            _ => {}
        }
        sig
    }

    pub fn create_account_reference(&self, extended_public_key: OpaqueKey, account_number: usize) -> u32 {
        let extended_public_key_data = extended_public_key
            .extended_public_key_data()
            .unwrap_or_default();
        let account_secret_key = self.hmac_256_data(&extended_public_key_data).reversed();
        let account_secret_key28 = u32::from_le_bytes(clone_into_array(&account_secret_key[..4])) >> 4;
        let shortened_account_bits = (account_number as u32) & 0x0FFFFFFF;
        let version = 0; // currently set to 0
        let version_bits = version << 28;
        // this is the account ref
        version_bits | (account_secret_key28 ^ shortened_account_bits)
    }

    pub fn create_identifier(&self) -> Result<[u8; 32], KeyError> {
        self.extended_public_key_data()
            .map(|ext_pubkey_data| sha256::Hash::hash(&ext_pubkey_data).to_byte_array())
    }

    pub fn public_derive_to_256_path_with_offset(&mut self, path: &IndexPathU256, offset: usize) -> Result<Self, KeyError> {
        self.public_derive_to_path_with_offset(&IndexPath::from(path), offset)
    }

    pub fn public_key_from_extended_public_key_data_at_index_path(&self, index_path: Vec<u32>) -> Result<Self, KeyError> {
        let index_path = IndexPath::from(index_path);
        match self {
            OpaqueKey::ECDSA(key) =>
                key.public_key_from_extended_public_key_data_at_index_path(&index_path)
                    .map(OpaqueKey::ECDSA),
            OpaqueKey::BLS(key) =>
                key.public_key_from_extended_public_key_data_at_index_path(&index_path)
                    .map(OpaqueKey::BLS),
            OpaqueKey::ED25519(key) =>
                key.public_key_from_extended_public_key_data_at_index_path(&index_path)
                    .map(OpaqueKey::ED25519)
        }
    }
    pub fn public_key_data_at_index_path(&self, index_path: Vec<u32>) -> Result<Vec<u8>, KeyError> {
        let index_path = IndexPath::from(index_path);
        match self {
            OpaqueKey::ECDSA(key) =>
                key.extended_public_key_data()
                    .and_then(|data| ECDSAKey::public_key_from_extended_public_key_data(&data, &index_path)),
            OpaqueKey::BLS(key) =>
                key.extended_public_key_data()
                    .and_then(|data| BLSKey::public_key_from_extended_public_key_data(&data, &index_path, key.use_legacy)),

            OpaqueKey::ED25519(key) =>
                key.extended_public_key_data()
                    .and_then(|data| ED25519Key::public_key_data_from_extended_public_key_data(&data, &index_path)),
        }
    }



    // Encryption
    pub fn encrypt_data(&self, public_key: OpaqueKey, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        match (self, public_key) {
            (OpaqueKey::ECDSA(key), OpaqueKey::ECDSA(public_key)) => {
                let pubkey = dashcore::secp256k1::PublicKey::from_slice(&public_key.public_key_data()).map_err(KeyError::from)?;
                let seckey = dashcore::secp256k1::SecretKey::from_byte_array(&key.seckey).map_err(KeyError::from)?;
                let shared_secret = dashcore::secp256k1::ecdh::SharedSecret::new(&pubkey, &seckey);
                let new_key = ECDSAKey::with_shared_secret(shared_secret, false);
                CryptoData::encrypt_with_dh_key(&data.to_vec(), &new_key)
            }
            (OpaqueKey::BLS(key), OpaqueKey::BLS(public_key)) if key.use_legacy == public_key.use_legacy => {
                let pubkey = public_key.bls_public_key().map_err(KeyError::from)?;
                let seckey = key.bls_private_key().map_err(KeyError::from)?;
                let product = (pubkey * seckey).map_err(KeyError::from)?;
                let new_key = BLSKey::key_with_public_key(g1_element_serialized(&product, key.use_legacy), key.use_legacy);
                CryptoData::encrypt_with_dh_key(&data.to_vec(), &new_key)
            }
            _ => Err(KeyError::DHKeyExchange)
        }
    }
    pub fn encrypt_data_vec(&self, public_key: OpaqueKey, data: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        self.encrypt_data(public_key, &data)
    }
    pub fn encrypt_data_using_iv(&self, public_key: OpaqueKey, data: &[u8], iv: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        match (self, public_key) {
            (OpaqueKey::ECDSA(key), OpaqueKey::ECDSA(public_key)) => {
                let pubkey = dashcore::secp256k1::PublicKey::from_slice(&public_key.public_key_data()).map_err(KeyError::from)?;
                let seckey = dashcore::secp256k1::SecretKey::from_byte_array(&key.seckey).map_err(KeyError::from)?;
                let shared_secret = dashcore::secp256k1::ecdh::SharedSecret::new(&pubkey, &seckey);
                let new_key = ECDSAKey::with_shared_secret(shared_secret, false);
                CryptoData::encrypt_with_dh_key_using_iv(&data.to_vec(), &new_key, iv)
            }
            (OpaqueKey::BLS(key), OpaqueKey::BLS(public_key)) if key.use_legacy == public_key.use_legacy => {
                let pubkey = public_key.bls_public_key().map_err(KeyError::from)?;
                let seckey = key.bls_private_key().map_err(KeyError::from)?;
                let product = (pubkey * seckey).map_err(KeyError::from)?;
                let new_key = BLSKey::key_with_public_key(g1_element_serialized(&product, key.use_legacy), key.use_legacy);
                CryptoData::encrypt_with_dh_key_using_iv(&data.to_vec(), &new_key, iv)
            }
            _ => Err(KeyError::DHKeyExchange)
        }
    }

    pub fn decrypt_data(&self, public_key: OpaqueKey, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        match (self, public_key) {
            (OpaqueKey::ECDSA(key), OpaqueKey::ECDSA(public_key)) => {
                let pubkey = dashcore::secp256k1::PublicKey::from_slice(&public_key.public_key_data()).map_err(KeyError::from)?;
                let seckey = dashcore::secp256k1::SecretKey::from_byte_array(&key.seckey).map_err(KeyError::from)?;
                let shared_secret = dashcore::secp256k1::ecdh::SharedSecret::new(&pubkey, &seckey);
                let new_key = ECDSAKey::with_shared_secret(shared_secret, false);
                CryptoData::decrypt_with_dh_key(&data.to_vec(), &new_key)
            }
            (OpaqueKey::BLS(key), OpaqueKey::BLS(public_key)) if key.use_legacy == public_key.use_legacy => {
                let pubkey = public_key.bls_public_key().map_err(KeyError::from)?;
                let seckey = key.bls_private_key().map_err(KeyError::from)?;
                let product = (pubkey * seckey).map_err(KeyError::from)?;
                let new_key = BLSKey::key_with_public_key(g1_element_serialized(&product, key.use_legacy), key.use_legacy);
                CryptoData::decrypt_with_dh_key(&data.to_vec(), &new_key)
            }
            _ => Err(KeyError::DHKeyExchange)
        }
    }
    pub fn decrypt_data_vec(&self, public_key: OpaqueKey, data: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        self.decrypt_data(public_key, &data)
    }

    pub fn decrypt_data_using_iv_size(&self, public_key: OpaqueKey, data: &[u8], iv_size: usize) -> Result<Vec<u8>, KeyError> {
        match (self, public_key) {
            (OpaqueKey::ECDSA(key), OpaqueKey::ECDSA(public_key)) => {
                let pubkey = dashcore::secp256k1::PublicKey::from_slice(&public_key.public_key_data()).map_err(KeyError::from)?;
                let seckey = dashcore::secp256k1::SecretKey::from_byte_array(&key.seckey).map_err(KeyError::from)?;
                let shared_secret = dashcore::secp256k1::ecdh::SharedSecret::new(&pubkey, &seckey);
                let new_key = ECDSAKey::with_shared_secret(shared_secret, false);
                CryptoData::decrypt_with_dh_key_using_iv_size(&data.to_vec(), &new_key, iv_size)
            }
            (OpaqueKey::BLS(key), OpaqueKey::BLS(public_key)) if key.use_legacy == public_key.use_legacy => {
                let pubkey = public_key.bls_public_key().map_err(KeyError::from)?;
                let seckey = key.bls_private_key().map_err(KeyError::from)?;
                let product = (pubkey * seckey).map_err(KeyError::from)?;
                let new_key = BLSKey::key_with_public_key(g1_element_serialized(&product, key.use_legacy), key.use_legacy);
                CryptoData::decrypt_with_dh_key_using_iv_size(&data.to_vec(), &new_key, iv_size)
            }
            _ => Err(KeyError::DHKeyExchange)
        }
    }

    pub fn encrypt_data_with_dh_key(&self, data: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) =>
                CryptoData::encrypt_with_dh_key(&data, key),
            OpaqueKey::BLS(key) =>
                CryptoData::encrypt_with_dh_key(&data, key),
            _ => Err(KeyError::DHKeyExchange),
        }
    }
    pub fn decrypt_data_with_dh_key(&self, data: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) =>
                CryptoData::decrypt_with_dh_key(&data, key),
            OpaqueKey::BLS(key) =>
                CryptoData::decrypt_with_dh_key(&data, key),
            _ => Err(KeyError::DHKeyExchange),
        }
    }
    pub fn encrypt_data_with_dh_key_using_iv(&self, data: Vec<u8>, iv: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) =>
                CryptoData::encrypt_with_dh_key_using_iv(&data, key, iv),
            OpaqueKey::BLS(key) =>
                CryptoData::encrypt_with_dh_key_using_iv(&data, key, iv),
            _ => Err(KeyError::DHKeyExchange),
        }
    }

    pub fn decrypt_data_with_dh_key_using_iv_size(&self, data: Vec<u8>, iv_size: usize) -> Result<Vec<u8>, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) =>
                CryptoData::decrypt_with_dh_key_using_iv_size(&data, key, iv_size),
            OpaqueKey::BLS(key) =>
                CryptoData::decrypt_with_dh_key_using_iv_size(&data, key, iv_size),
            _ => Err(KeyError::DHKeyExchange),
        }
    }

}

impl KeyKind {
    pub fn public_key_from_extended_public_key_data(&self, data: &[u8], index_path: &IndexPath<u32>) -> Result<Vec<u8>, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::public_key_from_extended_public_key_data(data, index_path),
            KeyKind::ED25519 => ED25519Key::public_key_data_from_extended_public_key_data(data, index_path),
            _ => BLSKey::public_key_from_extended_public_key_data(data, index_path, *self == KeyKind::BLS),
        }
    }

    pub fn derive_key_from_seed(&self, seed: &[u8], derivation_path: &IndexPath<[u8; 32]>) -> Result<OpaqueKey, KeyError> {
        self.key_with_seed_data(seed)
            .and_then(|top_key| top_key.private_derive_to_path(derivation_path))
    }
    pub fn private_keys_at_index_paths(
        &self,
        seed: &[u8],
        index_paths: Vec<IndexPath<u32>>,
        derivation_path: &IndexPath<[u8; 32]>
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
        derivation_path: &IndexPath<[u8; 32]>,
        chain_type: ChainType,
    ) -> Result<Vec<String>, KeyError> {
        self.derive_key_from_seed(seed, derivation_path)
            .map(|derivation_path_extended_key| {
                let script = chain_type.script_map().privkey;
                index_paths.iter()
                    .map(|index_path| derivation_path_extended_key.private_derive_to_path(index_path)
                        .map(|private_key| private_key.serialized_private_key_for_script(script)))
                    .flatten()
                    .collect()
            })
    }
    pub fn private_key_at_index_path_u32(&self, index_path: IndexPath<u32>, extended_private_key_data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_extended_private_key_data(extended_private_key_data)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::key_with_extended_private_key_data(extended_private_key_data)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::ED25519),
            _ => BLSKey::key_with_extended_private_key_data(extended_private_key_data, *self == KeyKind::BLS)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::BLS)
        }
    }
    pub fn derive_key_from_extended_private_key_data_for_index_path_u32(&self, data: &[u8], index_path: IndexPath<u32>) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_extended_private_key_data(data)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::key_with_extended_private_key_data(data)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::ED25519),
            _ => BLSKey::key_with_extended_private_key_data(data, *self == KeyKind::BLS)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::BLS)

        }
    }

}

/// TMP solution since ferment fails with expanding such a generic type
// #[ferment_macro::export]
// #[derive(Clone, Debug)]
// pub struct IndexPathU32 {
//     pub indexes: Vec<u32>,
//     pub hardened: Vec<bool>,
// }
#[ferment_macro::export]
#[derive(Clone, Debug)]
pub struct IndexPathU256 {
    pub indexes: Vec<[u8; 32]>,
    pub hardened: Vec<bool>,
}

impl From<IndexPathU256> for IndexPath<[u8; 32]> {
    fn from(value: IndexPathU256) -> Self {
        let IndexPathU256 { indexes, hardened } = value;
        IndexPath::new_hardened(indexes, hardened)
    }
}
impl From<&IndexPathU256> for IndexPath<[u8; 32]> {
    fn from(value: &IndexPathU256) -> Self {
        IndexPath::from(value.clone())
    }
}
impl From<Vec<u32>> for IndexPath<u32> {
    fn from(value: Vec<u32>) -> Self {
        // let IndexPathU32 { indexes, hardened } = value;
        IndexPath::new_hardened(value, vec![])
    }
}
impl From<&Vec<u32>> for IndexPath<u32> {
    fn from(value: &Vec<u32>) -> Self {
        IndexPath::from(value.clone())
    }
}

#[ferment_macro::export]
impl KeyKind {

    pub fn identity_derivation_kind(&self) -> DerivationPathKind {
        match self {
            KeyKind::ECDSA => DerivationPathKind::IdentityECDSA,
            KeyKind::BLS | KeyKind::BLSBasic => DerivationPathKind::IdentityECDSA,
            KeyKind::ED25519 => panic!("should not be called for ED25519 keys")
        }
    }

    pub fn equal_to_kind(&self, kind: KeyKind) -> bool {
        kind.eq(self)
    }
    pub fn index(&self) -> i16 {
        match self {
            KeyKind::ECDSA => 0,
            KeyKind::BLS => 1,
            KeyKind::BLSBasic => 2,
            KeyKind::ED25519 => 3
        }
    }
    pub fn public_key_from_extended_public_key_data_at_index_path(&self, data: &[u8], index_path: &Vec<u32>) -> Result<Vec<u8>, KeyError> {
        let index_path = IndexPath::from(index_path);
        self.public_key_from_extended_public_key_data(data, &index_path)
    }
    pub fn public_key_from_extended_public_key_data_at_index_path_256(&self, data: &[u8], index_path: &IndexPathU256) -> Result<OpaqueKey, KeyError> {
        let key = self.key_with_seed_data(data)?;
        let index_path = IndexPath::from(index_path);
        key.private_derive_to_path(&index_path)
    }
    pub fn private_key_at_index_path_wrapped(&self, seed: &[u8], index_path: Vec<u32>, derivation_path: IndexPathU256) -> Result<OpaqueKey, KeyError> {
        let key = self.derive_key_from_seed_wrapped(seed, derivation_path)?;
        let index_path = IndexPath::from(index_path);
        key.private_derive_to_path(&index_path)
    }
    pub fn private_key_at_index_path_wrapped_as_opt(&self, seed: &[u8], index_path: Vec<u32>, derivation_path: IndexPathU256) -> Option<OpaqueKey> {
        self.private_key_at_index_path_wrapped(seed, index_path, derivation_path).ok()
    }
    pub fn derive_key_from_seed_wrapped(&self, seed: &[u8], derivation_path: IndexPathU256) -> Result<OpaqueKey, KeyError> {
        let key = self.key_with_seed_data(seed)?;
        let index_path = IndexPath::from(derivation_path);
        key.private_derive_to_path(&index_path)
    }
    pub fn derive_key_from_seed_wrapped_as_opt(&self, seed: &[u8], derivation_path: IndexPathU256) -> Option<OpaqueKey> {
        self.derive_key_from_seed_wrapped(seed, derivation_path).ok()
    }

    pub fn key_with_private_key(&self, secret: &str, chain_type: ChainType) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_private_key(secret, chain_type).map(OpaqueKey::ECDSA),
            KeyKind::BLS => BLSKey::key_with_private_key(secret, true).map(OpaqueKey::BLS),
            KeyKind::BLSBasic => BLSKey::key_with_private_key(secret, false).map(OpaqueKey::BLS),
            KeyKind::ED25519 => ED25519Key::key_with_private_key(secret).map(OpaqueKey::ED25519),
        }
    }
    pub fn key_with_private_key_opt(&self, secret: &str, chain_type: ChainType) -> Option<OpaqueKey> {
        self.key_with_private_key(secret, chain_type).ok()
    }

    pub fn private_keys_at_index_paths_wrapped(
        &self,
        seed: &[u8],
        index_paths: Vec<Vec<u32>>,
        derivation_path: IndexPathU256
    ) -> Result<Vec<OpaqueKey>, KeyError> {
        let key = self.derive_key_from_seed_wrapped(seed, derivation_path)?;
        Ok(index_paths.into_iter()
            .map(|index_path| key.private_derive_to_path(&IndexPath::from(index_path)))
            .flatten()
            .collect())
    }
    pub fn serialized_private_keys_at_index_paths_wrapper(
        &self,
        seed: &[u8],
        index_paths: Vec<Vec<u32>>,
        derivation_path: IndexPathU256,
        chain_type: ChainType,
    ) -> Result<Vec<String>, KeyError> {
        let key = self.derive_key_from_seed_wrapped(seed, derivation_path)?;
        let script = chain_type.script_map().privkey;
        Ok(index_paths.into_iter()
            .map(|index_path| key.private_derive_to_path(&IndexPath::from(index_path))
                .map(|private_key| private_key.serialized_private_key_for_script(script)))
            .flatten()
            .collect())
    }


    pub fn derivation_string(&self) -> String {
        match self {
            KeyKind::ECDSA => "",
            KeyKind::ED25519 => "_ED_",
            KeyKind::BLS | KeyKind::BLSBasic  => "_BLS_",
        }.to_string()
    }
    pub fn key_storage_prefix(&self) -> String {
        match self {
            KeyKind::ECDSA => "",
            KeyKind::BLS => "_BLS_",
            KeyKind::BLSBasic => "_BLS_B_",
            KeyKind::ED25519 => "_ED25519_"
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
    pub fn key_with_private_key_data_as_opt(&self, data: &[u8]) -> Option<OpaqueKey> {
        self.key_with_private_key_data(data).ok()
    }

    pub fn key_with_seed_data(&self, seed: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::init_with_seed_data(seed).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::init_with_seed_data(seed).map(OpaqueKey::ED25519),
            _ => BLSKey::extended_private_key_with_seed_data(seed, *self == KeyKind::BLS).map(OpaqueKey::BLS)
        }
    }
    pub fn key_with_seed_data_as_opt(&self, seed: &[u8]) -> Option<OpaqueKey> {
        self.key_with_seed_data(seed).ok()
    }

    pub fn key_with_public_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_public_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::key_with_public_key_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::key_with_public_key_data(data, *self == KeyKind::BLS).map(OpaqueKey::BLS),
        }
    }
    pub fn key_with_public_key_data_as_opt(&self, data: &[u8]) -> Option<OpaqueKey> {
        self.key_with_public_key_data(data).ok()
    }

    pub fn key_init_with_extended_public_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::init_with_extended_public_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::init_with_extended_public_key_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::init_with_extended_public_key_data(data, *self == KeyKind::BLS)
                .map(OpaqueKey::BLS)
                .map_err(KeyError::from)
        }
    }
    pub fn key_with_extended_public_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_extended_public_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::key_with_extended_public_key_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::key_with_extended_public_key_data(data, *self == KeyKind::BLS).map(OpaqueKey::BLS).map_err(KeyError::from)
        }
    }
    pub fn key_with_extended_public_key_data_as_opt(&self, data: &[u8]) -> Option<OpaqueKey> {
        self.key_with_extended_public_key_data(data).ok()
    }

    pub fn key_with_extended_private_key_data(&self, data: &[u8]) -> Result<OpaqueKey, KeyError> {
        match self {
            KeyKind::ECDSA => ECDSAKey::init_with_extended_private_key_data(data).map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::init_with_extended_private_key_data(data).map(OpaqueKey::ED25519),
            _ => BLSKey::init_with_extended_private_key_data(data, *self == KeyKind::BLS).map(OpaqueKey::BLS).map_err(KeyError::from)
        }
    }
    pub fn key_with_extended_private_key_data_as_opt(&self, data: &[u8]) -> Option<OpaqueKey> {
        self.key_with_extended_private_key_data(data).ok()
    }

    pub fn derive_key_from_extended_private_key_data_for_index_path(&self, data: &[u8], index_path: Vec<u32>) -> Result<OpaqueKey, KeyError> {
        let index_path = IndexPath::from(index_path);
        match self {
            KeyKind::ECDSA => ECDSAKey::key_with_extended_private_key_data(data)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::ECDSA),
            KeyKind::ED25519 => ED25519Key::key_with_extended_private_key_data(data)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::ED25519),
            _ => BLSKey::key_with_extended_private_key_data(data, *self == KeyKind::BLS)
                .and_then(|key| key.private_derive_to_path(&index_path))
                .map(OpaqueKey::BLS)
        }
    }

    pub fn derive_key_from_extended_private_key_data_for_index_path_as_opt(&self, data: &[u8], index_path: Vec<u32>) -> Option<OpaqueKey> {
        self.derive_key_from_extended_private_key_data_for_index_path(data, index_path).ok()
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
where U: Clone + Debug + Encodable + IndexHardSoft + PartialEq + Extremum,
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
    fn public_derive_to_path_with_offset(&self, path: &IndexPath<U>, offset: usize) -> Result<Self, KeyError> {
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
    fn address_with_public_key_data(&self, chain: ChainType) -> String {
        address::with_public_key_data(&self.public_key_data(), chain)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            OpaqueKey::ECDSA(key) => key.compact_sign(data).to_vec(),
            OpaqueKey::BLS(key) => key.sign(data),
            OpaqueKey::ED25519(key) => key.sign(data)
        }
    }

    fn hash_and_sign(&self, data: Vec<u8>) -> Vec<u8> {
        let hash = sha256d::Hash::hash(&data);
        self.sign(hash.as_ref())
    }

    fn verify(&mut self, message_digest: &[u8], signature: &[u8]) -> Result<bool, KeyError> {
        match self {
            OpaqueKey::ECDSA(key) => key.verify(message_digest, signature),
            OpaqueKey::BLS(key) => key.verify(message_digest, signature),
            OpaqueKey::ED25519(key) => key.verify(message_digest, signature),
        }
    }

    fn secret_key(&self) -> [u8; 32] {
        match self {
            OpaqueKey::ECDSA(key) => key.seckey,
            OpaqueKey::BLS(key) => key.secret_key(),
            OpaqueKey::ED25519(key) => key.secret_key(),
        }
    }

    fn chaincode(&self) -> [u8; 32] {
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

    fn serialized_private_key_for_script(&self, chain_prefix: u8) -> String {
        match self {
            OpaqueKey::ECDSA(key) => key.serialized_private_key_for_script(chain_prefix),
            OpaqueKey::BLS(key) => key.serialized_private_key_for_script(chain_prefix),
            OpaqueKey::ED25519(key) => key.serialized_private_key_for_script(chain_prefix),
        }
    }

    fn hmac_256_data(&self, data: &[u8]) -> [u8; 32] {
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

    fn sign_message_digest(&self, digest: [u8; 32]) -> Vec<u8> {
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

#[ferment_macro::export]
pub fn key_kind_from_index(index: i16) -> KeyKind {
    KeyKind::from(index)
}


#[ferment_macro::export]
pub fn maybe_opaque_key_used_in_tx_input_script(
    tx_input_script: Vec<u8>,
    keys: Vec<OpaqueKey>,
    chain: ChainType
) -> Option<OpaqueKey> {
    for key in keys {
        let chain_script_map = chain.script_map();
        if let Some(script_address) = address::with_script_pub_key(&tx_input_script, &chain_script_map) {
            let key_addr = address::with_public_key_data_and_script_pub_key(&key.public_key_data(), chain_script_map.pubkey);
            if script_address.eq(&key_addr) {
                return Some(key);
            }
        }
    }
    None
}
