pub mod bls_key;
pub mod crypto_data;
pub mod dip14;
pub mod ed25519_key;
pub mod ecdsa_key;
pub mod key;
pub mod operator_public_key;

use std::convert::Infallible;
pub use self::key::OpaqueKey;
pub use self::bls_key::BLSKey;
pub use self::ecdsa_key::ECDSAKey;
pub use self::ed25519_key::ED25519Key;
pub use self::operator_public_key::OperatorPublicKey;

use std::fmt::Debug;
use dashcore::consensus::{encode, Encodable};
use crate::bip::bip32;
use crate::derivation::index_path::{Extremum, IIndexPath, IndexHardSoft};
use crate::keys::key::KeyKind;
use crate::network::ChainType;
use crate::util::{base58, sec_vec::SecVec};

pub trait DeriveKey<T>: Sized
    where T: IIndexPath<Item: Clone + Debug + Encodable + IndexHardSoft + PartialEq + Extremum> {
    fn private_derive_to_path(&self, path: &T) -> Result<Self, KeyError>;
    fn public_derive_to_path_with_offset(&self, path: &T, offset: usize) -> Result<Self, KeyError>;
    fn public_derive_to_path(&self, path: &T) -> Result<Self, KeyError> {
        self.public_derive_to_path_with_offset(path, 0)
    }
}

#[ferment_macro::export]
pub trait IKey: Send + Sync + Debug {
    fn kind(&self) -> KeyKind;
    fn secret_key_string(&self) -> String;
    fn has_private_key(&self) -> bool;

    fn address_with_public_key_data(&self, chain: ChainType) -> String;
    fn sign(&self, data: &[u8]) -> Vec<u8>;
    fn hash_and_sign(&self, data: Vec<u8>) -> Vec<u8>;
    fn verify(&mut self, message_digest: &[u8], signature: &[u8]) -> Result<bool, KeyError>;
    fn secret_key(&self) -> [u8; 32];

    fn chaincode(&self) -> [u8; 32];
    fn fingerprint(&self) -> u32;

    fn private_key_data(&self) -> Result<Vec<u8>, KeyError>;
    fn public_key_data(&self) -> Vec<u8>;
    fn extended_private_key_data(&self) -> Result<SecVec, KeyError>;
    fn extended_public_key_data(&self) -> Result<Vec<u8>, KeyError>;

    fn serialized_private_key_for_script(&self, chain_prefix: u8) -> String;
    fn hmac_256_data(&self, data: &[u8]) -> [u8; 32];
    fn forget_private_key(&mut self);
    fn sign_message_digest(&self, digest: [u8; 32]) -> Vec<u8>;
    fn private_key_data_equal_to(&self, other_private_key_data: &[u8; 32]) -> bool;
    fn public_key_data_equal_to(&self, other_public_key_data: &Vec<u8>) -> bool;
}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum KeyError {
    WrongFormat,
    WrongLength(usize),
    Extended(bool),
    UnableToDerive,
    DHKeyExchange,
    CCCrypt(i32),
    EmptySecKey,
    Product,
    Any(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
impl std::error::Error for KeyError {}

impl From<std::array::TryFromSliceError> for KeyError {
    fn from(value: std::array::TryFromSliceError) -> Self {
        Self::Any(value.to_string())
    }
}

impl From<Infallible> for KeyError {
    fn from(value: Infallible) -> Self {
        Self::Any(value.to_string())
    }
}

impl From<base58::Error> for KeyError {
    fn from(value: base58::Error) -> Self {
        Self::Any(value.to_string())
    }
}

impl From<bip32::Error> for KeyError {
    fn from(value: bip32::Error) -> Self {
        Self::Any(format!("{value:?}"))
    }
}
impl From<bip38::Error> for KeyError {
    fn from(value: bip38::Error) -> Self {
        Self::Any(value.to_string())
    }
}

impl From<byte::Error> for KeyError {
    fn from(value: byte::Error) -> Self {
        Self::Any(format!("{value:?}"))
    }
}
impl From<dashcore::secp256k1::Error> for KeyError {
    fn from(value: dashcore::secp256k1::Error) -> Self {
        Self::Any(value.to_string())
    }
}
impl From<dashcore::bls_signatures::BlsError> for KeyError {
    fn from(value: dashcore::bls_signatures::BlsError) -> Self {
        Self::Any(value.to_string())
    }
}
impl From<dashcore::hashes::hex::Error> for KeyError {
    fn from(value: dashcore::hashes::hex::Error) -> Self {
        Self::Any(value.to_string())
    }
}
impl From<ed25519_dalek::SignatureError> for KeyError {
    fn from(value: ed25519_dalek::SignatureError) -> Self {
        Self::Any(value.to_string())
    }
}

impl From<encode::Error> for KeyError {
    fn from(value: encode::Error) -> Self {
        Self::Any(value.to_string())
    }
}