pub mod bls_key;
pub mod crypto_data;
pub mod dip14;
pub mod ed25519_key;
pub mod ecdsa_key;
pub mod key;

pub use self::key::OpaqueKey;
// pub use self::key::KeyKind;
pub use self::bls_key::BLSKey;
pub use self::ecdsa_key::ECDSAKey;
pub use self::ed25519_key::ED25519Key;

use std::fmt::{Debug, Display};
use crate::chain::bip::bip32;
use crate::chain::ScriptMap;
use crate::chain::derivation::index_path::{Extremum, IIndexPath, IndexHardSoft};
use crate::chain::tx::protocol::SIGHASH_ALL;
use crate::consensus::Encodable;
use crate::crypto::byte_util::UInt256;
use crate::keys::key::KeyKind;
use crate::util::address::address;
use crate::util::base58;
use crate::util::data_append::DataAppend;
use crate::util::script::ScriptElement;
use crate::util::sec_vec::SecVec;

pub trait DeriveKey<T>: Sized
    where T: IIndexPath<Item: Copy + Clone + Display + Debug + Encodable + IndexHardSoft + PartialEq + Extremum> {
    fn private_derive_to_path(&self, path: &T) -> Result<Self, KeyError>;
    fn public_derive_to_path_with_offset(&mut self, path: &T, offset: usize) -> Result<Self, KeyError>;
    fn public_derive_to_path(&mut self, path: &T) -> Result<Self, KeyError> {
        self.public_derive_to_path_with_offset(path, 0)
    }
}

#[ferment_macro::export]
pub trait IKey: Send + Sync + Debug {
    fn kind(&self) -> KeyKind;
    fn address_with_public_key_data(&self, script_map: &ScriptMap) -> String {
        address::with_public_key_data(&self.public_key_data(), script_map)
    }
    fn sign(&self, data: &[u8]) -> Vec<u8>;
    fn verify(&mut self, message_digest: &[u8], signature: &[u8]) -> bool;
    fn secret_key(&self) -> UInt256;

    fn chaincode(&self) -> UInt256;
    fn fingerprint(&self) -> u32;

    fn private_key_data(&self) -> Result<Vec<u8>, KeyError>;
    fn public_key_data(&self) -> Vec<u8>;
    fn extended_private_key_data(&self) -> Result<SecVec, KeyError>;
    fn extended_public_key_data(&self) -> Result<Vec<u8>, KeyError>;

    // fn private_derive_to_path<PATH>(&self, path: &PATH) -> Result<Self, KeyError>
    //     where Self: Sized, PATH: IIndexPath<Item = u32>;
    // fn private_derive_to_256bit_derivation_path<PATH>(&self, path: &PATH) -> Result<Self, KeyError>
    //     where Self: Sized, PATH: IIndexPath<Item = UInt256> {
    //     self.private_derive_to_path(&path.base_index_path())
    // }
    // fn public_derive_to_256bit_derivation_path<PATH>(&mut self, path: &PATH) -> Result<Self, KeyError>
    //     where Self: Sized, PATH: IIndexPath<Item = UInt256> {
    //     self.public_derive_to_256bit_derivation_path_with_offset(path, 0)
    // }
    // fn public_derive_to_256bit_derivation_path_with_offset<PATH>(&mut self, path: &PATH, offset: usize) -> Result<Self, KeyError>
    //     where Self: Sized, PATH: IIndexPath<Item = UInt256>;

    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String;
    fn hmac_256_data(&self, data: &[u8]) -> UInt256;
    fn forget_private_key(&mut self);

    fn create_signature(&self, tx_input_script: &Vec<u8>, tx_data: &Vec<u8>) -> Vec<u8> {
        let mut sig = Vec::<u8>::new();
        let hash = UInt256::sha256d(tx_data);
        let mut s = self.sign(&hash.0.to_vec());
        let elem = tx_input_script.script_elements();
        (SIGHASH_ALL as u8).enc(&mut s);
        s.append_script_push_data(&mut sig);
        // sig.append_script_push_data(s);
        if elem.len() >= 2 {
            if let ScriptElement::Data([0x88 /*OP_EQUALVERIFY*/, ..], ..) = elem[elem.len() - 2] {
                // pay-to-pubkey-hash scriptSig
                self.public_key_data().append_script_push_data(&mut sig);
                // sig.append_script_push_data(self.public_key_data());
            }
        }
        sig
    }


}

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub enum KeyError {
    WrongFormat,
    WrongLength(usize),
    Extended(bool),
    Bip32(bip32::Error),
    Bip38(bip38::Error),
    Bytes(byte::Error),
    Secp256k1(secp256k1::Error),
    Base58(base58::Error),
    Bls(String),
    Hex(hashes::hex::Error),
    EDSignature(String),
    UnableToDerive,
    DHKeyExchange,
    CCCrypt(i32),
    EmptySecKey,
    Product,
    TryFromSliceError(std::array::TryFromSliceError)
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
impl std::error::Error for KeyError {}

impl From<std::array::TryFromSliceError> for KeyError {
    fn from(value: std::array::TryFromSliceError) -> Self {
        Self::TryFromSliceError(value)
    }
}

impl From<base58::Error> for KeyError {
    fn from(value: base58::Error) -> Self {
        Self::Base58(value)
    }
}

impl From<bip32::Error> for KeyError {
    fn from(value: bip32::Error) -> Self {
        Self::Bip32(value)
    }
}
impl From<bip38::Error> for KeyError {
    fn from(value: bip38::Error) -> Self {
        Self::Bip38(value)
    }
}

impl From<byte::Error> for KeyError {
    fn from(value: byte::Error) -> Self {
        Self::Bytes(value)
    }
}
impl From<secp256k1::Error> for KeyError {
    fn from(value: secp256k1::Error) -> Self {
        Self::Secp256k1(value)
    }
}
impl From<bls_signatures::BlsError> for KeyError {
    fn from(value: bls_signatures::BlsError) -> Self {
        Self::Bls(value.to_string())
    }
}
impl From<hashes::hex::Error> for KeyError {
    fn from(value: hashes::hex::Error) -> Self {
        Self::Hex(value)
    }
}
impl From<ed25519_dalek::SignatureError> for KeyError {
    fn from(value: ed25519_dalek::SignatureError) -> Self {
        Self::EDSignature(value.to_string())
    }
}