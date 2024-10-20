use std::mem;
use byte::BytesExt;
use byte::ctx::Bytes;
use hashes::sha256;
use hashes::hex::{FromHex, ToHex};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Scalar, Secp256k1};
use crate::chain::bip::bip32;
use crate::chain::common::ChainType;
use crate::chain::derivation::{BIP32_HARD, IIndexPath, IndexPath};
use crate::chain::params::ScriptMap;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, clone_into_array, ECPoint, UInt160, UInt256, UInt512, Zeroable};
use crate::keys::{KeyKind, KeyError, IKey, DeriveKey};
use crate::keys::crypto_data::{CryptoData, DHKey};
use crate::keys::dip14::{secp256k1_point_from_bytes, IChildKeyDerivation};
use crate::util::address::address;
use crate::util::address::address::is_valid_dash_private_key;
use crate::util::base58;
use crate::util::sec_vec::SecVec;

const EXT_PUBKEY_SIZE: usize = 4 + size_of::<UInt256>() + size_of::<ECPoint>();

#[derive(Clone, Debug, Default)]
#[ferment_macro::opaque]
pub struct ECDSAKey {
    pub seckey: UInt256,
    pub pubkey: Vec<u8>,
    pub compressed: bool,
    pub chaincode: UInt256,
    pub fingerprint: u32,
    pub is_extended: bool,
}

impl ECDSAKey {

    fn with_shared_secret(secret: secp256k1::ecdh::SharedSecret, compressed: bool) -> Self {
        Self { pubkey: secret.secret_bytes().to_vec(), compressed, ..Default::default() }
    }

    fn with_pubkey_compressed(pubkey: secp256k1::PublicKey, compressed: bool) -> Self {
        Self { pubkey: if compressed { pubkey.serialize().to_vec() } else { pubkey.serialize_uncompressed().to_vec() }, compressed, ..Default::default() }
    }

    fn with_seckey(seckey: secp256k1::SecretKey, compressed: bool) -> Self {
        Self { seckey: UInt256(seckey.secret_bytes()), compressed, ..Default::default() }
    }

    fn with_seckey_and_chaincode(seckey: secp256k1::SecretKey, chaincode: UInt256, compressed: bool) -> Self {
        Self { seckey: UInt256(seckey.secret_bytes()), chaincode, compressed, ..Default::default() }
    }
    fn update_extended_params(mut key: Self, data: &[u8]) -> Self {
        let offset = &mut 0;
        key.fingerprint = data.read_with::<u32>(offset, byte::LE).unwrap();
        key.chaincode = data.read_with::<UInt256>(offset, byte::LE).unwrap();
        key.is_extended = true;
        key
    }

    pub fn public_key(&self) -> Result<secp256k1::PublicKey, secp256k1::Error> {
        Self::public_key_from_bytes(&self.pubkey)
    }

    pub fn secret_key(&self) -> Result<secp256k1::SecretKey, secp256k1::Error> {
        Self::secret_key_from_bytes(self.seckey.as_bytes())
    }

    pub fn public_key_from_inner_secret_key_serialized(&self) -> Result<Vec<u8>, secp256k1::Error> {
        self.secret_key()
            .map(|ref secret_key| Self::public_key_from_secret_key_serialized(secret_key, self.compressed))
    }

    pub fn public_key_from_secret_key_serialized(secret_key: &secp256k1::SecretKey, compressed: bool) -> Vec<u8> {
        let pubkey = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
        if compressed {
            pubkey.serialize().to_vec()
        } else {
            pubkey.serialize_uncompressed().to_vec()
        }
    }


    fn private_derive_to_256bit_derivation_path_for_seckey_and_chaincode<PATH>(seckey: UInt256, chaincode: UInt256, path: &PATH) -> Result<Self, KeyError>
    where Self: Sized, PATH: IIndexPath<Item = UInt256> {
        let mut seckey = seckey.clone();
        let mut chaincode = chaincode.clone();
        let mut fingerprint = 0u32;
        let length = path.length();
        (0..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    fingerprint = secp256k1::SecretKey::from_slice(&seckey.0)
                        .map(|sk| secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk))
                        .map(|pk| UInt160::hash160u32le(&pk.serialize()))
                        .unwrap_or(0);
                }
                Self::derive_child_private_key(&mut seckey, &mut chaincode, path, position)
            });
        Ok(Self { seckey, chaincode, fingerprint, is_extended: true, compressed: true, ..Default::default() })

    }
    pub fn message_from_bytes(data: &[u8]) -> Result<secp256k1::Message, secp256k1::Error> {
        secp256k1::Message::from_slice(data)
    }

    pub fn public_key_from_bytes(data: &[u8]) -> Result<secp256k1::PublicKey, secp256k1::Error> {
        secp256k1::PublicKey::from_slice(data)
    }

    pub fn secret_key_from_bytes(data: &[u8]) -> Result<secp256k1::SecretKey, secp256k1::Error> {
        secp256k1::SecretKey::from_slice(data)
    }

}

/// Shorthands
#[ferment_macro::export]
impl ECDSAKey {
    pub fn key_with_secret_data(data: &[u8], compressed: bool) -> Result<Self, KeyError> {
        Self::secret_key_from_bytes(data)
            .map_err(KeyError::from)
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }
    pub fn key_with_extended_public_key_data(bytes: &[u8]) -> Result<Self, KeyError> {
        let len = bytes.len();
        match len {
            69 | 101 => {
                let offset = &mut 0;
                let fingerprint = bytes.read_with::<u32>(offset, byte::LE)?;
                let chaincode = bytes.read_with::<UInt256>(offset, byte::LE)?;
                let pubkeydata: &[u8] = bytes.read_with(offset, Bytes::Len(len - *offset))?;
                let compressed = pubkeydata.len() == 33;
                Self::public_key_from_bytes(pubkeydata)
                    .map_err(KeyError::from)
                    .map(|pubkey| Self {
                        fingerprint,
                        chaincode,
                        compressed,
                        pubkey: if compressed { pubkey.serialize().to_vec() } else { pubkey.serialize_uncompressed().to_vec() },
                        is_extended: true,
                        ..Default::default()
                    })
            },
            len => Err(KeyError::WrongLength(len))
        }
    }

    pub fn public_key_data_from_seed(seed: &[u8], compressed: bool) -> Option<Vec<u8>> {
        Self::secret_key_from_bytes(seed)
            .ok()
            .map(|secret_key|
                Self::public_key_from_secret_key_serialized(&secret_key, compressed))
    }

    pub fn key_with_secret(secret: &UInt256, compressed: bool) -> Result<Self, KeyError> {
        Self::secret_key_from_bytes(secret.as_bytes())
            .map_err(KeyError::from)
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }
    pub fn key_with_combined_secret(data: &UInt512, compressed: bool) -> Result<Self, KeyError> {
        Self::secret_key_from_bytes(&data.0[..32])
            .map_err(KeyError::from)
            .map(|seckey| Self::with_seckey_and_chaincode(seckey, UInt256::from(&data.0[32..]), compressed))
    }
    pub fn key_with_secret_hex(string: &str, compressed: bool) -> Result<Self, KeyError> {
        Vec::from_hex(string)
            .map_err(KeyError::from)
            .and_then(|data| Self::key_with_secret_data(&data, compressed))
    }

    pub fn key_recovered_from_compact_sig(compact_sig: &[u8], message_digest: UInt256) -> Result<Self, KeyError> {
        Self::init_with_compact_sig(compact_sig, message_digest)
    }

    pub fn key_with_private_key(private_key_string: &str, chain_type: ChainType) -> Result<Self, KeyError> {
        Self::init_with_private_key(private_key_string, chain_type)
    }

    pub fn key_with_public_key_data(data: &[u8]) -> Result<Self, KeyError> {
        assert!(!data.is_empty());
        match data.len() {
            33 | 65 => Self::public_key_from_bytes(data)
                .map(|pubkey| Self::with_pubkey_compressed(pubkey, data.len() == 33))
                .map_err(KeyError::from),
            len => Err(KeyError::WrongLength(len))
        }
    }

    pub fn init_with_compact_sig(compact_sig: &[u8], message_digest: UInt256) -> Result<ECDSAKey, KeyError> {
        if compact_sig.len() != 65 {
            return Err(KeyError::WrongLength(compact_sig.len()));
        }
        let compressed = compact_sig[0] - 27 >= 4;
        let recid = RecoveryId::from_i32(((compact_sig[0] - 27) % 4) as i32)?;
        RecoverableSignature::from_compact(&compact_sig[1..], recid)
            .map_err(KeyError::from)
            .and_then(|sig| Secp256k1::new().recover_ecdsa(&secp256k1::Message::from(message_digest), &sig)
                .map_err(KeyError::from)
                .map(|pk| Self::with_pubkey_compressed(pk, compressed)))
            .map_err(KeyError::from)
    }

    pub fn init_with_seed_data(seed: &[u8]) -> Result<Self, KeyError> {
        let i = UInt512::bip32_seed_key(seed);
        Self::secret_key_from_bytes(&i.0[..32])
            .map_err(KeyError::from)
            .map(|seckey| Self::with_seckey_and_chaincode(seckey, UInt256::from(&i.0[32..]), true))
    }

    pub fn init_with_secret(secret: UInt256, compressed: bool) -> Result<Self, KeyError> {
        Self::secret_key_from_bytes(secret.as_bytes())
            .map_err(KeyError::from)
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }

    pub fn init_with_extended_private_key_data(data: &Vec<u8>) -> Result<Self, KeyError> {
        data.read_with::<UInt256>(&mut 36, byte::LE)
            .map_err(KeyError::from)
            .and_then(|secret| Self::init_with_secret(secret, true))
            .map(|key| Self::update_extended_params(key, data))
    }

    pub fn init_with_extended_public_key_data(data: &Vec<u8>) -> Result<Self, KeyError> {
        Self::init_with_public_key(data[36..].to_vec())
            .map_err(KeyError::from)
            .map(|key| Self::update_extended_params(key, data))
    }

    pub fn init_with_private_key(private_key: &str, chain_type: ChainType) -> Result<Self, KeyError> {
        match private_key.len() {
            0 => Err(KeyError::WrongLength(0)),
            // mini private key format
            22 | 30 if private_key.starts_with('L') => match is_valid_dash_private_key(&private_key.to_string(), &chain_type.script_map()) {
                true => Ok(Self::with_seckey(secp256k1::SecretKey::from_hashed_data::<sha256::Hash>(private_key.as_bytes()), false)),
                false => Err(KeyError::WrongFormat)
            },
            _ => {
                let mut d = base58::from_check(private_key).ok();
                if d.is_none() || d.as_ref().unwrap().len() == 28 {
                    d = base58::from(private_key).ok();
                }
                if d.as_ref().is_none() || !(32..=34).contains(&d.as_ref().unwrap().len()) {
                    d = Vec::from_hex(private_key).ok();
                }
                if d.as_ref().is_none() {
                    return Err(KeyError::WrongLength(0));
                }
                let data = d.unwrap();
                match data.len() {
                    33 | 34 if data[0] == chain_type.script_map().privkey =>
                        Self::secret_key_from_bytes(&data[1..33])
                            .map_err(KeyError::from)
                            .map(|seckey| Self::with_seckey(seckey, data.len() == 34)),
                    32 =>
                        Self::secret_key_from_bytes(&data[..])
                            .map_err(KeyError::from)
                            .map(|seckey| Self::with_seckey(seckey, false)),
                    len =>
                        Err(KeyError::WrongLength(len)),
                }
            }
        }
    }

    pub fn init_with_public_key(public_key: Vec<u8>) -> Result<Self, KeyError> {
        assert!(!public_key.is_empty(), "public_key is empty");
        match public_key.len() {
            33 | 65 => Self::public_key_from_bytes(&public_key)
                .map_err(KeyError::from)
                .map(|pubkey| Self::with_pubkey_compressed(pubkey, public_key.len() == 33)),
            _ => Err(KeyError::WrongLength(public_key.len()))
        }
    }

    pub fn key_with_extended_private_key_data(bytes: &[u8]) -> Result<Self, KeyError> {
        bytes.read_with::<UInt256>(&mut 36, byte::LE)
            .map_err(KeyError::from)
            .and_then(|key| Self::init_with_secret(key, true))
            .map(|key| Self::update_extended_params(key, bytes))
    }

    /// Pieter Wuille's compact signature encoding used for bitcoin message signing
    /// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
    pub fn compact_sign(&self, message_digest: UInt256) -> [u8; 65] {
        let mut sig = [0u8; 65];
        if self.seckey.is_zero() {
            warn!("Can't sign with a public key");
            return sig;
        }
        let secp = secp256k1::Secp256k1::new();
        let msg = Self::message_from_bytes(&message_digest.0).unwrap();
        let seckey = self.secret_key().unwrap();
        let rec_sig = secp.sign_ecdsa_recoverable(&msg, &seckey);
        let (rec_id, bytes) = rec_sig.serialize_compact();
        let version = 27 + rec_id.to_i32() as u8 + if self.compressed { 4 } else { 0 };
        sig[0] = version;
        sig[1..].copy_from_slice(&bytes);
        sig
    }
    pub fn key_with_compact_sig(compact_sig: &[u8], message_digest: UInt256) -> Result<Self, KeyError> {
        if compact_sig.len() != 65 {
            return Err(KeyError::Secp256k1(secp256k1::Error::InvalidSignature));
        }
        RecoveryId::from_i32(((compact_sig[0] - 27) % 4) as i32)
            .and_then(|recid| RecoverableSignature::from_compact(&compact_sig[1..], recid)
                .and_then(|sig| Secp256k1::new()
                    .recover_ecdsa(&secp256k1::Message::from(message_digest), &sig)
                    .map(|pubkey| ECDSAKey::with_pubkey_compressed(pubkey, compact_sig[0] - 27 >= 4))))
            .map_err(KeyError::from)
    }
    pub fn deprecated_incorrect_extended_public_key_from_seed(
        &self,
        secret: &[u8],
        chaincode: &[u8],
        hashes: &[u8],
        derivation_len: usize)
        -> Result<Self, KeyError> {
        let mut chaincode = UInt256::from(chaincode);
        let mut key = UInt256::from(secret);
        let mut writer = SecVec::new();
        self.hash160().u32_le().enc(&mut writer);
        (0..derivation_len).into_iter().for_each(|position| {
            let soft_index = hashes.read_with::<u64>(&mut position.clone(), byte::LE).unwrap() as u32;
            // let soft_index = slice.read_with::<u64>(&mut 0, byte::BE).unwrap() as u32;
            let buf = &mut [0u8; 37];
            if soft_index & BIP32_HARD != 0 {
                buf[1..33].copy_from_slice(&key.0);
            } else {
                buf[..33].copy_from_slice(&secp256k1_point_from_bytes(&key.0));
            }
            buf[33..37].copy_from_slice(soft_index.to_be_bytes().as_slice());
            let i = UInt512::hmac(chaincode.as_ref(), buf);

            let mut sec_key = secp256k1::SecretKey::from_slice(&key.0).expect("invalid private key");
            let tweak = Scalar::from_be_bytes(clone_into_array(&i.0[..32])).expect("invalid tweak");
            sec_key = sec_key.add_tweak(&tweak).expect("failed to add tweak");
            key.0.copy_from_slice(&sec_key.secret_bytes());
            chaincode.0.copy_from_slice(&i.0[32..]);
        });
        ECDSAKey::key_with_secret(&key, true)
            .and_then(|seckey| {
                chaincode.enc(&mut writer);
                writer.extend(seckey.public_key_data());
                ECDSAKey::key_with_extended_public_key_data(&writer)
            })
    }
    pub fn hash160(&self) -> UInt160 {
        UInt160::hash160(&self.public_key_data())
    }

}

#[ferment_macro::export]
impl IKey for ECDSAKey {

    fn kind(&self) -> KeyKind {
        KeyKind::ECDSA
    }

    fn secret_key_string(&self) -> String {
        if self.has_private_key() {
            self.seckey.0.to_hex()
        } else {
            String::new()
        }
    }

    fn has_private_key(&self) -> bool {
        !self.seckey.is_zero()
    }
    fn address_with_public_key_data(&self, script_map: &ScriptMap) -> String {
        address::with_public_key_data(&self.public_key_data(), script_map)
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        if self.seckey.is_zero() {
            warn!("There is no seckey for sign");
            return vec![];
        }
        match (Self::message_from_bytes(data), self.secret_key()) {
            // todo: check should we truncate up to 72
            (Ok(msg), Ok(seckey)) => secp256k1::Secp256k1::new().sign_ecdsa(&msg, &seckey).serialize_der().to_vec(),
            _ => vec![]
        }
    }

    fn verify(&mut self, message_digest: &[u8], signature: &[u8]) -> bool {
        if signature.len() > 65 {
            // not compact
            Self::public_key_from_bytes(&self.public_key_data())
                .and_then(|pk| secp256k1::ecdsa::Signature::from_der(&signature)
                    .and_then(|sig| Self::message_from_bytes(message_digest)
                        .and_then(|msg| Secp256k1::new().verify_ecdsa(&msg, &sig, &pk))))
                .is_ok()
        } else {
            // compact
            Self::key_recovered_from_compact_sig(signature, UInt256::from(message_digest))
                .map_or(false, |key| key.public_key_data().eq(&self.public_key_data()))
        }
    }

    fn secret_key(&self) -> UInt256 {
        self.seckey
    }

    fn chaincode(&self) -> UInt256 {
        self.chaincode
    }

    fn fingerprint(&self) -> u32 {
        self.fingerprint
    }

    fn private_key_data(&self) -> Result<Vec<u8>, KeyError> {
        match self.seckey.is_zero() {
            true => Err(KeyError::EmptySecKey),
            false => Ok(self.seckey.0.to_vec())
        }
    }

    fn public_key_data(&self) -> Vec<u8> {
        if self.pubkey.is_empty() && self.has_private_key() {
            let seckey = self.secret_key().unwrap();
            let pubkey = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &seckey);
            let serialized = if self.compressed {
                pubkey.serialize().to_vec()
            } else {
                pubkey.serialize_uncompressed().to_vec()
            };
            return serialized;
        }
        self.pubkey.clone()
    }

    fn extended_private_key_data(&self) -> Result<SecVec, KeyError> {
        match (self.is_extended, self.private_key_data()) {
            (true, Ok(private_key_data)) => {
                // TODO: secure data
                //NSMutableData *data = [NSMutableData secureData];
                let mut writer = SecVec::new();
                self.fingerprint.enc(&mut writer);
                self.chaincode.enc(&mut writer);
                writer.extend(private_key_data);
                // private_key_data.enc(&mut writer);
                Ok(writer)
            },
            _ => Err(KeyError::Extended(self.is_extended))
        }
    }

    fn extended_public_key_data(&self) -> Result<Vec<u8>, KeyError> {
        match self.is_extended {
            true => {
                let mut writer = Vec::<u8>::new();
                self.fingerprint.enc(&mut writer);
                self.chaincode.enc(&mut writer);
                writer.extend(self.public_key_data());
                Ok(writer)
            },
            extended => Err(KeyError::Extended(extended))
        }
    }

    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String {
        //if (uint256_is_zero(_seckey)) return nil;
        //NSMutableData *d = [NSMutableData secureDataWithCapacity:sizeof(UInt256) + 2];
        let mut writer = SecVec::with_capacity(if self.compressed { 34 } else { 33 });
        script.privkey.enc(&mut writer);
        self.seckey.enc(&mut writer);
        if self.compressed {
            b'\x01'.enc(&mut writer);
        }
        base58::check_encode_slice(&writer)
    }

    fn hmac_256_data(&self, data: &[u8]) -> UInt256 {
        UInt256::hmac::<sha256::Hash>(self.seckey.as_bytes(), data)
    }

    fn forget_private_key(&mut self) {
        self.public_key_data_mut();
        self.seckey = UInt256::MIN;
    }

    fn sign_message_digest(&self, digest: UInt256) -> Vec<u8> {
        self.compact_sign(digest)
            .to_vec()
    }
    fn private_key_data_equal_to(&self, other_private_key_data: &[u8; 32]) -> bool {
        self.seckey.0.eq(other_private_key_data)
    }

    fn public_key_data_equal_to(&self, other_public_key_data: &Vec<u8>) -> bool {
        self.public_key_data().eq(other_public_key_data)
    }
}

impl ECDSAKey {


    pub(crate) fn public_key_data_mut(&mut self) -> Vec<u8> {
        if self.pubkey.is_empty() && self.has_private_key() {
            // let mut d = Vec::<u8>::with_capacity(if self.compressed { 33 } else { 65 });
            let seckey = self.secret_key().unwrap();
            let pubkey = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &seckey);
            self.pubkey = if self.compressed {
                pubkey.serialize().to_vec()
            } else {
                pubkey.serialize_uncompressed().to_vec()
            };
        }
        self.pubkey.clone()
    }



    pub fn serialized_auth_private_key_from_seed(seed: &[u8], script_map: ScriptMap) -> String {
        let key = UInt512::bip32_seed_key(seed);
        let mut seckey = UInt256::from(&key.0[..32]);
        let mut chaincode = UInt256::from(&key.0[32..]);
        // path m/1H/0 (same as copay uses for bitauth)
        let path = IndexPath::new(vec![1 | BIP32_HARD, 0]);
        Self::derive_child_private_key(&mut seckey, &mut chaincode, &path, 0);
        Self::derive_child_private_key(&mut seckey, &mut chaincode, &path, 1);
        // derive_child_private_key(&mut seckey, &mut chaincode, 1 | BIP32_HARD);
        // derive_child_private_key(&mut seckey, &mut chaincode, 0);
        let mut writer = SecVec::new();
        script_map.privkey.enc(&mut writer);
        writer.extend_from_slice(&seckey.0);
        b'\x01'.enc(&mut writer); // specifies compressed pubkey format
        base58::check_encode_slice(&writer)
    }

    pub fn serialized_private_master_key_from_seed(seed: &Vec<u8>, chain_type: ChainType) -> String {
        let i = UInt512::bip32_seed_key(seed);
        bip32::Key::new(0, 0, UInt256::MIN, UInt256::from(&i.0[32..]), i.0[..32].to_vec(), false)
            .serialize(chain_type)
    }

    pub fn public_key_from_extended_public_key_data<PATH>(data: &[u8], path: &PATH) -> Result<Vec<u8>, KeyError>
        where PATH: IIndexPath<Item = u32> {
        match data.len() {
            EXT_PUBKEY_SIZE.. => {
                let mut c = UInt256::from(&data[4..36]);
                let mut k = ECPoint::from(&data[36..69]);
                (0..path.length())
                    .into_iter()
                    .for_each(|position| Self::derive_child_public_key(&mut k, &mut c, path, position));
                Ok(k.as_bytes().to_vec())
            },
            _ => Err(KeyError::WrongLength(data.len()))
        }
    }

}

impl DeriveKey<IndexPath<u32>> for ECDSAKey {
    fn private_derive_to_path(&self, path: &IndexPath<u32>) -> Result<Self, KeyError> {
        let mut seckey = self.seckey.clone();
        let mut chaincode = self.chaincode.clone();
        let mut fingerprint = 0u32;
        let length = path.length();
        (0..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    fingerprint = secp256k1::SecretKey::from_slice(&seckey.0)
                        .map(|sk| secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk))
                        .map(|pk| UInt160::hash160u32le(&pk.serialize()))
                        .unwrap_or(0);
                }
                Self::derive_child_private_key(&mut seckey, &mut chaincode, path, position)
            });
        Ok(Self { seckey, chaincode, fingerprint, is_extended: true, compressed: true, ..Default::default() })
    }

    fn public_derive_to_path_with_offset(&mut self, path: &IndexPath<u32>, offset: usize) -> Result<Self, KeyError> {
        unimplemented!("ECDSAKey::public_derive_to_path_with_offset")
    }
}

impl DeriveKey<IndexPath<UInt256>> for ECDSAKey {
    fn private_derive_to_path(&self, path: &IndexPath<UInt256>) -> Result<Self, KeyError> {
        Self::private_derive_to_256bit_derivation_path_for_seckey_and_chaincode(self.seckey, self.chaincode, path)
    }

    fn public_derive_to_path_with_offset(&mut self, path: &IndexPath<UInt256>, offset: usize) -> Result<Self, KeyError> {
        assert!(path.length() > offset, "derivation path offset must be smaller than the its length");
        let mut chaincode = self.chaincode.clone();
        let mut data = ECPoint::from(&self.public_key_data());
        let mut fingerprint = 0u32;
        let length = path.length();
        (offset..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length { fingerprint = UInt160::hash160u32le(data.as_ref()); }
                Self::derive_child_public_key(&mut data, &mut chaincode, path, position)
            });
        if let Ok(mut child_key) = Self::public_key_from_bytes(&data.0).map(|pubkey| Self::with_pubkey_compressed(pubkey, true)) {
            child_key.chaincode = chaincode;
            child_key.fingerprint = fingerprint;
            child_key.is_extended = true;
            Ok(child_key)
        } else {
            assert!(false, "Public key should be created");
            Err(KeyError::UnableToDerive)
        }
    }
}

/// For FFI
impl ECDSAKey {

    pub fn public_key_from_extended_public_key_data_at_index_path<PATH>(key: &Self, index_path: &PATH) -> Result<Self, KeyError>
        where Self: Sized, PATH: IIndexPath<Item=u32> {
        key.extended_public_key_data()
            .and_then(|ext_pk_data| Self::public_key_from_extended_public_key_data(&ext_pk_data, index_path))
            .and_then(|pub_key_data| Self::key_with_public_key_data(&pub_key_data))
    }



    pub fn serialized_extended_private_key_from_seed(seed: &[u8], index_path: IndexPath<UInt256>, chain_type: ChainType) -> Result<String, KeyError> {
        let i = UInt512::bip32_seed_key(seed);
        Self::private_derive_to_256bit_derivation_path_for_seckey_and_chaincode(UInt256::from(&i.0[..32]), UInt256::from(&i.0[32..]), &index_path)
            .map(|key| bip32::Key::new(
                index_path.length() as u8,
                key.fingerprint,
                if index_path.is_empty() { UInt256::MIN } else { index_path.last_index() },
                key.chaincode,
                key.seckey.0.to_vec(),
                index_path.last_hardened())
                .serialize(chain_type))

    }
}

impl DHKey for ECDSAKey {
    fn init_with_dh_key_exchange_with_public_key(public_key: &mut Self, private_key: &Self) -> Result<Self, KeyError>
        where Self: Sized {
        match (Self::public_key_from_bytes(&public_key.public_key_data()),
               Self::secret_key_from_bytes(private_key.seckey.as_bytes())) {
            (Ok(pubkey), Ok(seckey)) => Ok(Self::with_shared_secret(secp256k1::ecdh::SharedSecret::new(&pubkey, &seckey), false)),
            _ => Err(KeyError::DHKeyExchange)
        }
    }
}

impl CryptoData<ECDSAKey> for Vec<u8> {
    fn encrypt_with_secret_key_using_iv(&mut self, secret_key: &ECDSAKey, public_key: &ECDSAKey, initialization_vector: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        let mut destination = initialization_vector.clone();
        secret_key.secret_key()
            .map_err(KeyError::from)
            .and_then(|scalar| ECDSAKey::secret_key_from_bytes(public_key.seckey.as_bytes())
            .and_then(|seckey| ECDSAKey::public_key_from_bytes(&ECDSAKey::public_key_from_secret_key_serialized(&seckey, false)))
            .map(|pubkey| secp256k1::ecdh::SharedSecret::new(&pubkey, &scalar))
            .map_err(KeyError::from)
            .and_then(|shared_secret| <Self as CryptoData<ECDSAKey>>::encrypt(self, shared_secret.secret_bytes(), initialization_vector))
            .map(|encrypted_data| {
                destination.extend(encrypted_data);
                destination
            })
        )
    }

    fn decrypt_with_secret_key_using_iv_size(&mut self, secret_key: &ECDSAKey, public_key: &ECDSAKey, iv_size: usize) -> Result<Vec<u8>, KeyError> {
        if self.len() < iv_size {
            return Err(KeyError::WrongLength(self.len()));
        }
        ECDSAKey::secret_key_from_bytes(public_key.seckey.as_bytes())
            .and_then(|seckey| ECDSAKey::public_key_from_bytes(&ECDSAKey::public_key_from_secret_key_serialized(&seckey, false)))
            .map_err(KeyError::from)
            .map(|pubkey| secp256k1::ecdh::SharedSecret::new(&pubkey, &secret_key.secret_key().unwrap()))
            .and_then(|shared_secret|
                <Self as CryptoData<ECDSAKey>>::decrypt(self[iv_size..self.len()].to_vec(), shared_secret.secret_bytes(), &self[..iv_size]))
    }

    fn encrypt_with_dh_key_using_iv(&self, key: &ECDSAKey, initialization_vector: Vec<u8>) -> Result<Vec<u8>, KeyError> {
        let mut destination = initialization_vector.clone();
        let pubkey_data = key.public_key_from_inner_secret_key_serialized()
            .unwrap_or(key.public_key_data());
        // TODO: make it crash-safe
        if pubkey_data.is_empty() {
            Err(KeyError::DHKeyExchange)
        } else {
            match (<&[u8] as TryInto<[u8; 32]>>::try_into(&pubkey_data[..32]),
                   <Vec<u8> as TryInto<[u8; 16]>>::try_into(initialization_vector)) {
                (Ok(key_data), Ok(iv_data)) =>
                    <Self as CryptoData<ECDSAKey>>::encrypt(self, key_data, iv_data)
                        .map(|encrypted_data| {
                            destination.extend(encrypted_data);
                            destination
                        }),
                _ => Err(KeyError::DHKeyExchange)
            }
        }
    }

    fn decrypt_with_dh_key_using_iv_size(&self, key: &ECDSAKey, iv_size: usize) -> Result<Vec<u8>, KeyError> {
        key.public_key_from_inner_secret_key_serialized()
            .map_err(KeyError::from)
            .and_then(|sym_key_data| sym_key_data[..32].try_into().map_err(KeyError::from))
            .and_then(|key_data: [u8; 32]| self[..iv_size].try_into().map_err(KeyError::from)
                .and_then(|iv_data: [u8; 16]|
                    <Self as CryptoData<ECDSAKey>>::decrypt(self[iv_size..self.len()].to_vec(), key_data, iv_data)))
    }
}
