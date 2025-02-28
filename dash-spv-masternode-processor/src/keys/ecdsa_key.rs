use std::mem;
use byte::BytesExt;
use byte::ctx::Bytes;
use hashes::sha256;
use hashes::hex::{FromHex, ToHex};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::Secp256k1;
use logging::*;
use tracing::*;
use crate::chain::bip::bip32;
use crate::chain::common::ChainType;
use crate::chain::derivation::{BIP32_HARD, IIndexPath, IndexPath};
use crate::chain::params::ScriptMap;
use crate::consensus::Encodable;
use crate::crypto::{ECPoint, UInt160, UInt256, UInt512, byte_util::{AsBytes, Zeroable}};
use crate::keys::{IKey, KeyKind, dip14::{IChildKeyDerivation, SignKey}};
use crate::keys::crypto_data::{CryptoData, DHKey};
use crate::util::address::address::is_valid_dash_private_key;
use crate::util::base58;
use crate::util::sec_vec::SecVec;

const EXT_PUBKEY_SIZE: usize = 4 + mem::size_of::<UInt256>() + mem::size_of::<ECPoint>();

#[derive(Clone, Debug, Default)]
pub struct ECDSAKey {
    pub seckey: UInt256,
    pub pubkey: Vec<u8>,
    pub compressed: bool,
    pub chaincode: UInt256,
    pub fingerprint: u32,
    pub is_extended: bool,
}

/// Shorthands
impl ECDSAKey {
    pub fn public_key_data_from_seed(seed: &[u8], compressed: bool) -> Option<Vec<u8>> {
        Self::secret_key_from_bytes(seed)
            .ok()
            .map(|secret_key|
                Self::public_key_from_secret_key_serialized(&secret_key, compressed))
    }

    pub fn key_with_secret(secret: &UInt256, compressed: bool) -> Option<Self> {
        Self::secret_key_from_bytes(secret.as_bytes())
            .ok()
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }
    pub fn key_with_combined_secret(data: &UInt512, compressed: bool) -> Option<Self> {
        Self::secret_key_from_bytes(&data.0[..32])
            .ok()
            .map(|seckey| Self::with_seckey_and_chaincode(seckey, UInt256::from(&data.0[32..]), compressed))
    }
    pub fn key_with_secret_data(data: &[u8], compressed: bool) -> Option<Self> {
        Self::secret_key_from_bytes(data)
            .ok()
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }
    pub fn key_with_secret_hex(string: &str, compressed: bool) -> Option<Self> {
        Vec::from_hex(string)
            .ok()
            .and_then(|data| Self::key_with_secret_data(&data, compressed))
    }

    pub fn key_recovered_from_compact_sig(compact_sig: &[u8], message_digest: UInt256) -> Option<Self> {
        Self::init_with_compact_sig(compact_sig, message_digest)
    }

    pub fn key_with_private_key(private_key_string: &str, chain_type: ChainType) -> Option<Self> {
        Self::init_with_private_key(private_key_string, chain_type)
    }

    pub fn key_with_public_key_data(data: &[u8]) -> Option<Self> {
        assert!(!data.is_empty());
        match data.len() {
            33 | 65 => Self::public_key_from_bytes(data).map(|pubkey| Self::with_pubkey_compressed(pubkey, data.len() == 33)).ok(),
            _ => None
        }
    }

    pub fn init_with_compact_sig(compact_sig: &[u8], message_digest: UInt256) -> Option<ECDSAKey> {
        // assert!(compact_sig, "ECDSAKey::init_with_compact_sig {null}");
        if compact_sig.len() != 65 {
            return None;
        }
        let compressed = compact_sig[0] - 27 >= 4;
        let recid = RecoveryId::from_i32(((compact_sig[0] - 27) % 4) as i32).unwrap();
        RecoverableSignature::from_compact(&compact_sig[1..], recid)
            .and_then(|sig| Secp256k1::new().recover_ecdsa(&secp256k1::Message::from(message_digest), &sig)
                .map(|pk| Self::with_pubkey_compressed(pk, compressed)))
            .ok()
    }

    pub fn init_with_seed_data(seed: &[u8]) -> Option<Self> {
        let i = UInt512::bip32_seed_key(seed);
        Self::secret_key_from_bytes(&i.0[..32])
            .ok()
            .map(|seckey| Self::with_seckey_and_chaincode(seckey, UInt256::from(&i.0[32..]), true))
    }

    pub fn init_with_secret(secret: UInt256, compressed: bool) -> Option<Self> {
        Self::secret_key_from_bytes(secret.as_bytes())
            .ok()
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }

    pub fn init_with_extended_private_key_data(data: &Vec<u8>) -> Option<Self> {
        // assert_eq!(data.len(), ECDSA_EXTENDED_SECRET_KEY_SIZE, "Key size is incorrect");
        Self::init_with_secret(data.read_with::<UInt256>(&mut 36, byte::LE).unwrap(), true)
            .map(|s| Self::update_extended_params(s, data))
    }

    pub fn init_with_extended_public_key_data(data: &Vec<u8>) -> Option<Self> {
        Self::init_with_public_key(data[36..].to_vec())
            .map(|s| Self::update_extended_params(s, data))
    }

    pub fn init_with_private_key(private_key: &str, chain_type: ChainType) -> Option<Self> {
        match private_key.len() {
            0 => None,
            // mini private key format
            22 | 30 if private_key.starts_with('L') =>
                is_valid_dash_private_key(&private_key.to_string(), &chain_type.script_map())
                    .then_some(Self::with_seckey(secp256k1::SecretKey::from_hashed_data::<sha256::Hash>(private_key.as_bytes()), false)),
            _ => {
                let mut d = base58::from_check(private_key).ok();
                if d.is_none() || d.as_ref().unwrap().len() == 28 {
                    d = base58::from(private_key).ok();
                }
                if d.as_ref().is_none() || !(32..=34).contains(&d.as_ref().unwrap().len()) {
                    d = Vec::from_hex(private_key).ok();
                }
                if d.as_ref().is_none() {
                    return None;
                }
                let data = d.unwrap();
                match data.len() {
                    33 | 34 if data[0] == chain_type.script_map().privkey =>
                        Self::secret_key_from_bytes(&data[1..33]).ok().map(|seckey| Self::with_seckey(seckey, data.len() == 34)),
                    32 =>
                        Self::secret_key_from_bytes(&data[..]).ok().map(|seckey| Self::with_seckey(seckey, false)),
                    _ =>
                        None
                }
            }
        }
    }

    pub fn init_with_public_key(public_key: Vec<u8>) -> Option<Self> {
        assert!(!public_key.is_empty(), "public_key is empty");
        if public_key.len() != 33 && public_key.len() != 65 {
            None
        } else {
            Self::public_key_from_bytes(&public_key)
                .ok()
                .map(|pubkey| Self::with_pubkey_compressed(pubkey, public_key.len() == 33))
        }
    }

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

    pub fn message_from_bytes(data: &[u8]) -> Result<secp256k1::Message, secp256k1::Error> {
        secp256k1::Message::from_slice(data)
    }

    pub fn public_key_from_bytes(data: &[u8]) -> Result<secp256k1::PublicKey, secp256k1::Error> {
        secp256k1::PublicKey::from_slice(data)
    }

    pub fn secret_key_from_bytes(data: &[u8]) -> Result<secp256k1::SecretKey, secp256k1::Error> {
        secp256k1::SecretKey::from_slice(data)
    }

    pub fn public_key(&self) -> Result<secp256k1::PublicKey, secp256k1::Error> {
        Self::public_key_from_bytes(&self.pubkey)
    }

    pub fn secret_key(&self) -> Result<secp256k1::SecretKey, secp256k1::Error> {
        Self::secret_key_from_bytes(self.seckey.as_bytes())
    }

    pub fn secret_key_string(&self) -> String {
        if self.has_private_key() {
            self.seckey.0.to_hex()
        } else {
            String::new()
        }
    }

    pub fn public_key_from_inner_secret_key_serialized(&self) -> Option<Vec<u8>> {
        self.secret_key().ok().map(|seckey| Self::public_key_from_secret_key_serialized(&seckey, self.compressed))
    }

    pub fn public_key_from_secret_key_serialized(secret_key: &secp256k1::SecretKey, compressed: bool) -> Vec<u8> {
        let pubkey = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
        if compressed {
            pubkey.serialize().to_vec()
        } else {
            pubkey.serialize_uncompressed().to_vec()
        }
    }

    pub fn has_private_key(&self) -> bool {
        !self.seckey.is_zero()
    }

    fn private_derive_to_256bit_derivation_path_for_seckey_and_chaincode<PATH>(seckey: UInt256, chaincode: UInt256, path: &PATH) -> Option<Self>
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
        Some(Self { seckey, chaincode, fingerprint, is_extended: true, compressed: true, ..Default::default() })

    }

}

impl IKey for ECDSAKey {
    // type SK = UInt256;

    fn r#type(&self) -> KeyKind {
        KeyKind::ECDSA
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        if self.seckey.is_zero() {
            log_warn!(target: "masternode-processor", "There is no seckey for sign");
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

    fn private_key_data(&self) -> Option<Vec<u8>> {
        (!self.seckey.is_zero())
            .then_some(self.seckey.0.to_vec())
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

    fn extended_private_key_data(&self) -> Option<SecVec> {
        if !self.is_extended {
            None
        } else if let Some(private_key_data) = self.private_key_data() {
            // TODO: secure data
            //NSMutableData *data = [NSMutableData secureData];
            let mut writer = SecVec::new();
            self.fingerprint.enc(&mut writer);
            self.chaincode.enc(&mut writer);
            writer.extend(private_key_data);
            // private_key_data.enc(&mut writer);
            Some(writer)
        } else {
            None
        }
    }

    fn extended_public_key_data(&self) -> Option<Vec<u8>> {
        self.is_extended.then_some({
            let mut writer = Vec::<u8>::new();
            self.fingerprint.enc(&mut writer);
            self.chaincode.enc(&mut writer);
            writer.extend(self.public_key_data());
            writer
        })
    }

    fn private_derive_to_path2<SK, PK, PATH, INDEX>(&self, path: &PATH) -> Option<Self>
        where Self: Sized + IChildKeyDerivation<INDEX, SK, PK>,
              PATH: IIndexPath<Item=INDEX>, SK: SignKey {
        todo!()
    }

    fn private_derive_to_path<PATH>(&self, path: &PATH) -> Option<Self>
        where Self: Sized, PATH: IIndexPath<Item = u32> {
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
        Some(Self { seckey, chaincode, fingerprint, is_extended: true, compressed: true, ..Default::default() })
    }

    // fn private_derive_to_path2<PATH, INDEX>(&self, path: &PATH) -> Option<Self> where Self: Sized, PATH: IIndexPath<Item=INDEX> {
    //     todo!()
        // let mut seckey = self.seckey.clone();
        // let mut chaincode = self.chaincode.clone();
        // let mut fingerprint = 0u32;
        // let length = path.length();
        // (0..length)
        //     .into_iter()
        //     .for_each(|position| {
        //         if position + 1 == length {
        //             fingerprint = secp256k1::SecretKey::from_slice(&seckey.0)
        //                 .map(|sk| secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk))
        //                 .map(|pk| UInt160::hash160(&pk.serialize()).u32_le())
        //                 .unwrap_or(0);
        //         }
        //         Self::derive_child_private_key(&mut seckey, &mut chaincode, path, position)
        //     });
        // Some(Self { seckey, chaincode, fingerprint, is_extended: true, compressed: true, ..Default::default() })
    // }

    fn private_derive_to_256bit_derivation_path<PATH>(&self, path: &PATH) -> Option<Self>
        where Self: Sized, PATH: IIndexPath<Item = UInt256> {
        Self::private_derive_to_256bit_derivation_path_for_seckey_and_chaincode(self.seckey, self.chaincode, path)
    }

    fn public_derive_to_256bit_derivation_path_with_offset<PATH>(&mut self, path: &PATH, offset: usize) -> Option<Self>
        where Self: Sized, PATH: IIndexPath<Item = UInt256> {
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
            Some(child_key)
        } else {
            assert!(false, "Public key should be created");
            None
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

    /// Pieter Wuille's compact signature encoding used for bitcoin message signing
    /// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
    pub fn compact_sign(&self, message_digest: UInt256) -> [u8; 65] {
        let mut sig = [0u8; 65];
        if self.seckey.is_zero() {
            log_warn!(target: "masternode-processor", "Can't sign with a public key");
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

    pub fn hash160(&self) -> UInt160 {
        UInt160::hash160(&self.public_key_data())
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

    pub fn public_key_from_extended_public_key_data<PATH>(data: &[u8], path: &PATH) -> Option<Vec<u8>>
        where PATH: IIndexPath<Item = u32> {
        if data.len() < EXT_PUBKEY_SIZE {
            assert!(false, "Extended public key is wrong size");
            return None;
        }
        let mut c = UInt256::from(&data[4..36]);
        let mut k = ECPoint::from(&data[36..69]);
        (0..path.length())
            .into_iter()
            .for_each(|position| Self::derive_child_public_key(&mut k, &mut c, path, position));
        Some(k.as_bytes().to_vec())
    }

    // pub fn encrypt_data_for_public_key(&self, secret: &str, mut public_key: Self, initialization_vector: &str) -> Vec<u8> {
    //     let key = Self::init_with_dh_key_exchange_with_public_key(public_key, self);
    //     // DSECDSAKey *key = [DSECDSAKey keyWithDHKeyExchangeWithPublicKey:peerPubKey forPrivateKey:secretKey];
    //
    //     // return [self encryptWithDHECDSAKey:key usingInitializationVector:initializationVector];
    //
    // }

    // pub fn encrypt_with_dh_key(&self, dh_key: Self, initialization_vector: &Vec<u8>) -> Vec<u8> {
    //
    //     // unsigned char *iv = (unsigned char *)initializationVector.bytes;
    //     //
    //     // NSData *resultData = AES256EncryptDecrypt(kCCEncrypt, self, (uint8_t *)dhKey.publicKeyData.bytes, initializationVector.length ? iv : 0);
    //     //
    //     // NSMutableData *finalData = [initializationVector mutableCopy];
    //     // [finalData appendData:resultData];
    //     // return finalData;
    //
    // }

    // pub fn key_with_dh_key_exchange_with_public_key(public_key: &Self, private_key: &Self) -> Option<Self> {
    //     private_key.secret_key()
    //         .and_then(|seckey| ECDSAKey::public_key_from_bytes(&ECDSAKey::public_key_from_secret_key_serialized(&seckey, false))
    //             .map(|pubkey| ECDSAKey::with_shared_secret(secp256k1::ecdh::SharedSecret::new(&pubkey, &seckey), false)))
    //         .ok()
    // }
}

/// For FFI
impl ECDSAKey {

    pub fn public_key_from_extended_public_key_data_at_index_path<PATH>(key: &Self, index_path: &PATH) -> Option<Self> where Self: Sized, PATH: IIndexPath<Item=u32> {
        key.extended_public_key_data()
            .and_then(|ext_pk_data| Self::public_key_from_extended_public_key_data(&ext_pk_data, index_path))
            .and_then(|pub_key_data| Self::key_with_public_key_data(&pub_key_data))
    }

    pub fn key_with_extended_public_key_data(bytes: &[u8]) -> Option<Self> {
        let len = bytes.len();
        if len == 69 || len == 101 {
            let offset = &mut 0;
            let fingerprint = bytes.read_with::<u32>(offset, byte::LE).unwrap();
            let chaincode = bytes.read_with::<UInt256>(offset, byte::LE).unwrap();
            let pubkeydata: &[u8] = bytes.read_with(offset, Bytes::Len(len - *offset)).unwrap();
            let compressed = pubkeydata.len() == 33;
            Self::public_key_from_bytes(pubkeydata).ok().map(|pubkey| {
                Self {
                    fingerprint,
                    chaincode,
                    compressed,
                    pubkey: if compressed { pubkey.serialize().to_vec() } else { pubkey.serialize_uncompressed().to_vec() },
                    is_extended: true,
                    ..Default::default() }
            })
        } else {
            None
        }
    }

    pub fn key_with_extended_private_key_data(bytes: &[u8]) -> Option<Self> {
        Self::init_with_secret(bytes.read_with::<UInt256>(&mut 36, byte::LE).unwrap(), true)
            .map(|key| Self::update_extended_params(key, bytes))
    }

    pub fn key_with_compact_sig(compact_sig: &[u8], message_digest: UInt256) -> Option<ECDSAKey> {
        if compact_sig.len() != 65 {
            return None;
        }
        RecoveryId::from_i32(((compact_sig[0] - 27) % 4) as i32)
            .and_then(|recid| RecoverableSignature::from_compact(&compact_sig[1..], recid)
                .and_then(|sig| Secp256k1::new()
                    .recover_ecdsa(&secp256k1::Message::from(message_digest), &sig)
                    .map(|pubkey| ECDSAKey::with_pubkey_compressed(pubkey, compact_sig[0] - 27 >= 4))))
            .ok()
    }


    pub fn serialized_extended_private_key_from_seed(seed: &[u8], index_path: IndexPath<UInt256>, chain_type: ChainType) -> Option<String> {
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
    fn init_with_dh_key_exchange_with_public_key(public_key: &mut Self, private_key: &Self) -> Option<Self> where Self: Sized {
        match (Self::public_key_from_bytes(&public_key.public_key_data()),
               Self::secret_key_from_bytes(private_key.seckey.as_bytes())) {
            (Ok(pubkey), Ok(seckey)) => Some(Self::with_shared_secret(secp256k1::ecdh::SharedSecret::new(&pubkey, &seckey), false)),
            _ => None
        }
    }
}

impl CryptoData<ECDSAKey> for Vec<u8> {
    fn encrypt_with_secret_key_using_iv(&mut self, secret_key: &ECDSAKey, public_key: &ECDSAKey, initialization_vector: Vec<u8>) -> Option<Vec<u8>> {
        let mut destination = initialization_vector.clone();
        ECDSAKey::secret_key_from_bytes(public_key.seckey.as_bytes())
            .and_then(|seckey| ECDSAKey::public_key_from_bytes(&ECDSAKey::public_key_from_secret_key_serialized(&seckey, false)))
            .map(|pubkey| secp256k1::ecdh::SharedSecret::new(&pubkey, &secret_key.secret_key().unwrap()))
            .ok()
            .and_then(|shared_secret| <Self as CryptoData<ECDSAKey>>::encrypt(self, shared_secret.secret_bytes(), initialization_vector))
            .map(|encrypted_data| {
                destination.extend(encrypted_data);
                destination
            })
    }

    fn decrypt_with_secret_key_using_iv_size(&mut self, secret_key: &ECDSAKey, public_key: &ECDSAKey, iv_size: usize) -> Option<Vec<u8>> {
        if self.len() < iv_size {
            return None;
        }
        ECDSAKey::secret_key_from_bytes(public_key.seckey.as_bytes())
            .and_then(|seckey| ECDSAKey::public_key_from_bytes(&ECDSAKey::public_key_from_secret_key_serialized(&seckey, false)))
            .map(|pubkey| secp256k1::ecdh::SharedSecret::new(&pubkey, &secret_key.secret_key().unwrap()))
            .ok()
            .and_then(|shared_secret|
                <Self as CryptoData<ECDSAKey>>::decrypt(self[iv_size..self.len()].to_vec(), shared_secret.secret_bytes(), &self[..iv_size]))
    }

    fn encrypt_with_dh_key_using_iv(&self, key: &ECDSAKey, initialization_vector: Vec<u8>) -> Option<Vec<u8>> {
        let mut destination = initialization_vector.clone();
        let pubkey_data = key.public_key_from_inner_secret_key_serialized().unwrap_or(key.public_key_data());
        if pubkey_data.is_empty() {
            None
        } else {
            pubkey_data[..32].try_into().ok()
                .and_then(|key_data: [u8; 32]| initialization_vector.try_into().ok()
                    .and_then(|iv_data: [u8; 16]| <Self as CryptoData<ECDSAKey>>::encrypt(self, key_data, iv_data))
                    .map(|encrypted_data| {
                        destination.extend(encrypted_data);
                        destination
                    }))
        }


        // key.public_key()
        //     .ok()
        //     .map(|pubk| if key.compressed { pubk.serialize().to_vec() } else { pubk.serialize_uncompressed().to_vec() })
        //     // .or(key.public_key_from_inner_secret_key_serialized())
        //     .and_then(|sym_key_data| sym_key_data[..32].try_into().ok())
        //     .and_then(|key_data: [u8; 32]| initialization_vector.try_into().ok()
        //         .and_then(|iv_data: [u8; 16]| <Self as CryptoData<ECDSAKey>>::encrypt(self, key_data, iv_data))
        //         .map(|encrypted_data| {
        //             destination.extend(encrypted_data);
        //             destination
        //         }))
    }

    fn decrypt_with_dh_key_using_iv_size(&self, key: &ECDSAKey, iv_size: usize) -> Option<Vec<u8>> {
        key.public_key_from_inner_secret_key_serialized()
            .and_then(|sym_key_data| sym_key_data[..32].try_into().ok())
            .and_then(|key_data: [u8; 32]| self[..iv_size].try_into().ok()
                .and_then(|iv_data: [u8; 16]|
                    <Self as CryptoData<ECDSAKey>>::decrypt(self[iv_size..self.len()].to_vec(), key_data, iv_data)))
    }
}

