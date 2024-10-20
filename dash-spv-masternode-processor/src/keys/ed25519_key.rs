use byte::BytesExt;
use byte::ctx::Bytes;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use hashes::hex::{FromHex, ToHex};
use hashes::sha256;
use crate::crypto::byte_util::{AsBytes, ECPoint, UInt160, UInt256, UInt512, Zeroable};
use crate::chain::{derivation::IIndexPath, ScriptMap};
use crate::chain::derivation::IndexPath;
use crate::consensus::Encodable;
use crate::keys::{IKey, KeyKind, dip14::IChildKeyDerivation, KeyError, DeriveKey};
use crate::util::address::address;
use crate::util::base58;
use crate::util::sec_vec::SecVec;

// TODO: check we need to use ECPoint here
const EXT_PUBKEY_SIZE: usize = 4 + size_of::<UInt256>() + size_of::<UInt256>();

#[derive(Clone, Debug, Default)]
#[ferment_macro::opaque]
pub struct ED25519Key {
    pub seckey: UInt256,
    pub pubkey: Vec<u8>,
    pub chaincode: UInt256,
    pub fingerprint: u32,
    pub is_extended: bool,
}

#[ferment_macro::export]
impl ED25519Key {
    pub fn key_with_extended_public_key_data(bytes: &[u8]) -> Result<Self, KeyError> {
        match bytes.len() {
            // if len == 68 || len == 69 {
            68 => {
                let offset = &mut 0;
                let fingerprint = bytes.read_with::<u32>(offset, byte::LE)?;
                let chaincode = bytes.read_with::<UInt256>(offset, byte::LE)?;
                // if len == 69 {
                //     // skip 1st byte as pub key was padded with 0x00
                //     *offset += 1;
                // }
                let data: &[u8] = bytes.read_with(offset, Bytes::Len(32))?;
                Self::public_key_from_bytes(data)
                    .map_err(KeyError::from)
                    .map(|pubkey| Self::init_with_extended_public_parts(pubkey.as_bytes().to_vec(), chaincode, fingerprint))
            },
            len => Err(KeyError::WrongLength(len))
        }
    }
    pub fn key_with_extended_private_key_data(bytes: &[u8]) -> Result<Self, KeyError> {
        match bytes.len() {
            69 => {
                let offset = &mut 0;
                let fingerprint = bytes.read_with::<u32>(offset, byte::LE)?;
                let chaincode = bytes.read_with::<UInt256>(offset, byte::LE)?;
                let seckey = bytes.read_with::<UInt256>(offset, byte::LE)?;
                Ok(Self::init_with_extended_private_parts(seckey, chaincode, fingerprint))
            },
            len => Err(KeyError::WrongLength(len))
        }
    }
    pub fn key_with_private_key(string: &str) -> Result<Self, KeyError> {
        Vec::from_hex(string.as_bytes().to_hex().as_str())
            .map_err(KeyError::from)
            .and_then(|data| Self::key_with_secret_data(&data))
    }
    pub fn key_with_secret_data(data: &[u8]) -> Result<Self, KeyError> {
        Self::secret_key_from_bytes(data)
            .map_err(KeyError::from)
            .map(|seckey| Self { seckey: seckey.into(), ..Default::default() })
    }
    pub fn hash160(&self) -> UInt160 {
        UInt160::hash160(&self.public_key_data())
    }
}

#[ferment_macro::export]
impl IKey for ED25519Key {

    fn kind(&self) -> KeyKind {
        KeyKind::ED25519
    }

    fn secret_key_string(&self) -> String {
        self.seckey.0.to_hex()
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
        let signing_key: SigningKey = self.seckey.into();
        match signing_key.try_sign(data) {
            Ok(signature) => signature.to_vec(),
            Err(err) => {
                warn!("ED25519Key::sign::error {}", err);
                vec![]
            }
        }
    }

    fn verify(&mut self, message_digest: &[u8], signature: &[u8]) -> bool {
        // todo: check if this needed & correct
        Signature::from_slice(signature)
            .map_or(false, |s| SigningKey::from(self.seckey)
                .verifying_key()
                .verify(message_digest, &s)
                .is_ok())
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
        if !self.pubkey.is_empty() {
            self.pubkey.to_vec()
        } else {
            let signing_key: SigningKey = self.seckey.into();
            let public_key = signing_key.verifying_key();
            public_key.as_bytes().to_vec()
            // ECPoint::from(signing_key.verifying_key()).0.to_vec()
        }
    }

    fn extended_private_key_data(&self) -> Result<SecVec, KeyError> {
        match self.is_extended {
            true => self.private_key_data().map(|private_key_data| {
                // TODO: secure allocator
                let mut writer = SecVec::new();
                self.fingerprint.enc(&mut writer);
                self.chaincode.enc(&mut writer);
                writer.extend(private_key_data);
                writer
            }),
            extended => Err(KeyError::Extended(extended))
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
        let mut writer = SecVec::with_capacity(33);
        script.privkey.enc(&mut writer);
        self.seckey.enc(&mut writer);
        // todo: should we add additional byte here ?
        // if self.compressed {
        //     b'\x01'.enc(&mut writer);
        // }
        base58::check_encode_slice(&writer)
    }

    fn hmac_256_data(&self, data: &[u8]) -> UInt256 {
        UInt256::hmac::<sha256::Hash>(self.seckey.as_bytes(), data)
    }

    fn forget_private_key(&mut self) {
        if self.pubkey.is_empty() && !self.seckey.is_zero() {
            let signing_key: SigningKey = self.seckey.into();
            let public_key = signing_key.verifying_key();
            self.pubkey = public_key.as_bytes().to_vec();
        }
        self.seckey = UInt256::MIN;
    }

    fn sign_message_digest(&self, digest: UInt256) -> Vec<u8> {
        self.sign(&digest.0)
    }
    fn private_key_data_equal_to(&self, other_private_key_data: &[u8; 32]) -> bool {

        self.seckey.0.eq(other_private_key_data)
    }

    fn public_key_data_equal_to(&self, other_public_key_data: &Vec<u8>) -> bool {
        self.public_key_data().eq(other_public_key_data)
    }
}

impl DeriveKey<IndexPath<u32>> for ED25519Key {
    fn private_derive_to_path(&self, path: &IndexPath<u32>) -> Result<Self, KeyError> {
        let mut signing_key: SigningKey = self.seckey.into();
        let mut chaincode = self.chaincode.clone();
        let mut fingerprint = 0u32;
        let length = path.length();
        (0..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    fingerprint = UInt160::hash160u32le(ECPoint::from(signing_key.verifying_key()).as_bytes());
                }
                Self::derive_child_private_key(&mut signing_key, &mut chaincode, path, position);
            });
        Ok(Self::init_with_extended_private_parts(signing_key.into(), chaincode, fingerprint))
    }

    fn public_derive_to_path_with_offset(&mut self, path: &IndexPath<u32>, offset: usize) -> Result<Self, KeyError> {
        unimplemented!()
    }
}

impl DeriveKey<IndexPath<UInt256>> for ED25519Key {
    fn private_derive_to_path(&self, path: &IndexPath<UInt256>) -> Result<Self, KeyError> {
        let mut signing_key: SigningKey = self.seckey.into();
        let mut chaincode = self.chaincode.clone();
        let mut fingerprint = 0u32;
        let length = path.length();
        (0..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    fingerprint = UInt160::hash160u32le(ECPoint::from(signing_key.verifying_key()).as_bytes());
                }
                Self::derive_child_private_key(&mut signing_key, &mut chaincode, path, position);
            });
        Ok(Self::init_with_extended_private_parts(signing_key.into(), chaincode, fingerprint))
    }

    fn public_derive_to_path_with_offset(&mut self, path: &IndexPath<UInt256>, offset: usize) -> Result<Self, KeyError> {
        let mut chaincode = self.chaincode.clone();
        let mut data = UInt256::from(&self.public_key_data());
        let mut fingerprint = 0u32;
        let length = path.length();
        (offset..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    fingerprint = UInt160::hash160u32le(ECPoint::from(data.as_bytes()).as_bytes());
                }
                Self::derive_child_public_key(&mut data, &mut chaincode, path, position);
            });
        Ok(Self::init_with_extended_public_parts(data.0.to_vec(), chaincode, fingerprint))
    }
}

impl ED25519Key {

    pub fn init_with_seed_data(seed: &[u8]) -> Result<Self, KeyError> {
        let i = UInt512::ed25519_seed_key(seed);
        Ok(Self { seckey: UInt256::from(&i.0[..32]), chaincode: UInt256::from(&i.0[32..]), ..Default::default() })
    }

    fn init_with_extended_private_parts(seckey: UInt256, chaincode: UInt256, fingerprint: u32) -> Self {
        Self { fingerprint, chaincode, seckey, is_extended: true, ..Default::default() }
    }

    fn init_with_extended_public_parts(pubkey: Vec<u8>, chaincode: UInt256, fingerprint: u32) -> Self {
        Self { fingerprint, chaincode, pubkey, is_extended: true, ..Default::default() }
    }

    pub fn init_with_extended_private_key_data(data: &Vec<u8>) -> Result<Self, KeyError> {
        Self::key_with_extended_private_key_data(data)
    }

    pub fn init_with_extended_public_key_data(data: &Vec<u8>) -> Result<Self, KeyError> {
        Self::key_with_extended_public_key_data(data)
    }


    pub fn public_key_from_bytes(data: &[u8]) -> Result<VerifyingKey, SignatureError> {
        VerifyingKey::try_from(data)
    }

    pub fn secret_key_from_bytes(data: &[u8]) -> Result<SigningKey, SignatureError> {
        SigningKey::try_from(data)
    }

    pub fn key_with_public_key_data(data: &[u8]) -> Result<Self, KeyError> {
        assert!(!data.is_empty());
        // TODO: if we follow SLIP-0010 then we have 33-bytes, and need to cut off 1st byte (0x00)
        // TODO: if we follow IETF then we must ensure length == 32 bytes
        match data.len() {
            32 => Self::public_key_from_bytes(data).map_err(KeyError::from),
            33 => Self::public_key_from_bytes(&data[1..]).map_err(KeyError::from),
            len => Err(KeyError::WrongLength(len))
        }.map(|pk| Self { pubkey: pk.to_bytes().to_vec(), ..Default::default() })
    }

    pub fn public_key_from_extended_public_key_data<PATH>(data: &[u8], path: &PATH) -> Result<Vec<u8>, KeyError>
        where PATH: IIndexPath<Item = u32> {
        if data.len() < EXT_PUBKEY_SIZE {
            assert!(false, "Extended public key is wrong size");
            return Err(KeyError::WrongLength(data.len()));
        }
        let mut chaincode = UInt256::from(&data[4..36]);
        let mut key = UInt256::from(&data[36..68]);
        (0..path.length())
            .into_iter()
            .for_each(|position| Self::derive_child_public_key(&mut key, &mut chaincode, path, position));
        Ok(key.as_bytes().to_vec())
    }
}


/// For FFI
impl ED25519Key {


    pub fn public_key_from_extended_public_key_data_at_index_path<PATH>(key: &Self, index_path: &PATH) -> Result<Self, KeyError>
        where Self: Sized, PATH: IIndexPath<Item=u32> {
        key.extended_public_key_data()
            .and_then(|ext_pk_data| Self::public_key_from_extended_public_key_data(&ext_pk_data, index_path))
            .and_then(|pub_key_data| Self::key_with_public_key_data(&pub_key_data))
    }



}
