use std::mem;
use byte::BytesExt;
use byte::ctx::Bytes;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use hashes::hex::{FromHex, ToHex};
use hashes::sha256;
use crate::crypto::{UInt160, UInt256, UInt512, byte_util::{AsBytes, Zeroable}};
use crate::chain::{derivation::IIndexPath, ScriptMap};
use crate::consensus::Encodable;
use crate::keys::{IKey, KeyKind, dip14::{IChildKeyDerivation, IChildKeyDerivationData}};
use crate::util::base58;
use crate::util::sec_vec::SecVec;

// TODO: check we need to use ECPoint here
// const EXT_PUBKEY_SIZE: usize = 4 + mem::size_of::<UInt256>() + mem::size_of::<ECPoint>();
const EXT_PUBKEY_SIZE: usize = 4 + mem::size_of::<UInt256>() + mem::size_of::<UInt256>();

#[derive(Clone, Debug, Default)]
pub struct ED25519Key {
    pub seckey: UInt256,
    pub pubkey: Vec<u8>,
    pub compressed: bool,
    pub chaincode: UInt256,
    pub fingerprint: u32,
    pub is_extended: bool,
}

impl IKey for ED25519Key
    where Self: IChildKeyDerivationData<u32, SigningKey, UInt256> + IChildKeyDerivationData<UInt256, SigningKey, UInt256> {

    fn r#type(&self) -> KeyKind {
        KeyKind::ED25519
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        if self.seckey.is_zero() {
            warn!("There is no seckey for sign");
            return vec![];
        }
        let signing_key = SigningKey::from_bytes(&self.seckey.0);
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
            .map_or(false, |s| SigningKey::from_bytes(&self.seckey.0)
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

    fn private_key_data(&self) -> Option<Vec<u8>> {
        (!self.seckey.is_zero())
            .then_some(self.seckey.0.to_vec())
    }

    fn public_key_data(&self) -> Vec<u8> {
        if !self.pubkey.is_empty() {
            self.pubkey.to_vec()
        } else {
            let signing_key = SigningKey::from_bytes(&self.seckey.0);
            let public_key = VerifyingKey::from(&signing_key);
            public_key.as_bytes().to_vec()
            // ECPoint::from(signing_key.verifying_key()).0.to_vec()
        }
    }

    fn extended_private_key_data(&self) -> Option<SecVec> {
        if !self.is_extended {
            None
        } else if let Some(private_key_data) = self.private_key_data() {
            // TODO: secure allocator
            let mut writer = SecVec::new();
            self.fingerprint.enc(&mut writer);
            self.chaincode.enc(&mut writer);
            writer.extend(private_key_data);
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

    // fn private_derive_to_path2<SK, PK, PATH, INDEX>(&self, path: &PATH) -> Option<Self>
    //     where Self: Sized + IChildKeyDerivation<INDEX, SK, PK>,
    //           PATH: IIndexPath<Item=INDEX>, SK: SignKey {
    //     // todo!()
    //     let mut signing_key = SigningKey::from_bytes(&self.seckey.0);
    //     let mut chaincode = self.chaincode.clone();
    //     let mut fingerprint = 0u32;
    //     let length = path.length();
    //     (0..length)
    //         .into_iter()
    //         .for_each(|position| {
    //             if position + 1 == length {
    //                 fingerprint = UInt160::hash160(ECPoint::from(signing_key.verifying_key()).as_ref()).u32_le();
    //             }
    //             <Self as IChildKeyDerivation<INDEX, SigningKey, ECPoint>>::derive_child_private_key::<PATH>(&mut signing_key, &mut chaincode, path, position);
    //         });
    //     Some(Self {
    //         seckey: UInt256(signing_key.to_bytes()),
    //         chaincode,
    //         fingerprint,
    //         is_extended: true,
    //         compressed: true,
    //         ..Default::default()
    //     })
    // }

    fn private_derive_to_path<PATH>(&self, path: &PATH) -> Option<Self>
        where Self: Sized, PATH: IIndexPath<Item = u32> {
        let mut signing_key = SigningKey::from_bytes(&self.seckey.0);
        let mut chaincode = self.chaincode.clone();
        let mut fingerprint = 0u32;
        let length = path.length();
        (0..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    // fingerprint = UInt160::hash160(ECPoint::from(signing_key.verifying_key()).as_ref()).u32_le();
                    fingerprint = UInt160::hash160(UInt256::from(signing_key.verifying_key()).as_ref()).u32_le();
                }
                Self::derive_child_private_key(&mut signing_key, &mut chaincode, path, position);
            });
        Some(Self {
            seckey: UInt256(signing_key.to_bytes()),
            chaincode,
            fingerprint,
            is_extended: true,
            compressed: true,
            ..Default::default()
        })
    }

    fn private_derive_to_256bit_derivation_path<PATH>(&self, path: &PATH) -> Option<Self>
        where Self: Sized, PATH: IIndexPath<Item=UInt256> {
        let mut signing_key = SigningKey::from_bytes(&self.seckey.0);
        let mut chaincode = self.chaincode.clone();
        let mut fingerprint = 0u32;
        let length = path.length();
        (0..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    fingerprint = UInt160::hash160(UInt256::from(signing_key.verifying_key()).as_ref()).u32_le();
                }
                Self::derive_child_private_key(&mut signing_key, &mut chaincode, path, position);
        });
        Some(Self {
            seckey: UInt256(signing_key.to_bytes()),
            chaincode,
            fingerprint,
            is_extended: true,
            compressed: true,
            ..Default::default()
        })
    }

    fn public_derive_to_256bit_derivation_path_with_offset<PATH>(&mut self, path: &PATH, offset: usize) -> Option<Self>
        where Self: Sized, PATH: IIndexPath<Item=UInt256> {
        let mut chaincode = self.chaincode.clone();
        // let mut data = ECPoint::from(&self.public_key_data());
        let mut data = UInt256::from(&self.public_key_data());
        let mut fingerprint = 0u32;
        let length = path.length();
        (offset..length)
            .into_iter()
            .for_each(|position| {
                if position + 1 == length {
                    fingerprint = UInt160::hash160(data.as_ref()).u32_le();
                }
                Self::derive_child_public_key(&mut data, &mut chaincode, path, position);
            });
        Some(Self { pubkey: data.0.to_vec(), chaincode, fingerprint, is_extended: true, ..Default::default() })
    }

    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String {
        //if (uint256_is_zero(_seckey)) return nil;
        //NSMutableData *d = [NSMutableData secureDataWithCapacity:sizeof(UInt256) + 2];
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
            let signing_key = SigningKey::from_bytes(&self.seckey.0);
            let public_key = VerifyingKey::from(&signing_key);
            // self.pubkey = ECPoint::from(public_key).0.to_vec();
            self.pubkey = public_key.as_bytes().to_vec();
        }
        self.seckey = UInt256::MIN;
    }
}

impl ED25519Key {

    pub fn init_with_seed_data(seed: &[u8]) -> Option<Self> {
        let i = UInt512::ed25519_seed_key(seed);
        Some(Self {
            seckey: UInt256::from(&i.0[..32]),
            chaincode: UInt256::from(&i.0[32..]),
            compressed: true,
            ..Default::default() })
    }

    pub fn init_with_extended_private_key_data(data: &Vec<u8>) -> Option<Self> {
        todo!()
    }

    pub fn init_with_extended_public_key_data(data: &Vec<u8>) -> Option<Self> {
        todo!()
    }

    pub fn key_with_secret_data(data: &[u8], compressed: bool) -> Option<Self> {
        Self::secret_key_from_bytes(data)
            .ok()
            .map(|seckey| Self { seckey: UInt256(seckey.to_bytes()), compressed, ..Default::default() })
    }

    pub fn public_key_from_bytes(data: &[u8]) -> Result<VerifyingKey, SignatureError> {
        VerifyingKey::try_from(data)
    }

    pub fn secret_key_from_bytes(data: &[u8]) -> Result<SigningKey, SignatureError> {
        SigningKey::try_from(data)
    }

    pub fn key_with_public_key_data(data: &[u8]) -> Option<Self> {
        assert!(!data.is_empty());
        // TODO: if we follow SLIP-0010 then we have 33-bytes, and need to cut off 1st byte (0x00)
        // TODO: if we follow IETF then we must ensure length == 32 bytes
        match data.len() {
            32 => Self::public_key_from_bytes(data).ok(),
            33 => Self::public_key_from_bytes(&data[1..]).ok(),
            _ => None
        }.map(|pk| Self { pubkey: pk.to_bytes().to_vec(), compressed: true, ..Default::default() })
    }

    pub fn public_key_from_extended_public_key_data<PATH>(data: &[u8], path: &PATH) -> Option<Vec<u8>>
        where PATH: IIndexPath<Item = u32> {
        if data.len() < EXT_PUBKEY_SIZE {
            assert!(false, "Extended public key is wrong size");
            return None;
        }
        let mut c = UInt256::from(&data[4..36]);
        // let mut k = ECPoint::from(&data[36..69]);
        let mut k = UInt256::from(&data[36..68]);
        (0..path.length())
            .into_iter()
            .for_each(|position|
                Self::derive_child_public_key(&mut k, &mut c, path, position)
            );
        Some(k.as_bytes().to_vec())
    }
}

/// For FFI
impl ED25519Key {

    pub fn key_with_private_key(string: &str) -> Option<Self> {
        Vec::from_hex(string.as_bytes().to_hex().as_str())
            .ok()
            .and_then(|data| Self::key_with_secret_data(&data, false))
    }

    pub fn public_key_from_extended_public_key_data_at_index_path<PATH>(key: &Self, index_path: &PATH) -> Option<Self> where Self: Sized, PATH: IIndexPath<Item=u32> {
        key.extended_public_key_data()
            .and_then(|ext_pk_data| Self::public_key_from_extended_public_key_data(&ext_pk_data, index_path))
            .and_then(|pub_key_data| Self::key_with_public_key_data(&pub_key_data))
    }


    pub fn key_with_extended_public_key_data(bytes: &[u8]) -> Option<Self> {
        let len = bytes.len();
        // if len == 68 || len == 69 {
        if len == 68 {
            let offset = &mut 0;
            let fingerprint = bytes.read_with::<u32>(offset, byte::LE).unwrap();
            let chaincode = bytes.read_with::<UInt256>(offset, byte::LE).unwrap();
            // if len == 69 {
            //     // skip 1st byte as pub key was padded with 0x00
            //     *offset += 1;
            // }
            let data: &[u8] = bytes.read_with(offset, Bytes::Len(32)).unwrap();
            Self::public_key_from_bytes(data).ok().map(|pubkey| {
                Self {
                    fingerprint,
                    chaincode,
                    compressed: true,
                    pubkey: pubkey.as_bytes().to_vec(),
                    is_extended: true,
                    ..Default::default() }
            })
        } else {
            None
        }
    }

    pub fn key_with_extended_private_key_data(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == 68).then_some({
            let offset = &mut 0;
            let fingerprint = bytes.read_with::<u32>(offset, byte::LE).unwrap();
            let chaincode = bytes.read_with::<UInt256>(offset, byte::LE).unwrap();
            let seckey = bytes.read_with::<UInt256>(offset, byte::LE).unwrap();
            Self {
                fingerprint,
                chaincode,
                seckey,
                compressed: true,
                is_extended: true,
                ..Default::default()
            }
        })
    }

    pub fn secret_key_string(&self) -> String {
        self.seckey.0.to_hex()
    }

    pub fn has_private_key(&self) -> bool {
        !self.seckey.is_zero()
    }

    pub fn hash160(&self) -> UInt160 {
        UInt160::hash160(&self.public_key_data())
    }

}
