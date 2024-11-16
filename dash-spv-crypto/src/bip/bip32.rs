use byte::{BytesExt, TryRead};
use hashes::{Hash, sha256d};
use crate::consensus::Encodable;
use crate::crypto::byte_util::{clone_into_array, UInt256};
use crate::derivation::BIP32_HARD;
use crate::keys::KeyError;
use crate::network::ChainType;
use crate::util::{base58, endian, sec_vec::SecVec};

#[allow(unused_assignments)]

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum Error {
    /// Invalid character encountered
    BadBase58(base58::Error),
    /// Checksum was not correct (expected, actual)
    BadChecksum(u32, u32),
    /// Checksum was not correct (expected, actual)
    InvalidAddress([u8; 4]),

    /// The length (in bytes) of the object was not correct
    /// Note that if the length is excessively long the provided length may be
    /// an estimate (and the checksum step may be skipped).
    InvalidLength(usize),
    /// Extended Key version byte(s) were not recognized
    InvalidExtendedKeyVersion([u8; 4]),
    /// Address version byte were not recognized
    InvalidAddressVersion(u8),
    /// Checked data was less than 4 bytes
    TooShort(usize),
    BadInput(&'static str),
}

impl From<base58::Error> for Error {
    fn from(value: base58::Error) -> Self {
        Error::BadBase58(value)
    }
}

impl From<byte::Error> for Error {
    fn from(value: byte::Error) -> Self {
        match value {
            byte::Error::BadInput { err } => Self::BadInput(err),
            byte::Error::BadOffset(offset) => Self::InvalidLength(offset),
            byte::Error::Incomplete => Self::BadInput("Incomplete")
        }
    }
}

impl From<Error> for byte::Error {
    fn from(_value: Error) -> Self {
        byte::Error::BadInput { err: "Invalid Key" }
    }
}

pub struct Key {
    pub depth: u8,
    pub fingerprint: u32,
    pub child: UInt256,
    pub chaincode: UInt256,
    pub data: Vec<u8>,
    pub hardened: bool
}

impl Key {
    pub fn new(depth: u8, fingerprint: u32, child: UInt256, chaincode: UInt256, data: Vec<u8>, hardened: bool) -> Self {
        Self { depth, fingerprint, child, chaincode, data, hardened }
    }

    pub fn extended_key_data(&self) -> Vec<u8> {
        let mut writer = Vec::<u8>::new();
        self.fingerprint.enc(&mut writer);
        self.chaincode.enc(&mut writer);
        writer.extend_from_slice(&self.data);
        writer
    }
}

// Decode base58-encoded string into bip32 private key
impl TryInto<Key> for (&str, ChainType) {
    type Error = KeyError;

    fn try_into(self) -> Result<Key, Self::Error> {
        base58::from(self.0)
            .map_err(KeyError::from)
            .and_then(|message| message.read_with::<Key>(&mut 0, self.1)
                .map_err(KeyError::from))
    }
}

impl<'a> TryRead<'a, ChainType> for Key {
    fn try_read(message: &'a [u8], chain_type: ChainType) -> byte::Result<(Self, usize)> {
        let len = message.len();
        let mid = len - 4;
        let (data, checked_data) = message.split_at(mid);
        let (head, _tail) = data.split_at(4);
        let expected = endian::slice_to_u32_le(&sha256d::Hash::hash(&data)[..4]);
        let actual = endian::slice_to_u32_le(&checked_data);
        let header: [u8; 4] = clone_into_array(&head);
        let mut offset = &mut 4;
        match (expected == actual, len) {
            (true, 82) /* 32 */ => {
                if chain_type.bip32_script_map().xpub.ne(&header) &&
                    chain_type.bip32_script_map().xprv.ne(&header) {
                    return Err(Error::InvalidAddress(header).into());
                }
                let depth = data.read_with::<u8>(&mut offset, byte::LE).unwrap();
                let fingerprint = data.read_with::<u32>(&mut offset, byte::LE).unwrap();
                let child_32 = data.read_with::<u32>(&mut offset, byte::BE).unwrap();
                let chain = data.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
                if chain_type.bip32_script_map().xprv.eq(&header) {
                    *offset += 1;
                }
                let hardened = (child_32 & BIP32_HARD) > 0;
                let child = UInt256::from(child_32 & !BIP32_HARD);
                Ok((Key { depth, fingerprint, child, chaincode: chain, data: Vec::from(&data[*offset..]), hardened }, len))
            },
            (true, 111) /* 256 */ => {
                if chain_type.dip14_script_map().dps.ne(&header) && chain_type.dip14_script_map().dpp.ne(&header) {
                    return Err(Error::InvalidAddress(header).into());
                }
                let depth = data.read_with::<u8>(&mut offset, byte::LE).unwrap();
                let fingerprint = data.read_with::<u32>(&mut offset, byte::LE).unwrap();
                let hardened = data.read_with::<u8>(&mut offset, byte::LE).unwrap() > 0;
                let child = data.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
                let chain = data.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
                if data.eq(&if chain_type.is_mainnet() { chain_type.dip14_script_map().dps } else { chain_type.bip32_script_map().xprv }) {
                    *offset += 1;
                }
                Ok((Key { depth, fingerprint, child, chaincode: chain, data: Vec::from(&data[*offset..]), hardened }, len))
            },
            (true, _) => Err(Error::InvalidLength(len).into()),
            _ => Err(Error::BadChecksum(expected, actual).into()),
        }
    }
}

impl Key {
    pub fn serialize(&self, chain_type: ChainType) -> String {
        if self.child.is_31_bits() {
            let mut child = u32::from_le_bytes(clone_into_array(&self.child.0[..4]));
            if self.hardened {
                child |= BIP32_HARD;
            }
            child = child.swap_bytes();
            // TODO: SecAlloc ([NSMutableData secureDataWithCapacity:14 + key.length + sizeof(chain)])
            // let mut writer = Vec::<u8>::with_capacity(14 + self.data.len() + std::mem::size_of::<UInt256>());
            let mut writer = SecVec::with_capacity(14 + self.data.len() + std::mem::size_of::<UInt256>());
            let is_priv = self.data.len() < 33;
            writer.extend_from_slice(&if is_priv { chain_type.bip32_script_map().xprv } else { chain_type.bip32_script_map().xpub }); // 4
            self.depth.enc(&mut writer);                // 5
            self.fingerprint.enc(&mut writer);          // 9
            child.enc(&mut writer);                     // 13
            self.chaincode.enc(&mut writer);                // 45
            if is_priv {
                b'\0'.enc(&mut writer);                 // 46 (prv) / 45 (pub)
            }
            writer.extend_from_slice(&self.data); // 78 (prv) / 78 (pub)
            base58::check_encode_slice(&writer)
        } else {
            // TODO: SecAlloc ([NSMutableData secureDataWithCapacity:47 + key.length + sizeof(chain)])
            // let mut writer = Vec::<u8>::with_capacity(47 + self.data.len() + std::mem::size_of::<UInt256>());
            let mut writer = SecVec::with_capacity(47 + self.data.len() + std::mem::size_of::<UInt256>());
            let is_priv = self.data.len() < 33;
            writer.extend_from_slice(&if is_priv { chain_type.dip14_script_map().dps } else { chain_type.dip14_script_map().dpp }); // 4
            self.depth.enc(&mut writer);                // 5
            self.fingerprint.enc(&mut writer);          // 9
            self.hardened.enc(&mut writer);             // 10
            self.child.enc(&mut writer);                // 42
            self.chaincode.enc(&mut writer);                // 74
            if is_priv {
                b'\0'.enc(&mut writer);                 // 75 (prv) / 74 (pub)
            }
            writer.extend_from_slice(&self.data); // 107 (prv) / 107 (pub)
            base58::check_encode_slice(&writer)
        }
    }
}
