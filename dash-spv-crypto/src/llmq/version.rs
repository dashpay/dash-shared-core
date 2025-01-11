use std::io;
use std::io::Read;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, TryWrite};
#[cfg(feature = "generate-dashj-tests")]
use serde::{Serialize, Serializer};
use crate::consensus::{Decodable, Encodable, encode::Error};
use crate::crypto::byte_util::BytesDecodable;

#[warn(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
#[ferment_macro::export]
pub enum LLMQVersion {
    Default = 1,
    Indexed = 2,
    BLSBasicDefault = 3,
    BLSBasicIndexed = 4,
}

#[cfg(feature = "generate-dashj-tests")]
impl Serialize for LLMQVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_u16(u16::from(self.clone()))
    }
}

#[ferment_macro::export]
impl LLMQVersion {
    pub fn use_bls_legacy(&self) -> bool {
        *self == Self::Default || *self == Self::Indexed
    }
    pub fn use_rotated_quorums(&self) -> bool {
        *self == Self::Indexed || *self == Self::BLSBasicIndexed
    }

    pub fn index(&self) -> u16 {
        u16::from(self.clone())
    }
}

impl From<u16> for LLMQVersion {
    fn from(orig: u16) -> Self {
        match orig {
            1 => LLMQVersion::Default,
            2 => LLMQVersion::Indexed,
            3 => LLMQVersion::BLSBasicDefault,
            4 => LLMQVersion::BLSBasicIndexed,
            _ => LLMQVersion::Default,
        }
    }
}

impl From<LLMQVersion> for u16 {
    fn from(value: LLMQVersion) -> Self {
        match value {
            LLMQVersion::Default => 1,
            LLMQVersion::Indexed => 2,
            LLMQVersion::BLSBasicDefault => 3,
            LLMQVersion::BLSBasicIndexed => 4,
        }
    }
}

impl Encodable for LLMQVersion {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        u16::consensus_encode(&u16::from(self.clone()), &mut writer)
    }
}

impl Decodable for LLMQVersion {
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        u16::consensus_decode(&mut d)
            .map(LLMQVersion::from)
    }
}

impl<'a> TryRead<'a, Endian> for LLMQVersion {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        bytes.read_with::<u16>(&mut 0, endian)
            .map(|orig| (LLMQVersion::from(orig), 2))
    }
}

impl<'a> TryWrite<Endian> for LLMQVersion {
    fn try_write(self, bytes: &mut [u8], _endian: Endian) -> byte::Result<usize> {
        let orig: u16 = self.into();
        orig.consensus_encode(bytes).unwrap();
        Ok(2)
    }
}
impl<'a> BytesDecodable<'a, LLMQVersion> for LLMQVersion {
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> byte::Result<Self> {
        bytes.read_with::<LLMQVersion>(offset, byte::LE)
    }
}

#[ferment_macro::export]
pub fn from_u16(value: u16) -> LLMQVersion {
    LLMQVersion::from(value)
}
