use std::io;
use bls_signatures::G1Element;
use byte::{BytesExt, TryRead};
use crate::consensus::{Decodable, Encodable, encode};
use crate::crypto::byte_util::UInt384;
use crate::keys::BLSKey;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[ferment_macro::export]
pub struct OperatorPublicKey {
    pub data: [u8; 48],
    pub version: u16,
}

impl OperatorPublicKey {
    pub fn is_basic(&self) -> bool {
        self.version >= 2
    }
    pub fn is_legacy(&self) -> bool {
        self.version < 2
    }
}

impl Encodable for OperatorPublicKey {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        self.data.enc(&mut s);
        Ok(48)
    }
}

impl Decodable for OperatorPublicKey {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let data = <[u8; 48]>::consensus_decode(&mut d)?;
        Ok(Self { data, version: 0 })
    }
}


// Ctx: (version, protocol_version)
impl<'a> TryRead<'a, u16> for OperatorPublicKey {
    fn try_read(bytes: &'a [u8], version: u16) -> byte::Result<(Self, usize)> {
        let data = bytes.read_with::<UInt384>(&mut 0, byte::LE)?.0;
        Ok((OperatorPublicKey { data, version }, 48))
    }
}

impl From<OperatorPublicKey> for Option<G1Element> {
    fn from(value: OperatorPublicKey) -> Self {
        if value.is_legacy() {
            G1Element::from_bytes_legacy(&value.data)
        } else {
            G1Element::from_bytes(&value.data)
        }.ok()
    }
}

impl From<BLSKey> for OperatorPublicKey {
    fn from(key: BLSKey) -> Self {
        OperatorPublicKey { data: key.public_key_uint(), version: key.bls_version() }
    }
}
