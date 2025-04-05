use std::io;
use dashcore::bls_signatures::G1Element;
use dashcore::consensus::{Decodable, Encodable};
use crate::keys::BLSKey;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
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
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.data.consensus_encode(writer)?;
        Ok(48)
    }
}

impl Decodable for OperatorPublicKey {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, dashcore::consensus::encode::Error> {
        let data = <[u8; 48]>::consensus_decode(reader)?;
        Ok(Self { data, version: 0 })
    }
}


// Ctx: (version, protocol_version)
// impl<'a> TryRead<'a, u16> for OperatorPublicKey {
//     fn try_read(bytes: &'a [u8], version: u16) -> byte::Result<(Self, usize)> {
//         let data = bytes.read_with::<UInt384>(&mut 0, byte::LE)?.0;
//         Ok((OperatorPublicKey { data, version }, 48))
//     }
// }

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
