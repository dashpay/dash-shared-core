use std::io;
use byte::ctx::Endian;
use byte::{BytesExt, check_len, LE, TryRead};
use crate::consensus::Decodable;
use crate::crypto::byte_util::{AsBytes, BytesDecodable};
use crate::impl_bytes_decodable;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Boolean(pub bool);

impl<'a> TryRead<'a, Endian> for Boolean {
    #[inline]
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        check_len(bytes, 1)?;
        Ok((Boolean(bytes[0] != 0), 1))
    }
}
impl Decodable for Boolean {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Boolean, crate::consensus::encode::Error> {
        match bool::consensus_decode(d) {
            Ok(data) => Ok(Boolean(data)),
            Err(err) => Err(err)
        }
    }
}

impl AsBytes for Boolean {
    fn as_bytes(&self) -> &[u8] {
        if self.0 {
            &[0x01]
        } else {
            &[0x00]
        }
    }
}

impl_bytes_decodable!(Boolean);
