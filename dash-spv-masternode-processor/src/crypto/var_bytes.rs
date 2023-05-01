use byte::{BytesExt, LE, Result, TryRead};
use byte::ctx::{Bytes, Endian};
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::BytesDecodable;

/// A variable-length bytes
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct VarBytes<'a>(pub VarInt, pub &'a [u8]);

impl<'a> VarBytes<'a> {
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len() + self.1.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> TryRead<'a, Endian> for VarBytes<'a> {
    #[inline]
    fn try_read(bytes: &'a [u8], _endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let var_int = bytes.read_with::<VarInt>(offset, LE)?;
        let payload = bytes.read_with(offset, Bytes::Len(var_int.0 as usize))?;
        let var_bytes = VarBytes(var_int, payload);
        Ok((var_bytes, var_bytes.len()))
    }
}
impl<'a> BytesDecodable<'a, VarBytes<'a>> for VarBytes<'a> {
    #[inline]
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<Self> {
        let var_int: VarInt = VarInt::from_bytes(bytes, offset)?;
        match bytes.read_with(offset, Bytes::Len(var_int.0 as usize)) {
            Ok(data) => Some(VarBytes(var_int, data)),
            Err(_err) => None
        }
    }
}
