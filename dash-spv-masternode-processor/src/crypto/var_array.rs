use byte::{BytesExt, LE, Result, TryRead};
use byte::ctx::Endian;
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::BytesDecodable;

/// A variable-length array of generics
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarArray<T>(
    pub VarInt,
    pub Vec<T>,
);
impl<T> VarArray<T> {
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len() + self.1.len()
    }
    pub fn is_empty(&self) -> bool {
        self.1.is_empty()
    }
    pub fn new(var_int: VarInt, arr: Vec<T>) -> VarArray<T> {
        Self(var_int, arr)
    }
}
impl<'a, T> TryRead<'a, Endian> for VarArray<T> where T: TryRead<'a, Endian> {
    #[inline]
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let var_int = bytes.read_with::<VarInt>(offset, endian)?;
        let arr_len = var_int.0 as usize;
        let mut arr = Vec::<T>::with_capacity(arr_len);
        for _i  in 0..arr_len {
            arr.push(bytes.read_with::<T>(offset, endian)?);
        }
        let var_arr = VarArray(var_int, arr);
        let len = var_arr.len();
        Ok((var_arr, len))
    }
}
impl<'a, T> BytesDecodable<'a, VarArray<T>> for VarArray<T> where T: TryRead<'a, Endian>{
    #[inline]
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<Self> {
        let var_int: VarInt = VarInt::from_bytes(bytes, offset)?;
        let arr_len = var_int.0 as usize;
        let mut arr = Vec::<T>::with_capacity(arr_len);
        for _i  in 0..arr_len {
            match bytes.read_with::<T>(offset, LE) {
                Ok(data) => { arr.push(data); },
                Err(_err) => { return None; }
            }
        }
        Some(VarArray(var_int, arr))
    }
}
