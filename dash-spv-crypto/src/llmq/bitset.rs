use std::io;
use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, TryRead};
use hashes::hex::ToHex;
use log::warn;
use crate::consensus::{Decodable, Encodable, encode, encode::VarInt, ReadExt, WriteExt};
use crate::crypto::data_ops::Data;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[ferment_macro::export]
pub struct Bitset {
    pub count: usize,
    pub bitset: Vec<u8>
}

impl Bitset {
    pub fn true_bits_count(&self) -> u64 {
        self.bitset.as_slice().true_bits_count()
    }
    #[allow(unused)]
    pub(crate) fn is_valid(&self) -> bool {
        if self.bitset.len() != (self.count + 7) / 8 {
            warn!("Error: The byte size of the bitvectors ({}) must match “(quorumSize + 7) / 8 ({})", self.bitset.len(), (self.count + 7) / 8);
            return false;
        }
        let len = (self.bitset.len() * 8) as i32;
        let size = self.count as i32;
        if len != size {
            let rem = len - size;
            let mask = !(0xff >> rem);
            let last_byte = match self.bitset.last() {
                Some(&last) => last as i32,
                None => 0,
            };
            if last_byte & mask != 0 {
                warn!("Error: No out-of-range bits should be set in byte representation of the bitvector");
                return false;
            }
        }
        true
    }
    pub fn bit_is_true_at_le_index(&self, index: usize) -> bool {
        self.bitset.as_slice().bit_is_true_at_le_index(index as u32)
    }

}

impl Encodable for Bitset {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.count as u64).enc(&mut writer);
        writer.emit_slice(&self.bitset).unwrap();
        len += self.bitset.len();
        Ok(len)
    }
}

impl Decodable for Bitset {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let count = VarInt::consensus_decode(&mut d)?.0 as usize;
        let mut bitset = vec![0u8; (count + 7) / 8];
        d.read_slice(&mut bitset)?;
        Ok(Self { count, bitset })
    }
}

impl<'a> TryRead<'a, Endian> for Bitset {
    fn try_read(bytes: &'a [u8], _ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let count = bytes.read_with::<VarInt>(offset, byte::LE)?.0 as usize;
        let bitset: &[u8] = bytes.read_with(offset, Bytes::Len((count + 7) / 8))?;
        Ok((Self { count, bitset: bitset.to_vec() }, *offset))
    }
}

impl std::fmt::Debug for Bitset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bitset")
            .field("count", &self.count)
            .field("bitset", &self.bitset.to_hex())
            .finish()
    }
}

